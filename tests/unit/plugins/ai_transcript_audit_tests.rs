//! Unit tests for the `ai_transcript_audit` plugin.
//!
//! Config-validation and metadata-emission tests drive the plugin hooks
//! directly. Record-content tests point the HTTP sink at a `wiremock` server
//! and assert on the captured batch (matching the `ai_federation` test style).

use async_trait::async_trait;
use bytes::Bytes;
use ferrum_edge::_test_support::{
    clone_log_metadata, set_response_presentation_policy_digest_for_test,
};
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
    MAX_TOOL_NAMES_AGGREGATE_BYTES, accounted_record_bytes, max_retained_record_bytes,
    max_serialized_record_bytes, snapshots,
};
use ferrum_edge::plugins::request_deduplication::RequestDeduplication;
use ferrum_edge::plugins::utils::ai_pii::PiiRedactor;
use ferrum_edge::plugins::{
    HTTP_ONLY_PROTOCOLS, Plugin, PluginFailurePolicy, PluginHttpClient, PluginResult,
    RequestContext, ResponseStreamAction, ResponseStreamInspector,
    chain_response_stream_inspectors, create_response_stream_inspector, plugin_failure_policy,
    priority, validate_plugin_config,
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
    // Stand in for the protocol entry path's plugin-cache presentation digest
    // so dedup can retain a finalized representation under a provable policy.
    set_response_presentation_policy_digest_for_test(&mut ctx, Some([0x5a; 32]));
    ctx.headers
        .insert("content-type".to_string(), "application/json".to_string());
    ctx
}

fn ai_request_body() -> &'static [u8] {
    br#"{"model":"gpt-4o","messages":[{"role":"user","content":"my ssn is 123-45-6789"}]}"#
}

/// An AI request that asks for an SSE response (`stream: true`), so staging
/// publishes the shared `ai_transcript_audit.stream_request` marker.
fn stream_request_body() -> &'static [u8] {
    br#"{"model":"gpt-4o","stream":true,"messages":[{"role":"user","content":"hi"}]}"#
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

async fn received_records(server: &MockServer) -> Vec<Value> {
    let mut records = Vec::new();
    if let Some(requests) = server.received_requests().await {
        for request in requests {
            if let Ok(Value::Array(batch)) = serde_json::from_slice::<Value>(&request.body) {
                records.extend(batch);
            }
        }
    }
    records
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
            "tool_calls",
            "stream_hash",
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
            "max_redaction_scan_bytes",
            "max_entry_bytes",
            "buffer_max_bytes",
            "max_stream_reservation_secs",
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
            "ack_policy",
            "ack_max_bytes",
            "ack_timeout_ms",
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
    let saturated_server = mock_sink().await;
    let saturated_endpoint = format!("{}/ingest", saturated_server.uri());
    // `batch_size: 1` on the shortest admitted flush interval: any record this
    // instance leaks reaches `saturated_server` within one flush cycle, so the
    // emptiness assertion at the end of this test cannot be satisfied merely by
    // a slow default flush (batch 50 / 1000 ms).
    let plugin = AiTranscriptAudit::new(
        &json!({
            "mode": "metadata_only",
            "capture": {
                "request": true,
                "response": true,
                "streaming_response": true
            },
            "sampling": {
                "rate": 0.0,
                "always_capture_on_guardrail": false,
                "always_capture_on_error": false
            },
            "sink": {
                "type": "http",
                "endpoint_url": saturated_endpoint,
                "allow_insecure_loopback": true,
                "batch_size": 1,
                "flush_interval_ms": 100,
                "on_buffer_full": "reject"
            }
        }),
        loopback_http_client(),
    )
    .unwrap();
    plugin.start_background_tasks().expect("live start");
    plugin.commit_background_tasks();
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

    let peer_server = mock_sink().await;
    let peer_endpoint = format!("{}/ingest", peer_server.uri());
    let peer = AiTranscriptAudit::new(
        &config_with_sink(
            &peer_endpoint,
            json!({ "capture": { "streaming_response": true } }),
        ),
        loopback_http_client(),
    )
    .unwrap();
    peer.start_background_tasks().expect("live start");
    peer.commit_background_tasks();
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
    assert!(
        !plugin.should_buffer_response_body(&peer_overflow),
        "a saturated instance must not buffer a response for a peer's candidate"
    );
    assert!(
        !plugin.forces_reqwest_dispatch(&peer_overflow),
        "a saturated instance must not force reqwest dispatch for a peer's stream candidate"
    );
    assert!(
        plugin
            .response_stream_inspector(&peer_overflow, 200, Some("text/event-stream"))
            .is_none(),
        "a saturated instance must not tee a peer's stream"
    );
    // Borrowed peer `sample_hit` must not reopen stream selection on the
    // saturated instance (the residual `MD_SAMPLE_HIT` fallback hazard).
    peer_overflow.metadata.insert(
        "ai_transcript_audit.sample_hit".to_string(),
        "true".to_string(),
    );
    assert!(
        plugin
            .response_stream_inspector(&peer_overflow, 200, Some("text/event-stream"))
            .is_none(),
        "shared sample_hit must not authorize a saturated instance to tee"
    );
    plugin
        .capture_final_response_body(
            &mut peer_overflow,
            200,
            &headers,
            br#"{"choices":[{"message":{"content":"ok"}}]}"#,
        )
        .await;
    plugin
        .on_response_stream_terminated(&mut peer_overflow, 200, &BodyOutcome::success(0))
        .await;
    assert!(
        peer.forces_reqwest_dispatch(&peer_overflow),
        "peer must retain its staging commit capability after saturated response hooks"
    );
    assert!(
        peer.response_stream_inspector(&peer_overflow, 200, Some("text/event-stream"))
            .is_some(),
        "peer must still be able to tee its own staged stream"
    );
    let mut still_saturated = make_ctx();
    assert!(
        matches!(
            plugin
                .on_final_request_body_with_context(
                    &mut still_saturated,
                    &headers,
                    ai_request_body()
                )
                .await,
            PluginResult::Reject {
                status_code: 503,
                ..
            }
        ),
        "saturated instance must remain at the 4096-entry bound"
    );

    // `request_rejected_for_sink` can preserve a prior "rejected" stamp even
    // across a successful enqueue, so non-emission has to be proven at the sink.
    // The peer's OWN commit is the positive control: waiting for its record to
    // land proves the export pipeline is live and that at least one flush cycle
    // elapsed on both identically configured (`batch_size: 1`,
    // `flush_interval_ms: 100`) background workers. Only then does an empty
    // `saturated_server` mean the saturated instance emitted nothing, rather
    // than that nothing had flushed yet.
    peer.capture_final_response_body(
        &mut peer_overflow,
        200,
        &headers,
        br#"{"choices":[{"message":{"content":"ok"}}]}"#,
    )
    .await;
    assert_eq!(
        wait_for_records(&peer_server).await.len(),
        1,
        "the peer that owns the staging entry must export exactly one record"
    );
    assert!(
        saturated_server
            .received_requests()
            .await
            .unwrap_or_default()
            .is_empty(),
        "a saturated instance must not emit a response record for a peer's candidate"
    );
}

/// A saturated instance owns no staging entry, but the shared
/// `ai_transcript_audit.candidate`/`record_id` markers a peer instance published
/// are still on the context. The reject-path refresh in `after_proxy` rewrites
/// SHARED metadata (`stream_request`, `request_hash`) that drives the peer's
/// buffer-vs-stream decision and its exported record, so it must stay gated on
/// the local staging entry rather than on the borrowed marker.
///
/// Staging in `before_proxy` is classification-only: the stream marker is
/// published immediately, but `request_hash` appears only when the *owning*
/// instance runs capture (reject-path `after_proxy` or the final-body hook).
#[tokio::test]
async fn saturated_instance_must_not_refresh_a_peer_instances_staged_request() {
    let plugin = AiTranscriptAudit::new(
        &json!({
            "capture": { "request": true, "response": true },
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
    for _ in 0..4096 {
        let mut filler = make_ctx();
        plugin
            .on_final_request_body_with_context(&mut filler, &headers, ai_request_body())
            .await;
    }

    let peer = AiTranscriptAudit::new(
        &config_with_sink("https://audit.example.com/x", json!({})),
        loopback_http_client(),
    )
    .unwrap();
    let mut ctx = make_ctx();
    let mut proxy_headers = json_headers();
    ctx.metadata.insert(
        "request_body".to_string(),
        String::from_utf8(stream_request_body().to_vec()).unwrap(),
    );
    peer.before_proxy(&mut ctx, &mut proxy_headers).await;
    assert_eq!(
        ctx.metadata
            .get("ai_transcript_audit.stream_request")
            .map(String::as_str),
        Some("true")
    );
    assert!(
        !ctx.metadata
            .contains_key("ai_transcript_audit.request_hash"),
        "provisional before_proxy staging must not publish a request hash"
    );

    // Peer owns the short-circuit/reject-path capture: hash + stream decision
    // are published from the still-streaming body before any terminator rewrite.
    let mut peer_response_headers = HashMap::new();
    assert!(matches!(
        peer.after_proxy(&mut ctx, 200, &mut peer_response_headers)
            .await,
        PluginResult::Continue
    ));
    let peer_request_hash = ctx
        .metadata
        .get("ai_transcript_audit.request_hash")
        .cloned()
        .expect("the owning peer publishes its request hash on reject-path capture");
    assert_eq!(
        ctx.metadata
            .get("ai_transcript_audit.stream_request")
            .map(String::as_str),
        Some("true"),
        "peer reject-path capture must keep the streamed request marker"
    );

    // The saturated instance sees the peer's shared marker but wins no permit.
    assert!(matches!(
        plugin.before_proxy(&mut ctx, &mut proxy_headers).await,
        PluginResult::Reject {
            status_code: 503,
            ..
        }
    ));
    assert_eq!(
        ctx.metadata
            .get("ai_transcript_audit.candidate")
            .map(String::as_str),
        Some("true"),
        "a saturated instance must not erase a peer instance's staged candidate"
    );
    assert_eq!(
        ctx.metadata.get("ai_transcript_audit.request_hash"),
        Some(&peer_request_hash),
        "a saturated before_proxy reject must not strip a peer's request hash"
    );

    // A request-phase terminator rewrites the body and drops `stream`. Only an
    // instance that actually staged this request may republish that decision.
    ctx.metadata.insert(
        "request_body".to_string(),
        String::from_utf8(ai_request_body().to_vec()).unwrap(),
    );
    let mut response_headers = HashMap::new();
    assert!(matches!(
        plugin
            .after_proxy(&mut ctx, 200, &mut response_headers)
            .await,
        PluginResult::Continue
    ));
    assert_eq!(
        ctx.metadata
            .get("ai_transcript_audit.stream_request")
            .map(String::as_str),
        Some("true"),
        "a saturated instance must not rewrite a peer's staged stream decision"
    );
    assert_eq!(
        ctx.metadata.get("ai_transcript_audit.request_hash"),
        Some(&peer_request_hash),
        "a saturated instance must not overwrite a peer's staged request hash"
    );
}

/// The staging entry IS the instance's commit capability: `on_response_committed`
/// consumes it with a single atomic `remove`, so a duplicated or retried commit
/// hook — and the deferred `log` fallback behind it — can never emit a second,
/// staging-less record for the same transaction.
#[tokio::test]
async fn committed_response_consumes_the_staging_permit_exactly_once() {
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
    plugin
        .capture_final_response_body(&mut ctx, 200, &headers, br#"{"ok":true}"#)
        .await;
    let records = wait_for_records(&server).await;
    assert_eq!(records.len(), 1, "the first commit emits one record");

    // A replayed commit hook over the same context, then the log fallback.
    plugin
        .capture_final_response_body(&mut ctx, 200, &headers, br#"{"ok":true}"#)
        .await;
    let mut summary = create_test_transaction_summary();
    summary.metadata = ctx.metadata.clone();
    plugin.log(&summary).await;

    tokio::time::sleep(std::time::Duration::from_millis(400)).await;
    let total: usize = server
        .received_requests()
        .await
        .unwrap_or_default()
        .iter()
        .filter_map(|request| serde_json::from_slice::<Value>(&request.body).ok())
        .filter_map(|body| body.as_array().map(Vec::len))
        .sum();
    assert_eq!(
        total, 1,
        "a replayed commit hook must not emit a second record from a consumed staging entry"
    );
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
    // Staging is classification-only: the pre-transform body is never hashed,
    // so there is no digest to throw away when a transform rewrites the body.
    assert!(
        !ctx.metadata
            .contains_key("ai_transcript_audit.request_hash"),
        "before_proxy must not hash the pre-transform body"
    );
    assert_eq!(plugin.capture_counters(), (0, 0));

    // A request transform changed the body; the final hook captures the
    // hash/excerpt/model from the final backend-visible bytes.
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
    assert_eq!(refreshed_hash.len(), 64);
    assert_eq!(
        plugin.capture_counters(),
        (1, 0),
        "a mutated body must still cost exactly one capture pass"
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
                    "endpoint_url": endpoint,
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
    ctx.metadata.insert(
        "ai_semantic_cache.7.cache_status".to_string(),
        "HIT".to_string(),
    );
    ctx.metadata.insert(
        "ai_semantic_cache.7.cache_match".to_string(),
        "semantic".to_string(),
    );
    ctx.metadata.insert(
        "ai_semantic_cache.7.cache_similarity".to_string(),
        "0.950000".to_string(),
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
    assert_eq!(
        records[0]["cache"]["ai_semantic_cache.7.cache_status"],
        "HIT"
    );
    assert_eq!(
        records[0]["cache"]["ai_semantic_cache.7.cache_match"],
        "semantic"
    );
    assert_eq!(
        records[0]["cache"]["ai_semantic_cache.7.cache_similarity"],
        "0.950000"
    );
}

/// The harvester must accept the `ai_semantic_cache.<instance_id>.*` telemetry
/// schema exactly — including keeping each instance's id in the exported key so
/// a multi-instance chain does not collapse into one ambiguous reading — while
/// refusing anything outside the producer's own grammar and value domain.
#[tokio::test]
async fn harvests_namespaced_cache_telemetry_and_rejects_everything_else() {
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

    let admitted: &[(&str, &str)] = &[
        // Two live instances: provenance must survive into the record.
        ("ai_semantic_cache.7.cache_status", "HIT"),
        ("ai_semantic_cache.7.cache_match", "semantic"),
        ("ai_semantic_cache.7.cache_similarity", "0.950000"),
        ("ai_semantic_cache.12.cache_status", "MISS"),
        // Pre-namespace spelling still lands in the cache section.
        ("ai_cache_status", "BYPASS"),
        // Separate producer, separate key.
        ("request_deduplication.replayed", "true"),
    ];
    let rejected: &[(&str, &str)] = &[
        // The staged prompt fingerprint is not telemetry and must never ship.
        ("ai_semantic_cache.7.cache_key", "0123456789abcdef01234567"),
        ("ai_cache_key", "0123456789abcdef01234567"),
        // Right namespace, invented field — must not become an export channel.
        ("ai_semantic_cache.7.prompt", "who is the ceo of acme corp"),
        ("ai_semantic_cache.7.cache_status.extra", "HIT"),
        // Namespace without the instance-id component.
        ("ai_semantic_cache.cache_status", "HIT"),
        // Non-numeric / oversized instance ids are not producer output.
        ("ai_semantic_cache.abc.cache_status", "HIT"),
        (
            "ai_semantic_cache.999999999999999999999.cache_status",
            "HIT",
        ),
        ("ai_semantic_cache.18446744073709551616.cache_status", "HIT"),
        ("ai_semantic_cache.007.cache_status", "HIT"),
        // Prefix-without-separator collision the old predicate accepted.
        ("ai_cache_hijack", "leaked"),
        // Grammar matches but the value is outside the producer's domain.
        ("ai_semantic_cache.9.cache_status", "who is the ceo of acme"),
        ("ai_semantic_cache.9.cache_match", "arbitrary"),
        ("ai_semantic_cache.10.cache_match", "exact"),
        ("ai_semantic_cache.9.cache_similarity", "not-a-number"),
        ("ai_semantic_cache.10.cache_similarity", "12.5"),
        // In-range floats that are not the producer's `{:.6}` spelling.
        ("ai_semantic_cache.11.cache_similarity", "0.95"),
        ("ai_semantic_cache.13.cache_similarity", "1"),
        ("ai_semantic_cache.14.cache_similarity", "1e0"),
        ("ai_semantic_cache.15.cache_similarity", "+0.950000"),
        ("ai_semantic_cache.16.cache_similarity", "1.000001"),
        // Sibling namespace under the dedup producer.
        ("request_deduplication.cached_body", "cached response text"),
    ];
    for &(key, value) in admitted.iter().chain(rejected) {
        ctx.metadata.insert(key.to_string(), value.to_string());
    }

    plugin
        .capture_final_response_body(&mut ctx, 200, &headers, br#"{"ok":true}"#)
        .await;
    let records = wait_for_records(&server).await;
    assert_eq!(records.len(), 1);
    let cache = records[0]["cache"]
        .as_object()
        .expect("cache section is an object");

    for &(key, value) in admitted {
        assert_eq!(
            cache.get(key).and_then(|entry| entry.as_str()),
            Some(value),
            "producer-schema key {key} was not exported"
        );
    }
    for &(key, _) in rejected {
        assert!(
            !cache.contains_key(key),
            "off-schema key {key} leaked into the audit record"
        );
    }
    // Nothing beyond the admitted set — no other section absorbed the rejects.
    assert_eq!(cache.len(), admitted.len());
    let serialized = serde_json::to_string(&records[0]).expect("record serializes");
    assert!(
        !serialized.contains("0123456789abcdef01234567"),
        "the staged cache key reached the record through another field"
    );
    assert!(
        !serialized.contains("who is the ceo of acme"),
        "off-schema metadata reached the record through another field"
    );
}

/// Oversized multi-instance chains must truncate the `cache` section in sorted
/// key order (not `HashMap` iteration order) so the surviving subset is stable,
/// and only along the per-instance axis: the fixed-name producer keys sort
/// around the `ai_semantic_cache.*` block — `request_deduplication.replayed`
/// sorts after all of it — so a plain sorted cut would drop the documented
/// replay marker before an eleventh cache instance's status.
#[tokio::test]
async fn cache_telemetry_section_caps_at_thirty_two_sorted_keys() {
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

    // Two fixed-name keys: one sorting before the namespaced block, one after.
    let fixed: &[(&str, &str)] = &[
        ("ai_cache_status", "BYPASS"),
        ("request_deduplication.replayed", "true"),
    ];
    for &(key, value) in fixed {
        ctx.metadata.insert(key.to_string(), value.to_string());
    }
    // 40 instances against a 32-entry cap with 2 fixed-name keys reserved
    // leaves a 30-entry budget on the per-instance axis.
    let mut expected_namespaced = std::collections::BTreeMap::new();
    for instance_id in 0..40u64 {
        let key = format!("ai_semantic_cache.{instance_id}.cache_status");
        let value = if instance_id % 2 == 0 { "HIT" } else { "MISS" };
        ctx.metadata.insert(key.clone(), value.to_string());
        expected_namespaced.insert(key, value.to_string());
    }
    let boundary = expected_namespaced.keys().nth(30).cloned();
    if let Some(boundary) = boundary {
        expected_namespaced.retain(|key, _| *key < boundary);
    }

    plugin
        .capture_final_response_body(&mut ctx, 200, &headers, br#"{"ok":true}"#)
        .await;
    let records = wait_for_records(&server).await;
    assert_eq!(records.len(), 1);
    let cache = records[0]["cache"]
        .as_object()
        .expect("cache section is an object");
    assert_eq!(cache.len(), 32);
    assert_eq!(expected_namespaced.len(), 30);
    for &(key, value) in fixed {
        assert_eq!(
            cache.get(key).and_then(|entry| entry.as_str()),
            Some(value),
            "the per-instance cap displaced fixed-name producer key {key}"
        );
    }
    for (key, value) in &expected_namespaced {
        assert_eq!(
            cache.get(key).and_then(|entry| entry.as_str()),
            Some(value.as_str()),
            "sorted truncation dropped or rewrote {key}"
        );
    }
    for key in cache.keys() {
        assert!(
            expected_namespaced.contains_key(key)
                || fixed.iter().any(|&(fixed_key, _)| fixed_key == key),
            "unsorted survivor {key} escaped the sorted cap"
        );
    }
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

/// Stream reserve/tee gates require THIS instance's staging entry. A peer's
/// shared `MD_CANDIDATE` / `MD_SAMPLE_HIT` metadata must not reserve stream
/// capacity, force reqwest dispatch, or install a stream inspector on a
/// saturated instance or change its retained-byte/reservation lifecycle;
/// `StreamingCapture::Off` never tees; a locally staged sampled winner may tee
/// and its own reservation must revoke and release normally.
#[tokio::test]
async fn instance_ownership_gates_stream_reserve_and_sampled_tee() {
    let saturated = AiTranscriptAudit::new(
        &json!({
            "capture": { "request": true, "response": false, "streaming_response": "sampled" },
            "sampling": { "rate": 0.0, "always_capture_on_guardrail": false },
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
    for _ in 0..4096 {
        let mut filler = make_ctx();
        saturated
            .on_final_request_body_with_context(&mut filler, &headers, ai_request_body())
            .await;
    }

    let peer = AiTranscriptAudit::new(
        &config_with_sink(
            "https://audit.example.com/x",
            json!({
                "capture": { "streaming_response": "sampled" },
                "sampling": { "rate": 1.0, "always_capture_on_guardrail": false },
                "limits": { "max_stream_reservation_secs": 1 }
            }),
        ),
        loopback_http_client(),
    )
    .unwrap();
    let mut ctx = make_ctx();
    assert!(matches!(
        peer.on_final_request_body_with_context(&mut ctx, &headers, stream_request_body())
            .await,
        PluginResult::Continue
    ));
    assert_eq!(
        ctx.metadata
            .get("ai_transcript_audit.sample_hit")
            .map(String::as_str),
        Some("true")
    );

    assert!(matches!(
        saturated
            .on_final_request_body_with_context(&mut ctx, &headers, stream_request_body())
            .await,
        PluginResult::Reject {
            status_code: 503,
            ..
        }
    ));
    assert_eq!(
        ctx.metadata
            .get("ai_transcript_audit.candidate")
            .map(String::as_str),
        Some("true")
    );
    ctx.metadata.insert(
        "ai_transcript_audit.sample_hit".to_string(),
        "true".to_string(),
    );

    // `on_response_stream_selected` -> `stream_commit_selected`: shared marker
    // without local staging must not reserve stream capacity or mutate retained
    // byte / expiry accounting.
    let saturated_before_peer_stream = saturated.status_snapshot();
    saturated.on_response_stream_selected(&ctx, 200, Some("text/event-stream"));
    assert!(
        !saturated.forces_reqwest_dispatch(&ctx),
        "peer sample_hit must not authorize stream dispatch without local staging"
    );
    assert!(
        saturated
            .response_stream_inspector(&ctx, 200, Some("text/event-stream"))
            .is_none(),
        "peer marker must not tee on a saturated instance"
    );
    let saturated_after_peer_stream = saturated.status_snapshot();
    assert_eq!(
        saturated_after_peer_stream.retained_bytes, saturated_before_peer_stream.retained_bytes,
        "peer stream markers must not acquire a retained-byte owner"
    );
    assert_eq!(
        saturated_after_peer_stream.stream_reservations_expired,
        saturated_before_peer_stream.stream_reservations_expired,
        "peer stream markers must not create a revocable reservation"
    );

    // `StreamingCapture::Off` never tees, even when this instance staged.
    let off = AiTranscriptAudit::new(
        &config_with_sink(
            "https://audit.example.com/x",
            json!({ "capture": { "streaming_response": false, "response": true } }),
        ),
        loopback_http_client(),
    )
    .unwrap();
    let mut off_ctx = make_ctx();
    off.on_final_request_body_with_context(&mut off_ctx, &headers, ai_request_body())
        .await;
    assert!(
        !off.forces_reqwest_dispatch(&off_ctx),
        "streaming off must not force reqwest dispatch"
    );
    assert!(
        off.response_stream_inspector(&off_ctx, 200, Some("text/event-stream"))
            .is_none(),
        "streaming off must not tee SSE"
    );

    // Sampled mode with an owned winning roll may tee. Its reservation owns
    // only this instance's accounting and expiry must synchronously revoke the
    // capture before releasing those bytes.
    assert!(
        peer.forces_reqwest_dispatch(&ctx),
        "locally staged sampled winner must tee"
    );
    let peer_before_reservation = peer.status_snapshot();
    peer.on_response_stream_selected(&ctx, 200, Some("text/event-stream"));
    let mut peer_inspector = peer
        .response_stream_inspector(&ctx, 200, Some("text/event-stream"))
        .expect("locally staged sampled winner must install a stream inspector");
    let peer_probe = peer
        .stream_capture_probe(&ctx)
        .expect("owned stream must publish a local lifecycle slot");
    let peer_chunk = vec![b'p'; 4096];
    let _ = peer_inspector.on_chunk(&peer_chunk).await;
    let peer_during_reservation = peer.status_snapshot();
    assert!(
        peer_during_reservation
            .retained_bytes
            .saturating_sub(peer_before_reservation.retained_bytes)
            >= peer_during_reservation.max_entry_retained_bytes,
        "fail-open stream capture must reserve the complete retained-record charge before copying"
    );
    tokio::time::sleep(std::time::Duration::from_millis(1_400)).await;
    let revoked = peer_probe
        .snapshot()
        .expect("the live inspector retains only its revoked slot");
    assert!(revoked.revoked);
    assert_eq!(revoked.retained_capture_bytes, 0);
    let peer_after_expiry = peer.status_snapshot();
    assert_eq!(peer_after_expiry.retained_bytes, 0);
    assert_eq!(peer_after_expiry.stream_reservations_expired, 1);

    drop(peer_inspector);
    peer.on_response_stream_terminated(&mut ctx, 200, &BodyOutcome::success(4096))
        .await;
    assert!(
        peer_probe.snapshot().is_none(),
        "terminal claim must release the revoked slot after accounting is gone"
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
                    "endpoint_url": endpoint,
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
async fn malformed_optional_sse_fields_do_not_bypass_split_pii_redaction() {
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
    let chunks: [&[u8]; 3] = [
        b"data: {\"object\":\"chat.completion.chunk\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"alice@\"}}]}\n\n",
        b"data: {\"object\":\"chat.completion.chunk\",\"choices\":[{\"index\":0,\"finish_reason\":123,\"delta\":{\"content\":\"example.com\",\"tool_calls\":[{\"index\":0,\"id\":7,\"type\":false,\"function\":{\"name\":[],\"arguments\":{}}}]}}]}\n\n",
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
    let excerpt = records[0]["response_body"]
        .as_str()
        .expect("response excerpt");
    assert!(excerpt.contains("sse_reassembled"), "{excerpt}");
    assert!(excerpt.contains("[REDACTED:email"), "{excerpt}");
    assert!(!excerpt.contains("alice@") && !excerpt.contains("example.com"));
    // Skipped optional fields are reported rather than silently dropped, and
    // the report carries only compiled-in field paths.
    let parsed: Value = serde_json::from_str(excerpt).expect("excerpt JSON");
    assert_eq!(
        parsed["malformed_fields"],
        json!([
            "choices[].delta.tool_calls[].function.arguments",
            "choices[].delta.tool_calls[].function.name",
            "choices[].delta.tool_calls[].id",
            "choices[].delta.tool_calls[].type",
            "choices[].finish_reason",
        ]),
        "{excerpt}"
    );
    // A malformed `finish_reason` is ignorable, so no reason is claimed.
    assert!(parsed.get("finish_reason").is_none(), "{excerpt}");
}

/// Drive one SSE capture through the streaming tee and return the exported
/// response excerpt. Shared by the malformed-field regressions below, which all
/// differ only in the frames they feed.
async fn reassembled_sse_excerpt(frames: &[&str]) -> String {
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
    let mut total = 0u64;
    for frame in frames {
        let chunk = format!("data: {frame}\n\n");
        let _ = inspector.on_chunk(chunk.as_bytes()).await;
        total += chunk.len() as u64;
    }
    let _ = inspector.on_end().await;
    plugin
        .on_response_stream_terminated(&mut ctx, 200, &BodyOutcome::success(total))
        .await;
    let records = wait_for_records(&server).await;
    records[0]["response_body"]
        .as_str()
        .expect("response excerpt")
        .to_string()
}

#[tokio::test]
async fn malformed_tool_call_array_element_does_not_force_raw_frame_fallback() {
    // A non-object `tool_calls` element carries no fragment at all, so it must
    // neither abort reassembly (per-frame redaction cannot see the email split
    // across the two `delta.content` fragments) nor mark the choice as holding
    // an unidentified call: the well-formed indexed sibling keeps full fidelity.
    let excerpt = reassembled_sse_excerpt(&[
        r#"{"object":"chat.completion.chunk","choices":[{"index":0,"delta":{"content":"carol@","tool_calls":[{"index":0,"id":"call_x","type":"function","function":{"name":"lookup","arguments":"{}"}}]}}]}"#,
        r#"{"object":"chat.completion.chunk","choices":[{"index":0,"delta":{"content":"example.net","tool_calls":[42]}}]}"#,
        "[DONE]",
    ])
    .await;
    assert!(excerpt.contains("sse_reassembled"), "{excerpt}");
    assert!(excerpt.contains("[REDACTED:email"), "{excerpt}");
    assert!(
        !excerpt.contains("carol@") && !excerpt.contains("example.net"),
        "split PII must not survive a malformed tool-call element: {excerpt}"
    );
    let parsed: Value = serde_json::from_str(&excerpt).expect("excerpt JSON");
    assert_eq!(
        parsed["malformed_fields"],
        json!(["choices[].delta.tool_calls[]"]),
        "{excerpt}"
    );
    // The well-formed sibling call is still attributed normally.
    assert_eq!(parsed["tool_calls"]["0"][0]["id"], "call_x");
}

#[tokio::test]
async fn empty_tool_call_array_never_forces_the_raw_frame_fallback() {
    // An empty `tool_calls` array must not abort reassembly: the split email
    // spans two `delta.content` fragments and per-frame redaction cannot see
    // it. Empty arrays also must not count as contributing tool-call deltas,
    // or a later single indexless call would be poisoned into withholding
    // despite being unambiguous by construction.
    let excerpt = reassembled_sse_excerpt(&[
        r#"{"object":"chat.completion.chunk","choices":[{"index":0,"delta":{"content":"dave@","tool_calls":[]}}]}"#,
        r#"{"object":"chat.completion.chunk","choices":[{"index":0,"delta":{"content":"example.org","tool_calls":[{"id":"call_y","type":"function","function":{"name":"notify","arguments":"{}"}}]}}]}"#,
        "[DONE]",
    ])
    .await;
    assert!(excerpt.contains("sse_reassembled"), "{excerpt}");
    assert!(excerpt.contains("[REDACTED:email"), "{excerpt}");
    assert!(
        !excerpt.contains("dave@") && !excerpt.contains("example.org"),
        "{excerpt}"
    );
    let parsed: Value = serde_json::from_str(&excerpt).expect("excerpt JSON");
    assert!(parsed.get("malformed_fields").is_none(), "{excerpt}");
    // Position is exported as `position`, never as a fabricated `index`.
    assert_eq!(parsed["tool_calls"]["0"][0]["position"], 0, "{excerpt}");
    assert!(
        parsed["tool_calls"]["0"][0].get("index").is_none(),
        "{excerpt}"
    );
    assert!(
        parsed["tool_calls"]["0"][0]
            .get("arguments_withheld")
            .is_none(),
        "{excerpt}"
    );
    assert_eq!(parsed["tool_calls"]["0"][0]["id"], "call_y", "{excerpt}");
    assert_eq!(
        parsed["tool_calls"]["0"][0]["function"]["name"], "notify",
        "{excerpt}"
    );
    assert_eq!(
        parsed["tool_calls"]["0"][0]["function"]["arguments"], "{}",
        "{excerpt}"
    );
}

#[tokio::test]
async fn repeated_indexless_tool_calls_withhold_arguments_instead_of_falling_back() {
    // The real ambiguity case: a later indexless frame could continue any prior
    // call. Guessing would splice unrelated calls; falling back to raw frames
    // would export the two argument halves separately (and a sensitive key can
    // straddle them). Both fragments are therefore withheld behind the fixed
    // placeholder, and the capture stays on the reassembled path.
    let excerpt = reassembled_sse_excerpt(&[
        r#"{"object":"chat.completion.chunk","choices":[{"index":0,"delta":{"tool_calls":[]}}]}"#,
        r#"{"object":"chat.completion.chunk","choices":[{"index":0,"delta":{"tool_calls":[{"id":"call_z","function":{"arguments":"{\"client_secret\":"}}]}}]}"#,
        r#"{"object":"chat.completion.chunk","choices":[{"index":0,"delta":{"tool_calls":[{"function":{"arguments":"\"sk-live-zzz\"}"}}]}}]}"#,
        "[DONE]",
    ])
    .await;
    assert!(excerpt.contains("sse_reassembled"), "{excerpt}");
    assert!(
        !excerpt.contains("sk-live-zzz") && !excerpt.contains("client_secret"),
        "split tool arguments must not be exported piecemeal: {excerpt}"
    );
    let parsed: Value = serde_json::from_str(&excerpt).expect("excerpt JSON");
    let calls = parsed["tool_calls"]["0"].as_array().expect("tool calls");
    assert_eq!(calls.len(), 1, "{excerpt}");
    assert_eq!(calls[0]["position"], 0, "{excerpt}");
    assert!(calls[0].get("index").is_none(), "{excerpt}");
    assert_eq!(calls[0]["arguments_withheld"], true, "{excerpt}");
    assert_eq!(
        calls[0]["function"]["arguments"], "[REDACTED:ambiguous_tool_call]",
        "{excerpt}"
    );
    // Unidentified entries also drop their positionally merged scalars under
    // ambiguity — otherwise a provider-controlled id/name would still export.
    assert!(calls[0].get("id").is_none(), "{excerpt}");
    assert!(calls[0]["function"].get("name").is_none(), "{excerpt}");
    assert!(!excerpt.contains("call_z"), "{excerpt}");
}

#[tokio::test]
async fn malformed_choice_indices_never_share_one_unattributed_bucket() {
    // `index` is identity-bearing: coercing a malformed value to 0 would
    // concatenate unrelated completions, and routing every malformed value to
    // one shared bucket does the same thing one step removed. Each malformed
    // occurrence gets its own ordinal, including two collisions inside a single
    // frame, and the ambiguous payload is withheld rather than guessed.
    for malformed_index in ["\"0\"", "-1", "1.5", "null", "18446744073709551616", "{}"] {
        let same_frame_collision = format!(
            r#"{{"object":"chat.completion.chunk","choices":[{{"index":{malformed_index},"delta":{{"content":"beta"}}}},{{"index":{malformed_index},"delta":{{"content":"gamma"}}}}]}}"#
        );
        let excerpt = reassembled_sse_excerpt(&[
            r#"{"object":"chat.completion.chunk","choices":[{"index":0,"delta":{"content":"alpha"}}]}"#,
            same_frame_collision.as_str(),
            "[DONE]",
        ])
        .await;
        let parsed: Value = serde_json::from_str(&excerpt).expect("excerpt JSON");
        let completion_text = parsed["completion_text"]
            .as_object()
            .expect("completion text");
        // Three distinct buckets: the real choice plus two per-occurrence
        // unattributed buckets that must not have merged with each other.
        assert_eq!(
            completion_text.len(),
            3,
            "index {malformed_index} collapsed buckets: {excerpt}"
        );
        for key in ["0", "unattributed:0", "unattributed:1"] {
            assert_eq!(
                completion_text[key], "[REDACTED:ambiguous_choice]",
                "index {malformed_index} key {key}: {excerpt}"
            );
        }
        assert_eq!(
            parsed["choice_identity_ambiguous"], true,
            "index {malformed_index}: {excerpt}"
        );
        assert_eq!(
            parsed["completion_text_withheld"], true,
            "index {malformed_index}: {excerpt}"
        );
        assert_eq!(
            parsed["malformed_fields"],
            json!(["choices[].index"]),
            "index {malformed_index}: {excerpt}"
        );
    }
}

#[tokio::test]
async fn complete_sensitive_arguments_followed_by_junk_are_not_concatenated() {
    // The concrete leak a shared unattributed bucket creates: a *complete*
    // sensitive JSON argument concatenated with unrelated junk stops parsing as
    // JSON, so the recursive sensitive-key redaction never runs and the value
    // escapes through the generic-pattern fallback. Two malformed tool indices
    // must land in different buckets, and the ambiguity must withhold both.
    let excerpt = reassembled_sse_excerpt(&[
        r#"{"object":"chat.completion.chunk","choices":[{"index":0,"delta":{"tool_calls":[{"index":"x","function":{"arguments":"{\"password\":\"s3cr3t-value\"}"}}]}}]}"#,
        r#"{"object":"chat.completion.chunk","choices":[{"index":0,"delta":{"tool_calls":[{"index":"y","function":{"arguments":"trailing junk"}}]}}]}"#,
        "[DONE]",
    ])
    .await;
    assert!(
        !excerpt.contains("s3cr3t-value"),
        "a complete sensitive argument must never be broken out of JSON shape by \
         an unrelated malformed-index fragment: {excerpt}"
    );
    let parsed: Value = serde_json::from_str(&excerpt).expect("excerpt JSON");
    let calls = parsed["tool_calls"]["0"].as_array().expect("tool calls");
    assert_eq!(calls.len(), 2, "malformed indices merged: {excerpt}");
    for (occurrence, call) in calls.iter().enumerate() {
        assert_eq!(call["index_unattributed"], true, "{excerpt}");
        assert_eq!(call["occurrence"], occurrence as u64, "{excerpt}");
        assert_eq!(call["arguments_withheld"], true, "{excerpt}");
        assert_eq!(
            call["function"]["arguments"], "[REDACTED:ambiguous_tool_call]",
            "{excerpt}"
        );
    }
    assert_eq!(
        parsed["malformed_fields"],
        json!(["choices[].delta.tool_calls[].index"]),
        "{excerpt}"
    );
}

#[tokio::test]
async fn two_malformed_tool_indices_in_one_frame_stay_separate_and_redacted() {
    // Same-frame collision: two malformed indices inside one delta are distinct
    // array entries, so each keeps its own bucket and its own parseable
    // arguments. Concatenating them would break both JSON documents and defeat
    // sensitive-key redaction; a single delta is not ambiguous, so nothing is
    // withheld here.
    let excerpt = reassembled_sse_excerpt(&[
        r#"{"object":"chat.completion.chunk","choices":[{"index":0,"delta":{"tool_calls":[{"index":"a","function":{"arguments":"{\"password\":\"alpha-secret\"}"}},{"index":[],"function":{"arguments":"{\"password\":\"beta-secret\"}"}}]}}]}"#,
        "[DONE]",
    ])
    .await;
    assert!(
        !excerpt.contains("alpha-secret") && !excerpt.contains("beta-secret"),
        "{excerpt}"
    );
    let parsed: Value = serde_json::from_str(&excerpt).expect("excerpt JSON");
    let calls = parsed["tool_calls"]["0"].as_array().expect("tool calls");
    assert_eq!(calls.len(), 2, "same-frame merge: {excerpt}");
    for (occurrence, call) in calls.iter().enumerate() {
        assert_eq!(call["index_unattributed"], true, "{excerpt}");
        assert_eq!(call["occurrence"], occurrence as u64, "{excerpt}");
        assert!(call.get("arguments_withheld").is_none(), "{excerpt}");
        let raw_arguments = call["function"]["arguments"].as_str().expect("arguments");
        let arguments: Value = serde_json::from_str(raw_arguments).expect("bucket JSON");
        assert_eq!(arguments["password"], "[REDACTED]", "{excerpt}");
    }
}

#[tokio::test]
async fn absent_choice_index_is_positional_within_one_delta_only() {
    // An absent index is a well-formed omission, not a malformed value, but
    // position identifies a choice only inside the delta that carried it. Two
    // indexless choices in one frame are distinct and unambiguous, and neither
    // is exported under a fabricated provider `index`.
    let excerpt = reassembled_sse_excerpt(&[
        r#"{"object":"chat.completion.chunk","choices":[{"delta":{"content":"first"}},{"delta":{"content":"second"}}]}"#,
        "[DONE]",
    ])
    .await;
    let parsed: Value = serde_json::from_str(&excerpt).expect("excerpt JSON");
    assert_eq!(
        parsed["completion_text"]["position:0"], "first",
        "{excerpt}"
    );
    assert_eq!(
        parsed["completion_text"]["position:1"], "second",
        "{excerpt}"
    );
    assert!(
        parsed["completion_text"].get("0").is_none(),
        "positional choices must not claim a provider index: {excerpt}"
    );
    assert!(parsed.get("malformed_fields").is_none(), "{excerpt}");
    assert!(
        parsed.get("choice_identity_ambiguous").is_none(),
        "{excerpt}"
    );
}

#[tokio::test]
async fn absent_choice_indices_across_frames_are_not_asserted_identity() {
    // Position is intra-delta identity: reusing it across frames would assert an
    // identity the provider never declared, and joining on that guess is what
    // makes the sensitive key in frame one adopt the value from frame two. The
    // bucket is withheld instead.
    let excerpt = reassembled_sse_excerpt(&[
        r#"{"object":"chat.completion.chunk","choices":[{"delta":{"content":"{\"api_key\":"}}]}"#,
        r#"{"object":"chat.completion.chunk","choices":[{"delta":{"content":"\"leak-me-please\"}"}}]}"#,
        "[DONE]",
    ])
    .await;
    assert!(
        !excerpt.contains("leak-me-please"),
        "cross-frame positional guessing must not export the fragments: {excerpt}"
    );
    let parsed: Value = serde_json::from_str(&excerpt).expect("excerpt JSON");
    assert_eq!(
        parsed["completion_text"]["position:0"], "[REDACTED:ambiguous_choice]",
        "{excerpt}"
    );
    assert_eq!(parsed["choice_identity_ambiguous"], true, "{excerpt}");
    assert_eq!(parsed["completion_text_withheld"], true, "{excerpt}");
}

#[tokio::test]
async fn indexless_choice_mixed_with_an_indexed_one_withholds_completion_text() {
    // A positional bucket is only safe while nothing else in the stream could be
    // its other half. Here the sensitive key arrives in an indexless choice and
    // its value in an indexed one, so the two land in *different* buckets: no
    // single bucket sees a second delta, yet exporting both verbatim hands the
    // consumer `{"api_key":` and `"leak-me-please"}` as separate strings, and
    // neither parses, so the recursive sensitive-key redaction never runs. The
    // whole stream must be withheld.
    let excerpt = reassembled_sse_excerpt(&[
        r#"{"object":"chat.completion.chunk","choices":[{"delta":{"content":"{\"api_key\":"}}]}"#,
        r#"{"object":"chat.completion.chunk","choices":[{"index":0,"delta":{"content":"\"leak-me-please\"}"}}]}"#,
        "[DONE]",
    ])
    .await;
    assert!(
        !excerpt.contains("leak-me-please"),
        "mixed indexed/indexless choices must not export the fragments apart: {excerpt}"
    );
    let parsed: Value = serde_json::from_str(&excerpt).expect("excerpt JSON");
    assert_eq!(
        parsed["completion_text"]["position:0"], "[REDACTED:ambiguous_choice]",
        "{excerpt}"
    );
    assert_eq!(
        parsed["completion_text"]["0"], "[REDACTED:ambiguous_choice]",
        "the indexed half is withheld too — it may be the value of the other half: {excerpt}"
    );
    assert_eq!(parsed["choice_identity_ambiguous"], true, "{excerpt}");
    assert_eq!(parsed["completion_text_withheld"], true, "{excerpt}");
}

#[tokio::test]
async fn indexless_choice_mixed_with_an_indexed_one_withholds_tool_arguments() {
    // Same split, one level down: each choice bucket sees exactly one
    // `tool_calls` delta with a well-formed tool index, so per-choice tool
    // ambiguity alone would clear both. Choice identity is what is unasserted,
    // and it must withhold the arguments in every bucket.
    let excerpt = reassembled_sse_excerpt(&[
        r#"{"object":"chat.completion.chunk","choices":[{"delta":{"tool_calls":[{"index":0,"function":{"arguments":"{\"api_key\":"}}]}}]}"#,
        r#"{"object":"chat.completion.chunk","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"\"leak-me-please\"}"}}]}}]}"#,
        "[DONE]",
    ])
    .await;
    assert!(
        !excerpt.contains("leak-me-please"),
        "tool arguments split across choice buckets must be withheld: {excerpt}"
    );
    let parsed: Value = serde_json::from_str(&excerpt).expect("excerpt JSON");
    for key in ["position:0", "0"] {
        let call = &parsed["tool_calls"][key][0];
        assert_eq!(
            call["function"]["arguments"], "[REDACTED:ambiguous_tool_call]",
            "{key}: {excerpt}"
        );
        assert_eq!(call["arguments_withheld"], true, "{key}: {excerpt}");
    }
    assert_eq!(parsed["choice_identity_ambiguous"], true, "{excerpt}");
}

#[tokio::test]
async fn malformed_tool_call_index_is_captured_unattributed_not_dropped_or_merged() {
    // Dropping a fragment whose index is malformed would let a provider keep
    // tool arguments out of the audit record entirely; merging it positionally
    // would splice it onto an unrelated call. It gets its own bucket, and
    // because a second delta contributed to a choice holding an unidentified
    // entry, every argument fragment in that choice is withheld.
    let excerpt = reassembled_sse_excerpt(&[
        r#"{"object":"chat.completion.chunk","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"call_real","type":"function","function":{"name":"lookup","arguments":"{\"q\":\"ok\"}"}}]}}]}"#,
        r#"{"object":"chat.completion.chunk","choices":[{"index":0,"delta":{"tool_calls":[{"index":-1,"function":{"arguments":"{\"password\":\"s3cr3t-value\"}"}}]}}]}"#,
        "[DONE]",
    ])
    .await;
    assert!(
        !excerpt.contains("s3cr3t-value"),
        "unattributed arguments must not be exported: {excerpt}"
    );
    let parsed: Value = serde_json::from_str(&excerpt).expect("excerpt JSON");
    let calls = parsed["tool_calls"]["0"].as_array().expect("tool calls");
    assert_eq!(calls.len(), 2, "{excerpt}");
    // Indexed slots sort before unattributed ones, and the real call keeps its
    // provider-declared identity even though its arguments are withheld.
    assert_eq!(calls[0]["index"], 0, "{excerpt}");
    assert_eq!(calls[0]["id"], "call_real", "{excerpt}");
    assert_eq!(calls[0]["arguments_withheld"], true, "{excerpt}");
    assert_eq!(calls[1]["index_unattributed"], true, "{excerpt}");
    assert!(calls[1].get("index").is_none(), "{excerpt}");
    assert_eq!(calls[1]["arguments_withheld"], true, "{excerpt}");
    assert_eq!(
        parsed["malformed_fields"],
        json!(["choices[].delta.tool_calls[].index"]),
        "{excerpt}"
    );
}

#[tokio::test]
async fn unattributed_tool_call_never_forces_the_raw_frame_fallback() {
    // A malformed tool index must not hand back the per-frame fallback: the
    // email is split across two `delta.content` fragments, whose choice is
    // properly indexed and therefore still joined and redacted. Only the
    // tool-call layer degrades to withholding.
    let excerpt = reassembled_sse_excerpt(&[
        r#"{"object":"chat.completion.chunk","choices":[{"index":0,"delta":{"content":"heidi@","tool_calls":[{"index":"nope","function":{"arguments":"{}"}}]}}]}"#,
        r#"{"object":"chat.completion.chunk","choices":[{"index":0,"delta":{"content":"example.net","tool_calls":[{"id":"call_w","type":"function","function":{"name":"notify","arguments":"{}"}}]}}]}"#,
        "[DONE]",
    ])
    .await;
    assert!(excerpt.contains("sse_reassembled"), "{excerpt}");
    assert!(excerpt.contains("[REDACTED:email"), "{excerpt}");
    assert!(
        !excerpt.contains("heidi@") && !excerpt.contains("example.net"),
        "{excerpt}"
    );
    let parsed: Value = serde_json::from_str(&excerpt).expect("excerpt JSON");
    // Choice identity is intact, so completion text is not withheld.
    assert!(
        parsed.get("choice_identity_ambiguous").is_none(),
        "{excerpt}"
    );
    let calls = parsed["tool_calls"]["0"].as_array().expect("tool calls");
    assert_eq!(calls.len(), 2, "{excerpt}");
    assert_eq!(calls[0]["position"], 0, "{excerpt}");
    assert_eq!(calls[1]["index_unattributed"], true, "{excerpt}");
    assert!(!excerpt.contains("call_w"), "{excerpt}");
    assert_eq!(
        parsed["malformed_fields"],
        json!(["choices[].delta.tool_calls[].index"]),
        "{excerpt}"
    );
}

#[tokio::test]
async fn fresh_indexed_choice_and_tool_progress_keeps_full_fidelity() {
    // The unambiguous path must not be collateral damage: provider-declared
    // indices correlate across deltas, so fragments join, sensitive keys are
    // redacted in place, and no withholding or diagnostic key appears.
    let excerpt = reassembled_sse_excerpt(&[
        r#"{"object":"chat.completion.chunk","choices":[{"index":0,"delta":{"content":"looking "}}]}"#,
        r#"{"object":"chat.completion.chunk","choices":[{"index":0,"delta":{"content":"it up","tool_calls":[{"index":0,"id":"call_a","type":"function","function":{"name":"lookup","arguments":"{\"password\":"}}]}}]}"#,
        r#"{"object":"chat.completion.chunk","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"\"hunter2\"}"}}]}}]}"#,
        r#"{"object":"chat.completion.chunk","choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]}"#,
        "[DONE]",
    ])
    .await;
    assert!(!excerpt.contains("hunter2"), "{excerpt}");
    let parsed: Value = serde_json::from_str(&excerpt).expect("excerpt JSON");
    assert_eq!(parsed["completion_text"]["0"], "looking it up", "{excerpt}");
    assert_eq!(parsed["finish_reason"]["0"], "tool_calls", "{excerpt}");
    let calls = parsed["tool_calls"]["0"].as_array().expect("tool calls");
    assert_eq!(calls.len(), 1, "{excerpt}");
    assert_eq!(calls[0]["index"], 0, "{excerpt}");
    assert_eq!(calls[0]["id"], "call_a", "{excerpt}");
    assert_eq!(calls[0]["function"]["name"], "lookup", "{excerpt}");
    let raw_arguments = calls[0]["function"]["arguments"]
        .as_str()
        .expect("arguments");
    let arguments: Value = serde_json::from_str(raw_arguments).expect("joined JSON");
    assert_eq!(arguments["password"], "[REDACTED]", "{excerpt}");
    for absent in [
        "malformed_fields",
        "choice_identity_ambiguous",
        "completion_text_withheld",
    ] {
        assert!(parsed.get(absent).is_none(), "{absent}: {excerpt}");
    }
    assert!(calls[0].get("arguments_withheld").is_none(), "{excerpt}");
}

#[tokio::test]
async fn single_delta_indexless_tool_call_is_reassembled_and_redacted() {
    // One contributing delta is unambiguous by construction: array positions
    // are distinct calls and nothing is joined across frames. Sensitive keys
    // are still recursively redacted after reassembly.
    let excerpt = reassembled_sse_excerpt(&[
        r#"{"object":"chat.completion.chunk","choices":[{"index":0,"delta":{"tool_calls":[{"id":"call_x","type":"function","function":{"name":"lookup","arguments":"{\"token\":\"AAA\",\"note\":\"keep\"}"}},{"id":"call_y","function":{"name":"other","arguments":"{\"note\":\"second\"}"}}]}}]}"#,
        r#"{"object":"chat.completion.chunk","choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]}"#,
        "[DONE]",
    ])
    .await;
    assert!(!excerpt.contains("AAA"), "{excerpt}");
    let parsed: Value = serde_json::from_str(&excerpt).expect("excerpt JSON");
    let calls = parsed["tool_calls"]["0"].as_array().expect("tool calls");
    assert_eq!(calls.len(), 2, "{excerpt}");
    assert_eq!(calls[0]["position"], 0, "{excerpt}");
    assert!(calls[0].get("arguments_withheld").is_none(), "{excerpt}");
    assert_eq!(calls[0]["id"], "call_x", "{excerpt}");
    let first: Value = serde_json::from_str(
        calls[0]["function"]["arguments"]
            .as_str()
            .expect("arguments"),
    )
    .expect("first arguments JSON");
    assert_eq!(first["token"], "[REDACTED]", "{excerpt}");
    assert_eq!(first["note"], "keep", "{excerpt}");
    assert_eq!(calls[1]["position"], 1, "{excerpt}");
    assert_eq!(calls[1]["id"], "call_y", "{excerpt}");
}

#[tokio::test]
async fn tool_call_ambiguity_is_scoped_to_one_choice() {
    // Choice 0 is correlated by provider `index` and stays reassembled; the
    // index-less repetition in choice 1 must not degrade it. Split secrets in
    // both choices must remain unexported.
    let excerpt = reassembled_sse_excerpt(&[
        r#"{"object":"chat.completion.chunk","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"call_a","function":{"name":"n0","arguments":"{\"token\":\"AAA"}}]}},{"index":1,"delta":{"tool_calls":[{"id":"call_b","function":{"arguments":"{\"token\":\"CCC"}}]}}]}"#,
        r#"{"object":"chat.completion.chunk","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"BBB\"}"}}]}},{"index":1,"delta":{"tool_calls":[{"function":{"arguments":"DDD\"}"}}]}}]}"#,
        "[DONE]",
    ])
    .await;
    for leaked in ["AAABBB", "AAA", "BBB", "CCC", "DDD"] {
        assert!(!excerpt.contains(leaked), "{leaked} in {excerpt}");
    }
    let parsed: Value = serde_json::from_str(&excerpt).expect("excerpt JSON");
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
    assert_eq!(joined["token"], "[REDACTED]", "{excerpt}");
    let ambiguous = parsed["tool_calls"]["1"].as_array().expect("choice 1");
    assert_eq!(ambiguous.len(), 1, "{excerpt}");
    assert_eq!(ambiguous[0]["arguments_withheld"], true, "{excerpt}");
    assert_eq!(
        ambiguous[0]["function"]["arguments"], "[REDACTED:ambiguous_tool_call]",
        "{excerpt}"
    );
}

#[tokio::test]
async fn indexed_tool_calls_survive_reordered_and_missing_frames() {
    // Provider-declared indices remain the trusted identity even when a call
    // is absent from a delta and the array order changes between deltas.
    let excerpt = reassembled_sse_excerpt(&[
        r#"{"object":"chat.completion.chunk","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"c0","function":{"name":"a","arguments":"{\"token\":\"XX"}},{"index":1,"id":"c1","function":{"name":"b","arguments":"{\"note\":\"pu"}}]}}]}"#,
        r#"{"object":"chat.completion.chunk","choices":[{"index":0,"delta":{"tool_calls":[{"index":1,"function":{"arguments":"bl"}}]}}]}"#,
        r#"{"object":"chat.completion.chunk","choices":[{"index":0,"delta":{"tool_calls":[{"index":1,"function":{"arguments":"ic\"}"}},{"index":0,"function":{"arguments":"YY\"}"}}]}}]}"#,
        "[DONE]",
    ])
    .await;
    assert!(!excerpt.contains("XXYY"), "{excerpt}");
    let parsed: Value = serde_json::from_str(&excerpt).expect("excerpt JSON");
    let calls = parsed["tool_calls"]["0"].as_array().expect("tool calls");
    assert_eq!(calls.len(), 2, "{excerpt}");
    assert!(calls[0].get("arguments_withheld").is_none(), "{excerpt}");
    let first: Value = serde_json::from_str(
        calls[0]["function"]["arguments"]
            .as_str()
            .expect("arguments"),
    )
    .expect("call 0 arguments JSON");
    assert_eq!(first["token"], "[REDACTED]", "{excerpt}");
    let second: Value = serde_json::from_str(
        calls[1]["function"]["arguments"]
            .as_str()
            .expect("arguments"),
    )
    .expect("call 1 arguments JSON");
    assert_eq!(second["note"], "public", "{excerpt}");
}

#[tokio::test]
async fn indexless_continuation_after_two_indexed_calls_withholds_arguments() {
    // Position cannot pick between two known calls, so an indexless continuation
    // must not be appended to whichever call sits at slot 0. That splice would
    // break both JSON documents and defeat sensitive-key redaction for the
    // split credential. Disjoint slots plus withholding close both directions.
    let excerpt = reassembled_sse_excerpt(&[
        r#"{"object":"chat.completion.chunk","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"call_0","type":"function","function":{"name":"safe","arguments":"{}"}},{"index":1,"id":"call_1","type":"function","function":{"name":"lookup","arguments":"{\"password\":\"HEADFRAG"}}]}}]}"#,
        r#"{"object":"chat.completion.chunk","choices":[{"index":0,"delta":{"tool_calls":[{"function":{"arguments":"TAILFRAG\"}"}}]}}]}"#,
        "[DONE]",
    ])
    .await;
    assert!(excerpt.contains("sse_reassembled"), "{excerpt}");
    assert!(
        !excerpt.contains("HEADFRAG") && !excerpt.contains("TAILFRAG"),
        "{excerpt}"
    );
    let parsed: Value = serde_json::from_str(&excerpt).expect("excerpt JSON");
    let calls = parsed["tool_calls"]["0"].as_array().expect("tool calls");
    assert_eq!(calls.len(), 3, "slots must stay disjoint: {excerpt}");
    for call in calls {
        assert_eq!(call["arguments_withheld"], true, "{excerpt}");
        assert_eq!(
            call["function"]["arguments"], "[REDACTED:ambiguous_tool_call]",
            "{excerpt}"
        );
    }
    assert_eq!(calls[0]["index"], 0, "{excerpt}");
    assert_eq!(calls[1]["index"], 1, "{excerpt}");
    assert_eq!(calls[2]["position"], 0, "{excerpt}");
}

#[tokio::test]
async fn indexless_tool_call_never_continues_an_indexed_call() {
    // #3167 supersession: even a single known indexed call must not absorb a
    // later index-less fragment by positional guess. The two key spaces stay
    // disjoint, and both argument halves are withheld so a split `token` cannot
    // escape JSON-key redaction in either direction. (#3166's more permissive
    // "lone continuation of one known call" rule is intentionally superseded.)
    let excerpt = reassembled_sse_excerpt(&[
        r#"{"object":"chat.completion.chunk","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"call_a","type":"function","function":{"name":"notify","arguments":"{\"token\":\"AAA"}}]}}]}"#,
        r#"{"object":"chat.completion.chunk","choices":[{"index":0,"delta":{"tool_calls":[{"function":{"arguments":"BBB\"}"}}]}}]}"#,
        "[DONE]",
    ])
    .await;
    assert!(excerpt.contains("sse_reassembled"), "{excerpt}");
    assert!(!excerpt.contains("AAA"), "{excerpt}");
    assert!(!excerpt.contains("BBB"), "{excerpt}");
    let parsed: Value = serde_json::from_str(&excerpt).expect("excerpt JSON");
    let calls = parsed["tool_calls"]["0"].as_array().expect("tool calls");
    assert_eq!(calls.len(), 2, "slots must stay disjoint: {excerpt}");
    // Provider-declared identity survives; its arguments do not.
    assert_eq!(calls[0]["index"], 0, "{excerpt}");
    assert_eq!(calls[0]["id"], "call_a", "{excerpt}");
    assert_eq!(calls[0]["function"]["name"], "notify", "{excerpt}");
    assert_eq!(calls[0]["arguments_withheld"], true, "{excerpt}");
    assert_eq!(
        calls[0]["function"]["arguments"], "[REDACTED:ambiguous_tool_call]",
        "{excerpt}"
    );
    assert_eq!(calls[1]["position"], 0, "{excerpt}");
    assert!(calls[1].get("index").is_none(), "{excerpt}");
    assert_eq!(calls[1]["arguments_withheld"], true, "{excerpt}");
    assert_eq!(
        calls[1]["function"]["arguments"], "[REDACTED:ambiguous_tool_call]",
        "{excerpt}"
    );
}

#[tokio::test]
async fn malformed_tool_call_index_is_unidentified_not_a_capture_downgrade() {
    // #3167 supersession: a null or non-integer tool-call `index` must not let
    // a backend force the leaky raw-frame fallback. #3169 routes each malformed
    // occurrence to its own unattributed bucket (stricter than #3167's shared
    // positional treatment) and withholds every argument fragment once a second
    // delta contributes.
    let excerpt = reassembled_sse_excerpt(&[
        r#"{"object":"chat.completion.chunk","choices":[{"index":0,"delta":{"tool_calls":[{"index":null,"id":"call_1","function":{"name":"lookup","arguments":"{\"token\":\"AAA"}}]}}]}"#,
        r#"{"object":"chat.completion.chunk","choices":[{"index":0,"delta":{"tool_calls":[{"index":"0","function":{"arguments":"BBB\"}"}}]}}]}"#,
        "[DONE]",
    ])
    .await;
    assert!(excerpt.contains("sse_reassembled"), "{excerpt}");
    assert!(!excerpt.contains("AAA"), "{excerpt}");
    assert!(!excerpt.contains("BBB"), "{excerpt}");
    let parsed: Value = serde_json::from_str(&excerpt).expect("excerpt JSON");
    let calls = parsed["tool_calls"]["0"].as_array().expect("tool calls");
    assert_eq!(
        calls.len(),
        2,
        "malformed indices must not share a bucket: {excerpt}"
    );
    for (occurrence, call) in calls.iter().enumerate() {
        assert_eq!(call["index_unattributed"], true, "{excerpt}");
        assert_eq!(call["occurrence"], occurrence as u64, "{excerpt}");
        assert!(call.get("index").is_none(), "{excerpt}");
        assert_eq!(call["arguments_withheld"], true, "{excerpt}");
        assert_eq!(
            call["function"]["arguments"], "[REDACTED:ambiguous_tool_call]",
            "{excerpt}"
        );
    }
    // Unidentified scalar identity is withheld under ambiguity.
    assert!(!excerpt.contains("call_1"), "{excerpt}");
    assert_eq!(
        parsed["malformed_fields"],
        json!(["choices[].delta.tool_calls[].index"]),
        "{excerpt}"
    );
}

#[tokio::test]
async fn frame_mixing_indexed_and_indexless_tool_calls_withholds_arguments() {
    // An index-less entry sharing a frame with an indexed one cannot use array
    // position as cross-frame identity, and the stream must not fall back to
    // per-frame redaction (which cannot see a value split across fragments).
    let excerpt = reassembled_sse_excerpt(&[
        r#"{"object":"chat.completion.chunk","choices":[{"index":0,"delta":{"tool_calls":[{"index":1,"id":"call_1","type":"function","function":{"name":"lookup","arguments":"{\"password\":\"HEADFRAG"}}]}}]}"#,
        r#"{"object":"chat.completion.chunk","choices":[{"index":0,"delta":{"tool_calls":[{"index":1,"function":{"arguments":"MIDFRAG"}},{"function":{"arguments":"TAILFRAG\"}"}}]}}]}"#,
        "[DONE]",
    ])
    .await;
    assert!(excerpt.contains("sse_reassembled"), "{excerpt}");
    assert!(
        !excerpt.contains("HEADFRAG")
            && !excerpt.contains("MIDFRAG")
            && !excerpt.contains("TAILFRAG"),
        "{excerpt}"
    );
    let parsed: Value = serde_json::from_str(&excerpt).expect("excerpt JSON");
    let calls = parsed["tool_calls"]["0"].as_array().expect("tool calls");
    assert_eq!(calls.len(), 2, "{excerpt}");
    for call in calls {
        assert_eq!(call["arguments_withheld"], true, "{excerpt}");
        assert_eq!(
            call["function"]["arguments"], "[REDACTED:ambiguous_tool_call]",
            "{excerpt}"
        );
    }
    assert_eq!(calls[0]["index"], 1, "{excerpt}");
    assert_eq!(calls[1]["position"], 1, "{excerpt}");
}

#[tokio::test]
async fn malformed_delta_and_tool_calls_containers_are_skipped_not_fatal() {
    // A non-object `delta` and a non-array `tool_calls` are ignorable: they
    // carry no attribution, so surrounding valid fragments must still join.
    let excerpt = reassembled_sse_excerpt(&[
        r#"{"object":"chat.completion.chunk","choices":[{"index":0,"delta":{"content":"erin@"}}]}"#,
        r#"{"object":"chat.completion.chunk","choices":[{"index":0,"delta":"not-an-object"}]}"#,
        r#"{"object":"chat.completion.chunk","choices":"not-an-array"}"#,
        r#"{"object":"chat.completion.chunk","choices":[{"index":0,"delta":{"content":["split"],"tool_calls":"not-an-array"}}]}"#,
        r#"{"object":"chat.completion.chunk","choices":[{"index":0,"delta":{"content":"example.io","tool_calls":[{"index":0,"function":"not-an-object"}]}}]}"#,
        "[DONE]",
    ])
    .await;
    assert!(excerpt.contains("[REDACTED:email"), "{excerpt}");
    assert!(
        !excerpt.contains("erin@") && !excerpt.contains("example.io"),
        "{excerpt}"
    );
    let parsed: Value = serde_json::from_str(&excerpt).expect("excerpt JSON");
    assert_eq!(
        parsed["malformed_fields"],
        json!([
            "choices",
            "choices[].delta",
            "choices[].delta.content",
            "choices[].delta.tool_calls",
            "choices[].delta.tool_calls[].function",
        ]),
        "{excerpt}"
    );
}

#[tokio::test]
async fn malformed_fields_never_carry_provider_values() {
    // The diagnostic must stay a list of compiled-in field paths: a malformed
    // value that is itself a secret must not be echoed into the record by the
    // very annotation that reports it.
    let excerpt = reassembled_sse_excerpt(&[
        r#"{"object":"chat.completion.chunk","choices":[{"index":0,"finish_reason":{"leak":"sk-live-deadbeef"},"delta":{"content":"hello","tool_calls":[{"index":0,"id":["sk-live-cafebabe"],"function":{"name":{"n":"sk-live-feedface"},"arguments":["sk-live-baddcafe"]}}]}}]}"#,
        "[DONE]",
    ])
    .await;
    for secret in [
        "sk-live-deadbeef",
        "sk-live-cafebabe",
        "sk-live-feedface",
        "sk-live-baddcafe",
    ] {
        assert!(
            !excerpt.contains(secret),
            "malformed value {secret} leaked into the record: {excerpt}"
        );
    }
    let parsed: Value = serde_json::from_str(&excerpt).expect("excerpt JSON");
    assert_eq!(parsed["completion_text"]["0"], "hello", "{excerpt}");
    for field in parsed["malformed_fields"]
        .as_array()
        .expect("malformed_fields")
    {
        let field = field.as_str().expect("field path");
        assert!(
            field.starts_with("choices"),
            "unexpected diagnostic entry {field}: {excerpt}"
        );
    }
}

#[tokio::test]
async fn duplicate_choice_indices_across_frames_still_join_one_bucket() {
    // The normal streaming case: repeated `index` for the same choice is a
    // continuation, and split PII across those fragments must be joined before
    // redaction even when interleaved with a second choice.
    let excerpt = reassembled_sse_excerpt(&[
        r#"{"object":"chat.completion.chunk","choices":[{"index":0,"delta":{"content":"frank@"}},{"index":1,"delta":{"content":"grace@"}}]}"#,
        r#"{"object":"chat.completion.chunk","choices":[{"index":1,"delta":{"content":"example.co"}},{"index":0,"delta":{"content":"example.dev"}}]}"#,
        "[DONE]",
    ])
    .await;
    for fragment in ["frank@", "grace@", "example.co", "example.dev"] {
        assert!(
            !excerpt.contains(fragment),
            "cross-frame fragment {fragment} must be joined and redacted: {excerpt}"
        );
    }
    let parsed: Value = serde_json::from_str(&excerpt).expect("excerpt JSON");
    for choice in ["0", "1"] {
        let text = parsed["completion_text"][choice]
            .as_str()
            .expect("choice text");
        assert!(text.contains("[REDACTED:email"), "choice {choice}: {text}");
    }
    assert!(parsed.get("malformed_fields").is_none(), "{excerpt}");
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

#[tokio::test]
async fn repeated_indexless_tool_call_frames_stay_reassembled_with_withheld_arguments() {
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
    let stream = b"data: {\"object\":\"chat.completion.chunk\",\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"call_1\",\"type\":\"function\",\"function\":{\"name\":\"lookup\",\"arguments\":\"{\\\"id\\\":\"}}]}}]}\n\ndata: {\"object\":\"chat.completion.chunk\",\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"function\":{\"arguments\":\"42}\"}}]}}]}\n\ndata: [DONE]\n\n";
    let _ = inspector.on_chunk(stream).await;
    let _ = inspector.on_end().await;
    plugin
        .on_response_stream_terminated(&mut ctx, 200, &BodyOutcome::success(stream.len() as u64))
        .await;

    let records = wait_for_records(&server).await;
    let excerpt = records[0]["response_body"]
        .as_str()
        .expect("response excerpt");
    // Ambiguous indexless continuations are neither guessed nor dropped back to
    // the raw-frame path (which would export both argument halves separately):
    // the capture stays reassembled and the arguments are withheld.
    assert!(excerpt.contains("sse_reassembled"), "{excerpt}");
    let parsed: Value = serde_json::from_str(excerpt).expect("excerpt JSON");
    let calls = parsed["tool_calls"]["0"].as_array().expect("tool calls");
    assert_eq!(calls.len(), 2, "{excerpt}");
    for call in calls {
        assert_eq!(call["arguments_withheld"], true, "{excerpt}");
        assert_eq!(
            call["function"]["arguments"], "[REDACTED:ambiguous_tool_call]",
            "{excerpt}"
        );
    }
    // The indexed call keeps the identity the provider declared; the positional
    // one is exported as a position and its scalar identity is withheld.
    assert_eq!(calls[0]["index"], 0, "{excerpt}");
    assert_eq!(calls[0]["id"], "call_1", "{excerpt}");
    assert_eq!(calls[1]["position"], 0, "{excerpt}");
    assert!(calls[1].get("id").is_none(), "{excerpt}");
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
                    "endpoint_url": endpoint,
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

// ---------------------------------------------------------------------------
// Acknowledgement drain/validation, retained-byte budget, stream reservation
// lifetime, bounded redaction, and capped streaming HMAC (#3048-#3052).
// ---------------------------------------------------------------------------

/// Drive one buffered request+response capture over `plugin` so exactly one
/// record reaches the sink.
async fn emit_one_record(plugin: &AiTranscriptAudit) -> RequestContext {
    let mut ctx = make_ctx();
    let headers = json_headers();
    plugin
        .on_final_request_body_with_context(&mut ctx, &headers, ai_request_body())
        .await;
    plugin
        .capture_final_response_body(&mut ctx, 200, &headers, br#"{"ok":true}"#)
        .await;
    ctx
}

/// Poll the authenticated status snapshot until `sink_healthy` matches.
async fn wait_for_sink_health(plugin: &AiTranscriptAudit, expected: bool) -> bool {
    for _ in 0..100 {
        if plugin.status_snapshot().sink_healthy == expected {
            return true;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    false
}

async fn assert_unhealthy_sink_rejects_next_candidate(plugin: &AiTranscriptAudit) {
    let mut ctx = make_ctx();
    let result = plugin
        .on_final_request_body_with_context(&mut ctx, &json_headers(), ai_request_body())
        .await;
    assert!(
        matches!(
            result,
            PluginResult::Reject {
                status_code: 503,
                ..
            }
        ),
        "on_sink_error=reject must reject after the complete acknowledgement attempt fails"
    );
    assert_eq!(
        ctx.metadata
            .get("ai_transcript_audit.sink_status")
            .map(String::as_str),
        Some("rejected")
    );
}

/// Serve 2xx headers advertising an acknowledgement body, then retain the
/// incomplete connection until the test releases it. This lets hosted tests
/// observe health after headers but before either timeout or transport EOF.
async fn spawn_incomplete_ack_server(
    reset_on_release: bool,
) -> (
    String,
    tokio::sync::oneshot::Receiver<()>,
    Arc<tokio::sync::Notify>,
) {
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind acknowledgement server");
    let addr = listener
        .local_addr()
        .expect("acknowledgement server address");
    let (headers_sent, headers_received) = tokio::sync::oneshot::channel();
    let release = Arc::new(tokio::sync::Notify::new());
    let release_server = Arc::clone(&release);
    tokio::spawn(async move {
        let _ = tokio::time::timeout(std::time::Duration::from_secs(5), async move {
            let Ok((mut socket, _)) = listener.accept().await else {
                return;
            };
            if !read_http11_request_headers(&mut socket).await {
                return;
            }
            if socket
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 16\r\nConnection: close\r\n\r\n")
                .await
                .is_err()
            {
                return;
            }
            let _ = headers_sent.send(());
            release_server.notified().await;
            // Dropping with fewer than Content-Length bytes makes the
            // response-body stream fail without placing collector bytes in any
            // diagnostic.
            if reset_on_release && let Ok(std_socket) = socket.into_std() {
                let reset_socket = socket2::Socket::from(std_socket);
                let _ = reset_socket.set_linger(Some(std::time::Duration::ZERO));
            }
        })
        .await;
    });
    (format!("http://{addr}/ingest"), headers_received, release)
}

/// A 2xx whose acknowledgement body overruns the configured bound is an
/// ambiguous delivery: health must NOT publish from the status line, and
/// `on_sink_error: reject` must start rejecting.
#[tokio::test]
async fn oversized_acknowledgement_body_marks_sink_unhealthy_and_rejects() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_string("A".repeat(8192)))
        .mount(&server)
        .await;
    let endpoint = format!("{}/ingest", server.uri());
    let plugin = AiTranscriptAudit::new(
        &config_with_sink(
            &endpoint,
            json!({
                "sink": {
                    "type": "http",
                    "endpoint_url": endpoint.clone(),
                    "allow_insecure_loopback": true,
                    "batch_size": 1,
                    "flush_interval_ms": 100,
                    "max_retries": 0,
                    "ack_max_bytes": 64,
                    "on_sink_error": "reject"
                }
            }),
        ),
        loopback_http_client(),
    )
    .expect("valid config");
    plugin.start_background_tasks().expect("live start");
    plugin.commit_background_tasks();
    assert!(
        plugin.status_snapshot().sink_healthy,
        "a fresh instance starts healthy"
    );

    emit_one_record(&plugin).await;
    assert!(
        wait_for_sink_health(&plugin, false).await,
        "a 2xx whose acknowledgement exceeded ack_max_bytes must not publish healthy"
    );

    assert_unhealthy_sink_rejects_next_candidate(&plugin).await;
}

/// A successful status line does not publish health while its body is stalled.
/// Only the admitted acknowledgement timeout completes the attempt and flips
/// fail-closed admission to unhealthy.
#[tokio::test]
async fn stalled_2xx_acknowledgement_marks_sink_unhealthy_and_rejects() {
    let (endpoint, headers_received, release) = spawn_incomplete_ack_server(false).await;
    let plugin = AiTranscriptAudit::new(
        &config_with_sink(
            &endpoint,
            json!({
                "sink": {
                    "type": "http",
                    "endpoint_url": endpoint.clone(),
                    "allow_insecure_loopback": true,
                    "batch_size": 1,
                    "flush_interval_ms": 100,
                    "max_retries": 0,
                    "ack_timeout_ms": 500,
                    "on_sink_error": "reject"
                }
            }),
        ),
        loopback_http_client(),
    )
    .expect("valid config");
    plugin.start_background_tasks().expect("live start");
    plugin.commit_background_tasks();

    emit_one_record(&plugin).await;
    tokio::time::timeout(std::time::Duration::from_secs(2), headers_received)
        .await
        .expect("collector should receive the batch")
        .expect("collector should publish 2xx headers");
    assert!(
        plugin.status_snapshot().sink_healthy,
        "2xx headers alone must not change sink health before acknowledgement timeout"
    );
    assert!(
        wait_for_sink_health(&plugin, false).await,
        "a stalled 2xx acknowledgement must become unhealthy at ack_timeout_ms"
    );
    release.notify_one();
    assert_unhealthy_sink_rejects_next_candidate(&plugin).await;
}

/// A 2xx acknowledgement whose declared body is cut off by transport failure
/// is an ambiguous delivery and immediately closes fail-closed admission.
#[tokio::test]
async fn reset_2xx_acknowledgement_transport_marks_sink_unhealthy_and_rejects() {
    let (endpoint, headers_received, release) = spawn_incomplete_ack_server(true).await;
    let plugin = AiTranscriptAudit::new(
        &config_with_sink(
            &endpoint,
            json!({
                "sink": {
                    "type": "http",
                    "endpoint_url": endpoint.clone(),
                    "allow_insecure_loopback": true,
                    "batch_size": 1,
                    "flush_interval_ms": 100,
                    "max_retries": 0,
                    "ack_timeout_ms": 1000,
                    "on_sink_error": "reject"
                }
            }),
        ),
        loopback_http_client(),
    )
    .expect("valid config");
    plugin.start_background_tasks().expect("live start");
    plugin.commit_background_tasks();

    emit_one_record(&plugin).await;
    tokio::time::timeout(std::time::Duration::from_secs(2), headers_received)
        .await
        .expect("collector should receive the batch")
        .expect("collector should publish 2xx headers");
    assert!(
        plugin.status_snapshot().sink_healthy,
        "2xx headers alone must not change sink health before body transport completes"
    );
    release.notify_one();
    assert!(
        wait_for_sink_health(&plugin, false).await,
        "an incomplete 2xx acknowledgement body must publish unhealthy"
    );
    assert_unhealthy_sink_rejects_next_candidate(&plugin).await;
}

/// `ack_policy: json` rejects a 2xx acknowledgement that reports lost records,
/// and accepts a clean one. Neither path may leak acknowledgement bytes.
#[tokio::test]
async fn json_acknowledgement_policy_distinguishes_reported_failures_from_success() {
    for (body, expect_healthy) in [
        (r#"{"status":"ok","errors":0}"#, true),
        (r#"{"status":"ok","errors":3}"#, false),
        (r#"{"status":"partial_failure"}"#, false),
        (r#"{"status":"partial_ok"}"#, false),
        // A present non-string status is ambiguous and must not count as success.
        (r#"{"status":true}"#, false),
        (r#"{"status":1}"#, false),
        (r#"{"status":null}"#, false),
        ("not json at all", false),
    ] {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_string(body))
            .mount(&server)
            .await;
        let endpoint = format!("{}/ingest", server.uri());
        let plugin = AiTranscriptAudit::new(
            &config_with_sink(
                &endpoint,
                json!({
                    "sink": {
                        "type": "http",
                        "endpoint_url": endpoint.clone(),
                        "allow_insecure_loopback": true,
                        "batch_size": 1,
                        "flush_interval_ms": 100,
                        "max_retries": 0,
                        "ack_policy": "json"
                    }
                }),
            ),
            loopback_http_client(),
        )
        .expect("valid config");
        plugin.start_background_tasks().expect("live start");
        plugin.commit_background_tasks();
        emit_one_record(&plugin).await;
        // Wait for the batch to be delivered before reading health, so the
        // "healthy" case is not just the untouched startup default.
        let _ = wait_for_records(&server).await;
        assert!(
            wait_for_sink_health(&plugin, expect_healthy).await,
            "acknowledgement {body:?} should publish sink_healthy={expect_healthy}"
        );
    }
}

/// The aggregate retained-byte budget bounds queued records even though the
/// record COUNT capacity is nowhere near full.
#[tokio::test]
async fn retained_byte_budget_bounds_queued_records_before_count_capacity() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_delay(std::time::Duration::from_secs(30)))
        .mount(&server)
        .await;
    let endpoint = format!("{}/ingest", server.uri());
    let plugin = AiTranscriptAudit::new(
        &config_with_sink(
            &endpoint,
            json!({
                "limits": {
                    "max_request_bytes": 1024,
                    "max_response_bytes": 1024,
                    "max_stream_capture_bytes": 1024,
                    "buffer_max_bytes": 180000
                },
                "sink": {
                    "type": "http",
                    "endpoint_url": endpoint.clone(),
                    "allow_insecure_loopback": true,
                    "batch_size": 1,
                    "flush_interval_ms": 100,
                    // Count capacity stays far above what the byte budget admits.
                    "buffer_capacity": 10000,
                    "max_retries": 0
                }
            }),
        ),
        loopback_http_client(),
    )
    .expect("valid config");
    plugin.start_background_tasks().expect("live start");
    plugin.commit_background_tasks();

    let mut dropped = 0usize;
    for _ in 0..256 {
        let ctx = emit_one_record(&plugin).await;
        if ctx
            .metadata
            .get("ai_transcript_audit.sink_status")
            .map(String::as_str)
            == Some("dropped")
        {
            dropped += 1;
        }
    }
    let snapshot = plugin.status_snapshot();
    assert!(
        dropped > 0,
        "aggregate retained bytes must bound admission before the count capacity does"
    );
    assert!(
        snapshot.retained_byte_drops > 0,
        "budget saturation must be observable on authenticated status"
    );
    assert!(
        snapshot.retained_bytes <= snapshot.buffer_max_bytes,
        "charged bytes {} exceeded the budget {}",
        snapshot.retained_bytes,
        snapshot.buffer_max_bytes
    );
}

/// Queue admission serializes once under the entry cap, charges the exact
/// escaped JSON bytes for both retained copies, and sends that immutable
/// representation without reqwest re-serializing it.
#[tokio::test]
async fn serialized_record_bytes_are_exactly_charged_during_delivery() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_delay(std::time::Duration::from_secs(30)))
        .mount(&server)
        .await;
    let endpoint = format!("{}/ingest", server.uri());
    let plugin = AiTranscriptAudit::new(
        &config_with_sink(
            &endpoint,
            json!({
                "mode": "full_body",
                "allow_full_body": true,
                "limits": {
                    "max_request_bytes": 4096,
                    "max_response_bytes": 1024,
                    "max_stream_capture_bytes": 1024,
                    "buffer_max_bytes": 1048576
                },
                "sink": {
                    "type": "http",
                    "endpoint_url": endpoint.clone(),
                    "allow_insecure_loopback": true,
                    "batch_size": 1,
                    "flush_interval_ms": 100,
                    "max_retries": 0
                }
            }),
        ),
        loopback_http_client(),
    )
    .expect("valid config");
    plugin.start_background_tasks().expect("live start");
    plugin.commit_background_tasks();

    let escape_heavy = "\\\"\n".repeat(1024);
    let body = serde_json::to_vec(&json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": escape_heavy}]
    }))
    .expect("body");
    let mut ctx = make_ctx();
    let headers = json_headers();
    plugin
        .on_final_request_body_with_context(&mut ctx, &headers, &body)
        .await;
    plugin
        .capture_final_response_body(&mut ctx, 200, &headers, br#"{"ok":true}"#)
        .await;

    let mut request_body = None;
    for _ in 0..100 {
        if let Some(requests) = server.received_requests().await
            && let Some(request) = requests.last()
        {
            request_body = Some(request.body.clone());
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    let request_body = request_body.expect("collector request");
    let batch: Value = serde_json::from_slice(&request_body).expect("JSON batch");
    let record = &batch.as_array().expect("batch")[0];
    let serialized_record_bytes = serde_json::to_vec(record).expect("record JSON").len();
    assert_eq!(
        request_body.len(),
        serialized_record_bytes + 2,
        "the HTTP body must be the admitted record plus exact single-entry array framing"
    );
    assert_eq!(
        plugin.status_snapshot().retained_bytes,
        accounted_record_bytes(serialized_record_bytes) as u64,
        "the live lease must cover the queued payload, HTTP body, framing, and delivery state"
    );
}

/// Refusing refresh growth must never retain newly enlarged model/tool strings
/// without a covering lease: the old staged entry stays small, the budget has
/// When the aggregate retained-byte budget has no headroom for a first Final
/// capture charge, the plugin withholds the request excerpt (and any uncharged
/// growth) rather than retaining unaccounted bytes. Capture-once admission
/// means provisional `before_proxy` staging charges zero; the Final capture is
/// the only request-side charge point.
#[tokio::test]
async fn refresh_growth_refusal_does_not_retain_uncharged_metadata() {
    let server = mock_sink().await;
    let endpoint = format!("{}/ingest", server.uri());
    let plugin = AiTranscriptAudit::new(
        &config_with_sink(
            &endpoint,
            json!({
                "mode": "full_body",
                "allow_full_body": true,
                "limits": {
                    "max_request_bytes": 1024,
                    "max_response_bytes": 1024,
                    "max_stream_capture_bytes": 1024,
                    "buffer_max_bytes": 180000
                },
                "sink": {
                    "type": "http",
                    "endpoint_url": endpoint.clone(),
                    "allow_insecure_loopback": true,
                    "batch_size": 1,
                    "flush_interval_ms": 100,
                    "buffer_capacity": 10000,
                    "max_retries": 0
                }
            }),
        ),
        loopback_http_client(),
    )
    .expect("valid config");
    plugin.start_background_tasks().expect("live start");
    plugin.commit_background_tasks();

    let small_body = br#"{"model":"a","messages":[{"role":"user","content":"hi"}]}"#;
    let headers = json_headers();

    // Capture many small Final candidates first so the aggregate budget has no
    // headroom for a later large capture charge.
    let mut fillers = Vec::new();
    for _ in 0..240 {
        let mut filler = make_ctx();
        plugin
            .on_final_request_body_with_context(&mut filler, &headers, small_body)
            .await;
        if filler
            .metadata
            .get("ai_transcript_audit.candidate")
            .map(String::as_str)
            != Some("true")
        {
            break;
        }
        fillers.push(filler);
        let snap = plugin.status_snapshot();
        if snap.buffer_max_bytes.saturating_sub(snap.retained_bytes) < 4_096 {
            break;
        }
    }
    let before = plugin.status_snapshot();
    assert!(
        before
            .buffer_max_bytes
            .saturating_sub(before.retained_bytes)
            < 4_096,
        "budget must be near saturation before the oversized capture attempt"
    );

    let grown_model = "m".repeat(MAX_MODEL_BYTES);
    let mut tools = Vec::new();
    let mut aggregate = 0usize;
    let mut index = 0usize;
    while aggregate < MAX_TOOL_NAMES_AGGREGATE_BYTES.saturating_sub(MAX_TOOL_NAME_BYTES)
        && tools.len() < MAX_TOOL_NAMES
    {
        let name = format!("tool_{index:04}_{}", "t".repeat(96));
        aggregate = aggregate.saturating_add(name.len().min(MAX_TOOL_NAME_BYTES));
        tools.push(json!({"type":"function","function":{"name": name}}));
        index += 1;
    }
    let large_body = serde_json::to_vec(&json!({
        "model": grown_model,
        "messages": [{"role":"user","content":"x".repeat(512)}],
        "tools": tools,
    }))
    .expect("large body");

    let mut ctx = make_ctx();
    plugin
        .on_final_request_body_with_context(&mut ctx, &headers, &large_body)
        .await;
    let after = plugin.status_snapshot();
    assert!(
        after.retained_bytes <= after.buffer_max_bytes,
        "oversized capture must not push retained_bytes past the budget"
    );

    // Finish the transaction; if capture was admitted under pressure the
    // exported request body must either be present within budget or omitted
    // with the retained-byte reason — never an uncharged full excerpt.
    plugin
        .capture_final_response_body(&mut ctx, 200, &headers, br#"{"ok":true}"#)
        .await;
    // Drain any queued record and inspect omission reason when present.
    let records = wait_for_records(&server).await;
    if let Some(record) = records.first()
        && record.get("request_body").is_none()
    {
        assert_eq!(
            record
                .get("request_body_omitted_reason")
                .and_then(|v| v.as_str()),
            Some("retained_byte_budget"),
            "withheld excerpt must use the compiled-in retained-byte reason"
        );
    }
    let final_snap = plugin.status_snapshot();
    assert!(
        final_snap.retained_bytes <= final_snap.buffer_max_bytes,
        "retained_bytes {} must stay within budget {}",
        final_snap.retained_bytes,
        final_snap.buffer_max_bytes
    );
}

/// A refused retained-byte staging admission must not publish this instance's
/// shared candidate / sampling / stream / request-hash metadata, and must not
/// erase a co-located peer instance's valid shared markers. Publishing those
/// keys before `try_acquire` + local staging insert would leave stale markers
/// that `discard_staged_candidate` deliberately refuses to clear when this
/// instance owns no staging entry.
#[tokio::test]
async fn retained_budget_staging_refusal_leaves_no_stale_or_peer_erasing_metadata() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_delay(std::time::Duration::from_secs(30)))
        .mount(&server)
        .await;
    let endpoint = format!("{}/ingest", server.uri());
    let plugin = AiTranscriptAudit::new(
        &config_with_sink(
            &endpoint,
            json!({
                "mode": "full_body",
                "allow_full_body": true,
                "sampling": { "rate": 1.0 },
                "limits": {
                    "max_request_bytes": 1024,
                    "max_response_bytes": 1024,
                    "max_stream_capture_bytes": 1024,
                    "buffer_max_bytes": 180000
                },
                "capture": { "request": true, "response": true },
                "sink": {
                    "type": "http",
                    "endpoint_url": endpoint.clone(),
                    "allow_insecure_loopback": true,
                    "batch_size": 1,
                    "flush_interval_ms": 100,
                    "buffer_capacity": 10000,
                    "max_retries": 0,
                    "on_buffer_full": "reject"
                }
            }),
        ),
        loopback_http_client(),
    )
    .expect("valid config");
    plugin.start_background_tasks().expect("live start");
    plugin.commit_background_tasks();

    let small_body = br#"{"model":"a","messages":[{"role":"user","content":"hi"}]}"#;
    let headers = json_headers();
    // Hold Final staging leases until the aggregate budget has no room for
    // another non-zero staging charge (`STAGING_ENTRY_OVERHEAD_BYTES`).
    let mut fillers = Vec::new();
    for _ in 0..240 {
        let mut filler = make_ctx();
        let result = plugin
            .on_final_request_body_with_context(&mut filler, &headers, small_body)
            .await;
        if !matches!(result, PluginResult::Continue)
            || filler
                .metadata
                .get("ai_transcript_audit.candidate")
                .map(String::as_str)
                != Some("true")
        {
            break;
        }
        fillers.push(filler);
        let snap = plugin.status_snapshot();
        if snap.buffer_max_bytes.saturating_sub(snap.retained_bytes) < 1_024 {
            break;
        }
    }
    let before = plugin.status_snapshot();
    assert!(
        before
            .buffer_max_bytes
            .saturating_sub(before.retained_bytes)
            < 1_024,
        "budget must be saturated below one staging overhead charge"
    );
    assert!(
        !fillers.is_empty(),
        "fillers must hold the retained-byte leases"
    );

    // Fresh context: refusal must leave no candidate/hash/stream metadata from
    // this failing instance (final-phase fallback must not see a false owner).
    let mut refused = make_ctx();
    let refused_result = plugin
        .on_final_request_body_with_context(&mut refused, &headers, stream_request_body())
        .await;
    assert!(
        matches!(
            refused_result,
            PluginResult::Reject {
                status_code: 503,
                ..
            }
        ),
        "saturated retained-byte staging must fail closed: {refused_result:?}"
    );
    assert_ne!(
        refused
            .metadata
            .get("ai_transcript_audit.candidate")
            .map(String::as_str),
        Some("true"),
        "refused admission must not publish MD_CANDIDATE=true"
    );
    assert!(
        !refused
            .metadata
            .contains_key("ai_transcript_audit.record_id"),
        "refused admission must not publish MD_RECORD_ID"
    );
    assert!(
        !refused
            .metadata
            .contains_key("ai_transcript_audit.request_hash"),
        "refused admission must not publish MD_REQUEST_HASH"
    );
    assert!(
        !refused
            .metadata
            .contains_key("ai_transcript_audit.stream_request"),
        "refused admission must not publish MD_STREAM_REQUEST"
    );
    assert!(
        !refused
            .metadata
            .contains_key("ai_transcript_audit.sample_hit"),
        "refused admission must not publish sampling flags"
    );
    assert_eq!(
        refused
            .metadata
            .get("ai_transcript_audit.sink_status")
            .map(String::as_str),
        Some("rejected")
    );
    let after_refuse = plugin.status_snapshot();
    assert_eq!(
        after_refuse.retained_bytes, before.retained_bytes,
        "refused staging must not retain a leaked byte lease"
    );
    assert!(
        !plugin.should_buffer_response_body(&refused),
        "no local staging means this instance must not buffer from stale markers"
    );
    assert!(
        !plugin.forces_reqwest_dispatch(&refused),
        "no local staging means this instance must not force stream dispatch"
    );

    // Peer already owns shared markers + its own staging. A saturated sibling
    // must leave those markers intact so the peer can still tee/export.
    let peer = AiTranscriptAudit::new(
        &config_with_sink(
            &endpoint,
            json!({
                "capture": { "request": true, "response": true, "streaming_response": true },
                "sampling": { "rate": 1.0 }
            }),
        ),
        loopback_http_client(),
    )
    .expect("valid peer");
    peer.start_background_tasks().expect("peer live start");
    peer.commit_background_tasks();
    let mut peer_ctx = make_ctx();
    assert!(matches!(
        peer.on_final_request_body_with_context(&mut peer_ctx, &headers, stream_request_body())
            .await,
        PluginResult::Continue
    ));
    let peer_record_id = peer_ctx
        .metadata
        .get("ai_transcript_audit.record_id")
        .cloned()
        .expect("peer publishes record_id after successful staging");
    let peer_hash = peer_ctx
        .metadata
        .get("ai_transcript_audit.request_hash")
        .cloned()
        .expect("peer publishes request_hash after successful staging");
    assert_eq!(
        peer_ctx
            .metadata
            .get("ai_transcript_audit.candidate")
            .map(String::as_str),
        Some("true")
    );
    assert_eq!(
        peer_ctx
            .metadata
            .get("ai_transcript_audit.stream_request")
            .map(String::as_str),
        Some("true")
    );

    let peer_attack = plugin
        .on_final_request_body_with_context(&mut peer_ctx, &headers, stream_request_body())
        .await;
    assert!(
        matches!(
            peer_attack,
            PluginResult::Reject {
                status_code: 503,
                ..
            }
        ),
        "saturated instance must still fail closed against a peer-owned context"
    );
    assert_eq!(
        peer_ctx
            .metadata
            .get("ai_transcript_audit.candidate")
            .map(String::as_str),
        Some("true"),
        "failed local admission must not erase a peer's MD_CANDIDATE"
    );
    assert_eq!(
        peer_ctx
            .metadata
            .get("ai_transcript_audit.record_id")
            .map(String::as_str),
        Some(peer_record_id.as_str()),
        "failed local admission must not replace a peer's MD_RECORD_ID"
    );
    assert_eq!(
        peer_ctx
            .metadata
            .get("ai_transcript_audit.request_hash")
            .map(String::as_str),
        Some(peer_hash.as_str()),
        "failed local admission must not erase a peer's MD_REQUEST_HASH"
    );
    assert_eq!(
        peer_ctx
            .metadata
            .get("ai_transcript_audit.stream_request")
            .map(String::as_str),
        Some("true"),
        "failed local admission must not erase a peer's MD_STREAM_REQUEST"
    );
    assert!(
        peer.forces_reqwest_dispatch(&peer_ctx),
        "peer must retain stream dispatch after a sibling's refused admission"
    );
    assert!(
        peer.response_stream_inspector(&peer_ctx, 200, Some("text/event-stream"))
            .is_some(),
        "peer must still tee its owned stream after a sibling refusal"
    );
    assert!(
        !plugin.forces_reqwest_dispatch(&peer_ctx),
        "saturated sibling must not claim the peer's stream markers"
    );
    let after_peer = plugin.status_snapshot();
    assert_eq!(
        after_peer.retained_bytes, before.retained_bytes,
        "peer-context refusal must not leak a retained-byte lease on the saturated instance"
    );

    // Keep fillers alive through the assertions above.
    assert_eq!(
        plugin.status_snapshot().retained_bytes,
        before.retained_bytes
    );
    drop(fillers);
}

/// Fail-closed pre-commit admission reserves the complete maximum serialized
/// delivery charge, so late metadata growth cannot make the eventual queue
/// publication under-accounted.
#[tokio::test]
async fn fail_closed_reservation_covers_the_full_serialized_entry_charge() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_delay(std::time::Duration::from_secs(30)))
        .mount(&server)
        .await;
    let endpoint = format!("{}/ingest", server.uri());
    let plugin = AiTranscriptAudit::new(
        &config_with_sink(
            &endpoint,
            json!({
                "mode": "full_body",
                "allow_full_body": true,
                "limits": {
                    "max_request_bytes": 1024,
                    "max_response_bytes": 1024,
                    "max_stream_capture_bytes": 1024,
                    "buffer_max_bytes": 180000
                },
                "sink": {
                    "type": "http",
                    "endpoint_url": endpoint.clone(),
                    "allow_insecure_loopback": true,
                    "batch_size": 1,
                    "flush_interval_ms": 100,
                    "buffer_capacity": 10000,
                    "max_retries": 0,
                    "on_buffer_full": "reject"
                }
            }),
        ),
        loopback_http_client(),
    )
    .expect("valid config");
    plugin.start_background_tasks().expect("live start");
    plugin.commit_background_tasks();

    let mut ctx = make_ctx();
    let headers = json_headers();
    plugin
        .on_final_request_body_with_context(&mut ctx, &headers, ai_request_body())
        .await;
    let staged_bytes = plugin.status_snapshot().retained_bytes;
    // Take the fail-closed commit reservation before the response is immutable.
    let admission = plugin
        .on_final_response_body(&mut ctx, 200, &headers, br#"{"ok":true}"#)
        .await;
    assert!(
        matches!(admission, PluginResult::Continue),
        "pre-commit admission must succeed: {admission:?}"
    );
    let reserved = plugin.status_snapshot();
    assert_eq!(
        reserved.retained_bytes - staged_bytes,
        reserved.max_entry_retained_bytes,
        "fail-closed admission must reserve the full queue + delivery charge"
    );

    // Grow harvested metadata after the reservation was taken. Exact bounded
    // serialization must shrink the full reservation, not reacquire or queue
    // attacker-shaped data outside the lease.
    ctx.metadata
        .insert("ai_prompt_shield.decision".to_string(), "G".repeat(4_096));

    plugin
        .on_response_committed(&mut ctx, 200, &headers, br#"{"ok":true}"#)
        .await;
    assert_eq!(
        ctx.metadata
            .get("ai_transcript_audit.sink_status")
            .map(String::as_str),
        Some("queued"),
        "the fully reserved record should remain admissible"
    );
    let snap = plugin.status_snapshot();
    assert!(
        snap.retained_bytes <= snap.buffer_max_bytes,
        "exact serialization must stay within the aggregate retained-byte budget"
    );
}

/// A record that is delivered releases its retained-byte lease.
#[tokio::test]
async fn delivered_record_releases_its_retained_bytes() {
    let server = mock_sink().await;
    let endpoint = format!("{}/ingest", server.uri());
    let plugin = AiTranscriptAudit::new(
        &config_with_sink(&endpoint, json!({})),
        loopback_http_client(),
    )
    .expect("valid config");
    plugin.start_background_tasks().expect("live start");
    plugin.commit_background_tasks();
    emit_one_record(&plugin).await;
    assert_eq!(wait_for_records(&server).await.len(), 1);

    let mut released = false;
    for _ in 0..100 {
        if plugin.status_snapshot().retained_bytes == 0 {
            released = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert!(released, "a delivered record must release its byte lease");
}

/// An active stream that never terminates cannot hold its staging entry and
/// reserved commit permit forever.
#[tokio::test]
async fn active_selected_stream_without_inspector_expires_without_sweep_trigger() {
    let server = mock_sink().await;
    let endpoint = format!("{}/ingest", server.uri());
    let plugin = AiTranscriptAudit::new(
        &config_with_sink(
            &endpoint,
            json!({
                "capture": { "streaming_response": true },
                "limits": { "max_stream_reservation_secs": 1 },
                "sink": {
                    "type": "http",
                    "endpoint_url": endpoint.clone(),
                    "allow_insecure_loopback": true,
                    "batch_size": 1,
                    "flush_interval_ms": 100,
                    "on_buffer_full": "reject"
                }
            }),
        ),
        loopback_http_client(),
    )
    .expect("valid config");
    plugin.start_background_tasks().expect("live start");
    plugin.commit_background_tasks();

    let mut stuck = make_ctx();
    plugin
        .on_final_request_body_with_context(&mut stuck, &json_headers(), ai_request_body())
        .await;
    // Reaching stream selection with a reserved commit permit is exactly the
    // state the old sweeper exempted from the TTL unconditionally.
    plugin.on_response_stream_selected(&stuck, 200, Some("text/event-stream"));
    let held = plugin.status_snapshot().retained_bytes;
    assert!(held > 0, "an active stream reservation charges bytes");
    assert_eq!(plugin.status_snapshot().stream_reservations_expired, 0);

    // The stream never terminates: no terminal hook, no `on_end`, and no later
    // request is allowed to trigger the repair sweep.
    tokio::time::sleep(std::time::Duration::from_millis(1_400)).await;

    let snapshot = plugin.status_snapshot();
    assert_eq!(
        snapshot.stream_reservations_expired, 1,
        "the staging-owned exact deadline must reclaim and count an active selection with no inspector"
    );
    assert_eq!(
        snapshot.retained_bytes, 0,
        "expiry must release staging, queue, and byte owners without a later sweep trigger"
    );
    assert_eq!(snapshot.max_stream_reservation_secs, 1);
}

/// Normal inspector completion can deliberately retain staging for the
/// transaction-log fallback. Losing that fallback must not cancel the original
/// reservation deadline or pin its owners indefinitely.
#[tokio::test]
async fn terminal_handoff_lost_before_log_fallback_still_expires_staging() {
    let server = mock_sink().await;
    let endpoint = format!("{}/ingest", server.uri());
    let plugin = Arc::new(
        AiTranscriptAudit::new(
            &config_with_sink(
                &endpoint,
                json!({
                    "capture": { "streaming_response": true },
                    "sampling": { "rate": 0.0 },
                    "limits": { "max_stream_reservation_secs": 1 }
                }),
            ),
            loopback_http_client(),
        )
        .expect("valid config"),
    );
    plugin.start_background_tasks().expect("live start");
    plugin.commit_background_tasks();
    let plugins: Vec<Arc<dyn Plugin>> = vec![plugin.clone()];

    let mut ctx = make_ctx();
    plugin
        .on_final_request_body_with_context(&mut ctx, &json_headers(), ai_request_body())
        .await;
    let mut inspector =
        create_response_stream_inspector(&plugins, &mut ctx, 200, Some("text/event-stream"))
            .expect("inspector");
    let _ = inspector.on_end().await;
    drop(inspector);
    run_response_stream_termination_hooks(&plugins, &mut ctx, 200, &BodyOutcome::success(0)).await;
    assert_eq!(
        ctx.metadata
            .get("ai_transcript_audit.sink_status")
            .map(String::as_str),
        Some("deferred"),
        "normal unsampled completion must retain staging for the immediate log fallback"
    );
    assert!(
        plugin.status_snapshot().retained_bytes > 0,
        "the fallback handoff still owns staged request bytes"
    );

    // Simulate cancellation/loss of transaction logging. No request or sweep
    // trigger follows.
    tokio::time::sleep(std::time::Duration::from_millis(1_400)).await;
    let snapshot = plugin.status_snapshot();
    assert_eq!(snapshot.stream_reservations_expired, 1);
    assert_eq!(
        snapshot.retained_bytes, 0,
        "the original selection deadline must remain armed through terminal handoff"
    );
}

/// When the transaction-log fallback consumes retained staging normally, its
/// cancellation owner wakes the exact deadline task promptly and the request
/// is never later counted as expired.
#[tokio::test]
async fn normal_log_fallback_consumption_cancels_stream_deadline() {
    let server = mock_sink().await;
    let endpoint = format!("{}/ingest", server.uri());
    let plugin = Arc::new(
        AiTranscriptAudit::new(
            &config_with_sink(
                &endpoint,
                json!({
                    "capture": { "streaming_response": true },
                    "sampling": { "rate": 0.0 },
                    "limits": { "max_stream_reservation_secs": 1 }
                }),
            ),
            loopback_http_client(),
        )
        .expect("valid config"),
    );
    plugin.start_background_tasks().expect("live start");
    plugin.commit_background_tasks();
    let plugins: Vec<Arc<dyn Plugin>> = vec![plugin.clone()];

    let mut ctx = make_ctx();
    plugin
        .on_final_request_body_with_context(&mut ctx, &json_headers(), ai_request_body())
        .await;
    let mut inspector =
        create_response_stream_inspector(&plugins, &mut ctx, 200, Some("text/event-stream"))
            .expect("inspector");
    let _ = inspector.on_end().await;
    drop(inspector);
    run_response_stream_termination_hooks(&plugins, &mut ctx, 200, &BodyOutcome::success(0)).await;

    let mut summary = create_test_transaction_summary();
    summary.response_status_code = 200;
    summary.metadata = ctx.metadata.clone();
    plugin.log(&summary).await;
    assert_eq!(
        plugin.status_snapshot().retained_bytes,
        0,
        "normal fallback consumption must release staging immediately"
    );

    tokio::time::sleep(std::time::Duration::from_millis(1_400)).await;
    assert_eq!(
        plugin.status_snapshot().stream_reservations_expired,
        0,
        "normal staging consumption must cancel rather than merely outwait the deadline task"
    );
}

/// Expiry synchronously revokes inspector-owned bytes and HMAC work before it
/// releases reservation accounting. Later chunks still forward byte-for-byte.
#[tokio::test]
async fn expired_stream_revokes_capture_and_hash_work_while_forwarding() {
    let server = mock_sink().await;
    let endpoint = format!("{}/ingest", server.uri());
    let plugin = Arc::new(
        AiTranscriptAudit::new(
            &config_with_sink(
                &endpoint,
                json!({
                    "mode": "full_body",
                    "allow_full_body": true,
                    "capture": {
                        "streaming_response": true,
                        "stream_hash": "full"
                    },
                    "limits": {
                        "max_stream_capture_bytes": 8192,
                        "max_stream_reservation_secs": 1
                    },
                    "sink": {
                        "type": "http",
                        "endpoint_url": endpoint.clone(),
                        "allow_insecure_loopback": true,
                        "batch_size": 1,
                        "flush_interval_ms": 100,
                        "on_buffer_full": "reject"
                    }
                }),
            ),
            loopback_http_client(),
        )
        .expect("valid config"),
    );
    plugin.start_background_tasks().expect("live start");
    plugin.commit_background_tasks();
    let plugins: Vec<Arc<dyn Plugin>> = vec![plugin.clone()];

    let mut stuck = make_ctx();
    plugin
        .on_final_request_body_with_context(&mut stuck, &json_headers(), ai_request_body())
        .await;
    let mut inspector =
        create_response_stream_inspector(&plugins, &mut stuck, 200, Some("text/event-stream"))
            .expect("inspector");
    let probe = plugin
        .stream_capture_probe(&stuck)
        .expect("registered capture probe");
    let first = vec![b'a'; 4096];
    match inspector.on_chunk(&first).await {
        ResponseStreamAction::Forward(forwarded) => {
            assert_eq!(forwarded.as_ref(), first.as_slice())
        }
        action => panic!("audit inspector must not cut the stream: {action:?}"),
    }
    let before = probe.snapshot().expect("live capture state");
    assert_eq!(before.retained_capture_bytes, 4096);
    assert_eq!(before.hashed_bytes, 4096);
    assert!(!before.revoked);

    tokio::time::sleep(std::time::Duration::from_millis(1_400)).await;

    let revoked = probe.snapshot().expect("revoked inspector still owns slot");
    assert!(revoked.revoked);
    assert_eq!(
        revoked.retained_capture_bytes, 0,
        "expiry must take and drop the inspector Vec before accounting releases"
    );
    assert_eq!(revoked.hashed_bytes, before.hashed_bytes);
    assert_eq!(plugin.status_snapshot().stream_reservations_expired, 1);

    let after_expiry = vec![b'b'; 4096];
    match inspector.on_chunk(&after_expiry).await {
        ResponseStreamAction::Forward(forwarded) => {
            assert_eq!(forwarded.as_ref(), after_expiry.as_slice())
        }
        action => panic!("revocation must not alter forwarding: {action:?}"),
    }
    assert_eq!(
        probe.snapshot(),
        Some(revoked),
        "revoked inspectors must neither recapture nor resume full-stream HMAC work"
    );
}

/// Repeated cohorts that outlive the reservation bound cannot leave captured
/// bytes behind while fresh cohorts consume the released accounting.
#[tokio::test]
async fn repeated_expired_stream_cohorts_cannot_bypass_retained_capacity() {
    let server = mock_sink().await;
    let endpoint = format!("{}/ingest", server.uri());
    let plugin = Arc::new(
        AiTranscriptAudit::new(
            &config_with_sink(
                &endpoint,
                json!({
                    "mode": "full_body",
                    "allow_full_body": true,
                    "capture": {
                        "streaming_response": true,
                        "stream_hash": "full"
                    },
                    "limits": {
                        "max_stream_capture_bytes": 8192,
                        "max_stream_reservation_secs": 1
                    },
                    "sink": {
                        "type": "http",
                        "endpoint_url": endpoint.clone(),
                        "allow_insecure_loopback": true,
                        "batch_size": 1,
                        "flush_interval_ms": 100,
                        "on_buffer_full": "reject"
                    }
                }),
            ),
            loopback_http_client(),
        )
        .expect("valid config"),
    );
    plugin.start_background_tasks().expect("live start");
    plugin.commit_background_tasks();
    let plugins: Vec<Arc<dyn Plugin>> = vec![plugin.clone()];

    let mut contexts = Vec::new();
    let mut inspectors = Vec::new();
    let mut probes = Vec::new();
    for _ in 0..3 {
        let mut ctx = make_ctx();
        plugin
            .on_final_request_body_with_context(&mut ctx, &json_headers(), ai_request_body())
            .await;
        let mut inspector =
            create_response_stream_inspector(&plugins, &mut ctx, 200, Some("text/event-stream"))
                .expect("cohort inspector");
        let cohort_chunk = vec![b'c'; 8192];
        let _ = inspector.on_chunk(&cohort_chunk).await;
        probes.push(
            plugin
                .stream_capture_probe(&ctx)
                .expect("cohort capture probe"),
        );
        contexts.push(ctx);
        inspectors.push(inspector);
    }
    assert!(
        probes.iter().all(|probe| {
            probe
                .snapshot()
                .is_some_and(|snapshot| snapshot.retained_capture_bytes == 8192)
        }),
        "the first cohort must actually retain capture windows"
    );

    tokio::time::sleep(std::time::Duration::from_millis(1_400)).await;
    let mut second_cohort = make_ctx();
    plugin
        .on_final_request_body_with_context(&mut second_cohort, &json_headers(), ai_request_body())
        .await;
    assert_eq!(plugin.status_snapshot().stream_reservations_expired, 3);
    assert!(
        probes.iter().all(|probe| {
            probe
                .snapshot()
                .is_some_and(|snapshot| snapshot.revoked && snapshot.retained_capture_bytes == 0)
        }),
        "every expired inspector must release its capture window"
    );

    // Released staging/queue capacity admits a new cohort, while chunks sent to
    // every old live stream remain forwarding-only and cannot regrow memory.
    let mut second_inspector = create_response_stream_inspector(
        &plugins,
        &mut second_cohort,
        200,
        Some("text/event-stream"),
    )
    .expect("second cohort must be admitted");
    let second_probe = plugin
        .stream_capture_probe(&second_cohort)
        .expect("second cohort probe");
    let second_chunk = vec![b'd'; 8192];
    let _ = second_inspector.on_chunk(&second_chunk).await;
    for inspector in &mut inspectors {
        let forwarded = vec![b'e'; 8192];
        match inspector.on_chunk(&forwarded).await {
            ResponseStreamAction::Forward(bytes) => {
                assert_eq!(bytes.as_ref(), forwarded.as_slice())
            }
            action => panic!("expired stream must still forward: {action:?}"),
        }
    }
    assert!(
        probes.iter().all(|probe| {
            probe
                .snapshot()
                .is_some_and(|snapshot| snapshot.revoked && snapshot.retained_capture_bytes == 0)
        }),
        "old cohorts must not recapture after their accounting was released"
    );
    assert_eq!(
        second_probe
            .snapshot()
            .expect("second cohort capture")
            .retained_capture_bytes,
        8192
    );
    let snapshot = plugin.status_snapshot();
    assert!(snapshot.retained_bytes <= snapshot.buffer_max_bytes);
}

/// A stream that finishes normally after expiry emits one bounded fallback
/// without resurrecting any released permit or stale body/hash evidence.
#[tokio::test]
async fn late_normal_termination_emits_exactly_one_safe_expiry_fallback() {
    let server = mock_sink().await;
    let endpoint = format!("{}/ingest", server.uri());
    let plugin = Arc::new(
        AiTranscriptAudit::new(
            &config_with_sink(
                &endpoint,
                json!({
                    "mode": "full_body",
                    "allow_full_body": true,
                    "capture": { "streaming_response": true },
                    "limits": { "max_stream_reservation_secs": 1 },
                    "sink": {
                        "type": "http",
                        "endpoint_url": endpoint.clone(),
                        "allow_insecure_loopback": true,
                        "batch_size": 1,
                        "flush_interval_ms": 100,
                        "on_buffer_full": "reject"
                    }
                }),
            ),
            loopback_http_client(),
        )
        .expect("valid config"),
    );
    plugin.start_background_tasks().expect("live start");
    plugin.commit_background_tasks();
    let plugins: Vec<Arc<dyn Plugin>> = vec![plugin.clone()];

    let request_marker = "expired-request-MUST-NOT-EXPORT";
    let response_marker = "expired-response-MUST-NOT-EXPORT";
    let request = format!(r#"{{"model":"gpt","messages":[{{"content":"{request_marker}"}}]}}"#);
    let response = format!("data: {{\"content\":\"{response_marker}\"}}\n\n");
    let mut ctx = make_ctx();
    plugin
        .on_final_request_body_with_context(&mut ctx, &json_headers(), request.as_bytes())
        .await;
    let mut inspector =
        create_response_stream_inspector(&plugins, &mut ctx, 200, Some("text/event-stream"))
            .expect("inspector");
    let _ = inspector.on_chunk(response.as_bytes()).await;

    tokio::time::sleep(std::time::Duration::from_millis(1_400)).await;
    let _ = inspector.on_end().await;
    drop(inspector);

    let outcome = BodyOutcome::success(response.len() as u64);
    run_response_stream_termination_hooks(&plugins, &mut ctx, 200, &outcome).await;
    run_response_stream_termination_hooks(&plugins, &mut ctx, 200, &outcome).await;

    let records = wait_for_total_records(&server, 1).await;
    assert_eq!(records.len(), 1);
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    let records = received_records(&server).await;
    assert_eq!(records.len(), 1, "terminal fallback must be single-fire");
    let record = &records[0];
    for field in [
        "request_body",
        "response_body",
        "request_hash",
        "response_hash",
        "response_hash_scope",
        "response_hash_bytes",
    ] {
        assert!(
            record.get(field).is_none(),
            "revoked fallback must omit {field}: {record}"
        );
    }
    let encoded = serde_json::to_string(record).expect("record JSON");
    assert!(!encoded.contains(request_marker));
    assert!(!encoded.contains(response_marker));
}

/// Abnormal inspector drop after expiry uses the same single-fire safe
/// fallback and releases the request-owned lifecycle state after termination.
#[tokio::test]
async fn abnormal_post_expiry_drop_cannot_leak_or_double_emit() {
    let server = mock_sink().await;
    let endpoint = format!("{}/ingest", server.uri());
    let plugin = Arc::new(
        AiTranscriptAudit::new(
            &config_with_sink(
                &endpoint,
                json!({
                    "mode": "full_body",
                    "allow_full_body": true,
                    "capture": { "streaming_response": true },
                    "limits": { "max_stream_reservation_secs": 1 }
                }),
            ),
            loopback_http_client(),
        )
        .expect("valid config"),
    );
    plugin.start_background_tasks().expect("live start");
    plugin.commit_background_tasks();
    let plugins: Vec<Arc<dyn Plugin>> = vec![plugin.clone()];

    let mut ctx = make_ctx();
    plugin
        .on_final_request_body_with_context(&mut ctx, &json_headers(), ai_request_body())
        .await;
    let mut inspector =
        create_response_stream_inspector(&plugins, &mut ctx, 200, Some("text/event-stream"))
            .expect("inspector");
    let _ = inspector.on_chunk(b"abnormal-secret").await;
    let probe = plugin.stream_capture_probe(&ctx).expect("capture probe");

    tokio::time::sleep(std::time::Duration::from_millis(1_400)).await;
    drop(inspector);
    let outcome = BodyOutcome::client_disconnect(15);
    run_response_stream_termination_hooks(&plugins, &mut ctx, 200, &outcome).await;
    run_response_stream_termination_hooks(&plugins, &mut ctx, 200, &outcome).await;

    let records = wait_for_total_records(&server, 1).await;
    assert_eq!(records.len(), 1);
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    assert_eq!(received_records(&server).await.len(), 1);
    assert!(
        probe.snapshot().is_none(),
        "terminal claim must release every slot owner"
    );
}

/// An oversized redacted JSON POST is conservatively audited without JSON
/// parsing/model/tool extraction. Even malformed JSON cannot disappear as
/// "non-AI", and fail-closed byte admission still applies.
#[tokio::test]
async fn oversized_redacted_json_skips_parse_work_and_remains_fail_closed() {
    let payload_marker = "OVERSIZED-PAYLOAD-MUST-NOT-EXPORT";
    let body = format!(
        r#"{{"model":"MODEL-MUST-NOT-EXTRACT","tools":[{{"function":{{"name":"TOOL-MUST-NOT-EXTRACT"}}}}],"messages":[{{"content":"{}{}""#,
        payload_marker,
        "z".repeat(16_384)
    );
    let server = mock_sink().await;
    let endpoint = format!("{}/ingest", server.uri());
    let plugin = AiTranscriptAudit::new(
        &config_with_sink(
            &endpoint,
            json!({
                "mode": "redacted_body",
                "limits": {
                    "max_request_bytes": 1024,
                    "max_response_bytes": 1024,
                    "max_stream_capture_bytes": 1024,
                    "max_redaction_scan_bytes": 4096,
                    "buffer_max_bytes": 180000
                },
                "sink": {
                    "type": "http",
                    "endpoint_url": endpoint.clone(),
                    "allow_insecure_loopback": true,
                    "batch_size": 1,
                    "flush_interval_ms": 100,
                    "on_buffer_full": "reject"
                }
            }),
        ),
        loopback_http_client(),
    )
    .expect("valid config");
    plugin.start_background_tasks().expect("live start");
    plugin.commit_background_tasks();
    let mut ctx = make_ctx();
    ctx.metadata.insert(
        "request_body".to_string(),
        String::from_utf8(ai_request_body().to_vec()).expect("UTF-8 request"),
    );
    let mut headers = json_headers();
    let initial = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(
        matches!(initial, PluginResult::Continue),
        "the initial candidate should stage"
    );
    // Exercise the refresh path with the final backend-visible body. If refresh
    // parsed this intentionally malformed payload, it would discard the
    // candidate as non-JSON instead of preserving omission evidence.
    let admission = plugin
        .on_final_request_body_with_context(&mut ctx, &headers, body.as_bytes())
        .await;
    assert!(
        matches!(admission, PluginResult::Continue),
        "the first conservative candidate should reserve fail-closed capacity"
    );
    assert!(
        !plugin.should_buffer_response_body(&ctx),
        "an unparsed oversized request is conservatively treated as potentially streaming"
    );
    plugin.on_response_stream_selected(&ctx, 200, Some("application/json"));

    // Stream selection must not release the first candidate's full fail-closed
    // serialized-entry reservation. The response is already committed by the
    // time the log fallback runs, so a late admission failure cannot reject it.
    // A second oversized request must therefore remain rejected here.
    let mut saturated = make_ctx();
    let rejected = plugin
        .on_final_request_body_with_context(&mut saturated, &headers, body.as_bytes())
        .await;
    assert!(
        matches!(
            rejected,
            PluginResult::Reject {
                status_code: 503,
                ..
            }
        ),
        "oversized conservative classification must still enforce fail-closed byte admission"
    );

    plugin
        .capture_final_response_body(&mut ctx, 200, &headers, br#"{"ok":true}"#)
        .await;

    let records = wait_for_records(&server).await;
    assert_eq!(records.len(), 1);
    let record = &records[0];
    assert!(
        record.get("request_body").is_none(),
        "an over-limit body must not be parsed, redacted, or exported: {record}"
    );
    assert_eq!(
        record["request_body_omitted_reason"],
        "redaction_scan_limit"
    );
    assert_eq!(record["request_body_truncated"], true);
    assert!(
        record["request_hash"].is_string(),
        "the keyed request hash still exports"
    );
    assert!(
        record.get("model").is_none(),
        "parse-dependent model extraction must be skipped"
    );
    assert!(
        record.get("tool_names").is_none(),
        "parse-dependent tool extraction must be skipped"
    );
    assert!(
        !serde_json::to_string(record)
            .unwrap()
            .contains(payload_marker),
        "no part of the oversized payload may reach the sink"
    );
}

/// Streaming redaction copies at most the independent scan bound. Crossing it
/// records the fixed omission reason while keyed hashing keeps the configured
/// stream scope.
#[tokio::test]
async fn redacted_stream_accumulation_stops_at_scan_bound() {
    let server = mock_sink().await;
    let endpoint = format!("{}/ingest", server.uri());
    let plugin = AiTranscriptAudit::new(
        &config_with_sink(
            &endpoint,
            json!({
                "mode": "redacted_body",
                "capture": { "streaming_response": true },
                "limits": {
                    "max_stream_capture_bytes": 8192,
                    "max_redaction_scan_bytes": 4096
                }
            }),
        ),
        loopback_http_client(),
    )
    .expect("valid config");
    plugin.start_background_tasks().expect("live start");
    plugin.commit_background_tasks();

    let mut ctx = make_ctx();
    plugin
        .on_final_request_body_with_context(&mut ctx, &json_headers(), ai_request_body())
        .await;
    plugin.on_response_stream_selected(&ctx, 200, Some("text/event-stream"));
    let mut inspector = plugin
        .response_stream_inspector(&ctx, 200, Some("text/event-stream"))
        .expect("inspector");
    let probe = plugin.stream_capture_probe(&ctx).expect("capture probe");
    let chunk = vec![b'r'; 6000];
    match inspector.on_chunk(&chunk).await {
        ResponseStreamAction::Forward(forwarded) => {
            assert_eq!(forwarded.as_ref(), chunk.as_slice())
        }
        action => panic!("audit inspector must forward unchanged: {action:?}"),
    }
    let snapshot = probe.snapshot().expect("live capture state");
    assert_eq!(
        snapshot.retained_capture_bytes, 4096,
        "the smaller redaction bound must cap streaming copies"
    );
    assert_eq!(
        snapshot.hashed_bytes, 6000,
        "hashing keeps capture.stream_hash semantics until lifecycle revocation"
    );

    let _ = inspector.on_end().await;
    drop(inspector);
    plugin
        .on_response_stream_terminated(&mut ctx, 200, &BodyOutcome::success(chunk.len() as u64))
        .await;
    let records = wait_for_records(&server).await;
    assert_eq!(records.len(), 1);
    let record = &records[0];
    assert!(record.get("response_body").is_none());
    assert_eq!(
        record["response_body_omitted_reason"],
        "redaction_scan_limit"
    );
    assert_eq!(record["response_body_truncated"], true);
    assert_eq!(record["response_hash_scope"], "full");
    assert_eq!(record["response_hash_bytes"], 6000);
}

/// The streamed keyed digest stops at the documented capture bound by default,
/// and a capped digest is explicitly marked, byte-counted, and domain-separated
/// from the full-stream digest of the same prefix.
#[tokio::test]
async fn streaming_hash_is_capped_by_default_and_marked_partial() {
    async fn stream_record(stream_hash: &str, chunk: &[u8]) -> Value {
        let server = mock_sink().await;
        let endpoint = format!("{}/ingest", server.uri());
        let plugin = AiTranscriptAudit::new(
            &config_with_sink(
                &endpoint,
                json!({
                    "capture": { "streaming_response": true, "stream_hash": stream_hash },
                    "limits": {
                        "max_request_bytes": 1024,
                        "max_response_bytes": 1024,
                        "max_stream_capture_bytes": 1024
                    }
                }),
            ),
            loopback_http_client(),
        )
        .expect("valid config");
        plugin.start_background_tasks().expect("live start");
        plugin.commit_background_tasks();
        let mut ctx = make_ctx();
        plugin
            .on_final_request_body_with_context(&mut ctx, &json_headers(), ai_request_body())
            .await;
        let mut inspector = plugin
            .response_stream_inspector(&ctx, 200, Some("text/event-stream"))
            .expect("inspector");
        let _ = inspector.on_chunk(chunk).await;
        let _ = inspector.on_end().await;
        drop(inspector);
        plugin
            .on_response_stream_terminated(&mut ctx, 200, &BodyOutcome::success(chunk.len() as u64))
            .await;
        let records = wait_for_records(&server).await;
        assert_eq!(records.len(), 1);
        records[0].clone()
    }

    let chunk = vec![b'd'; 8192];
    let capped = stream_record("capped", &chunk).await;
    assert_eq!(capped["response_hash_scope"], "partial");
    assert_eq!(capped["response_hash_bytes"], 1024);
    assert_eq!(capped["response_body_truncated"], true);
    assert_eq!(
        capped["response_body_omitted_reason"],
        "stream_truncation_boundary"
    );

    let full = stream_record("full", &chunk).await;
    assert_eq!(full["response_hash_scope"], "full");
    assert_eq!(full["response_hash_bytes"], 8192);
    assert_ne!(
        capped["response_hash"], full["response_hash"],
        "a capped digest must be domain-separated from a full-stream digest"
    );
}

/// The new bounds are admitted, range-checked, and cross-checked.
#[tokio::test]
async fn new_bound_configuration_is_range_checked() {
    for overrides in [
        json!({ "capture": { "stream_hash": "everything" } }),
        json!({ "limits": { "max_redaction_scan_bytes": 16 } }),
        json!({ "limits": { "max_redaction_scan_bytes": 99_999_999 } }),
        json!({ "limits": { "max_stream_reservation_secs": 0 } }),
        json!({ "limits": { "max_stream_reservation_secs": 999_999 } }),
        json!({ "limits": { "max_entry_bytes": 2048 } }),
        json!({ "limits": { "buffer_max_bytes": 1024 } }),
    ] {
        let config = config_with_sink("https://audit.example.com/x", overrides.clone());
        assert!(
            AiTranscriptAudit::new(&config, loopback_http_client()).is_err(),
            "out-of-range bound must fail closed: {overrides}"
        );
    }
    for sink_override in [
        json!({ "ack_policy": "maybe" }),
        json!({ "ack_max_bytes": 8 }),
        json!({ "ack_max_bytes": 99_999_999 }),
        json!({ "ack_timeout_ms": 0 }),
        json!({ "ack_timeout_ms": 999_999 }),
    ] {
        let mut sink = json!({
            "type": "http",
            "endpoint_url": "https://audit.example.com/x"
        });
        for (key, value) in sink_override.as_object().expect("object") {
            sink.as_object_mut()
                .expect("object")
                .insert(key.clone(), value.clone());
        }
        assert!(
            AiTranscriptAudit::new(&json!({ "sink": sink }), loopback_http_client()).is_err(),
            "out-of-range acknowledgement bound must fail closed: {sink_override}"
        );
    }

    let plugin = AiTranscriptAudit::new(
        &config_with_sink("https://audit.example.com/x", json!({})),
        loopback_http_client(),
    )
    .expect("defaults are admissible");
    let snapshot = plugin.status_snapshot();
    assert_eq!(snapshot.stream_hash_scope, "capped");
    assert_eq!(snapshot.ack_policy, "drain");
    assert_eq!(snapshot.ack_max_bytes, 65_536);
    assert_eq!(snapshot.ack_timeout_ms, 1_000);
    assert_eq!(snapshot.max_stream_reservation_secs, 900);
    assert_eq!(snapshot.max_redaction_scan_bytes, 1_048_576);
    assert_eq!(
        snapshot.max_entry_bytes,
        max_serialized_record_bytes(snapshot.max_retained_record_bytes as usize + 8_192) as u64
    );
    assert_eq!(
        snapshot.max_entry_retained_bytes,
        accounted_record_bytes(snapshot.max_entry_bytes as usize) as u64
    );
    assert!(snapshot.buffer_max_bytes >= snapshot.max_entry_retained_bytes);
}

// ---------------------------------------------------------------------------
// Capture admission and one-pass request hashing (issues #3067, #3053)
// ---------------------------------------------------------------------------

const CANDIDATE_KEY: &str = "ai_transcript_audit.candidate";
const HASH_KEY: &str = "ai_transcript_audit.request_hash";
const SINK_KEY: &str = "ai_transcript_audit.sink_status";

/// One `ai_transcript_audit.*` transaction-metadata value, owned.
fn audit_meta(ctx: &RequestContext, key: &str) -> Option<String> {
    ctx.metadata.get(key).cloned()
}

/// Fill the pre-`before_proxy` buffered request-body metadata slot.
fn set_prebuffered_body(ctx: &mut RequestContext, body: &[u8]) {
    let text = String::from_utf8(body.to_vec()).expect("utf8 body");
    ctx.metadata.insert("request_body".to_string(), text);
}

/// `sampling.rate: 0` with both overrides disabled means no record can ever be
/// emitted, so the request body must never reach the keyed HMAC, the redactor,
/// the excerpt shaper, or the model/tool extractors. `capture_counters()`
/// reports `(captures_performed, captures_skipped)`.
#[tokio::test]
async fn unemittable_candidate_pays_no_capture_work() {
    let server = mock_sink().await;
    let endpoint = format!("{}/ingest", server.uri());
    let plugin = AiTranscriptAudit::new(
        &config_with_sink(
            &endpoint,
            json!({
                "sampling": {
                    "rate": 0.0,
                    "always_capture_on_guardrail": false,
                    "always_capture_on_error": false
                }
            }),
        ),
        loopback_http_client(),
    )
    .expect("valid config");
    plugin.start_background_tasks().expect("live start");
    plugin.commit_background_tasks();

    let mut ctx = make_ctx();
    set_prebuffered_body(&mut ctx, ai_request_body());
    let mut proxy_headers = ctx.headers.clone();
    plugin.before_proxy(&mut ctx, &mut proxy_headers).await;
    // The candidate is still staged (a bounded slot plus correlation metadata)
    // so buffer/dispatch decisions and the log fallback stay coherent.
    assert_eq!(audit_meta(&ctx, CANDIDATE_KEY).as_deref(), Some("true"));

    let headers = json_headers();
    plugin
        .on_final_request_body_with_context(&mut ctx, &headers, ai_request_body())
        .await;
    assert_eq!(
        plugin.capture_counters(),
        (0, 1),
        "an unemittable candidate must not reach the capture helpers"
    );
    assert_eq!(audit_meta(&ctx, HASH_KEY), None, "no HMAC, no hash");

    plugin
        .capture_final_response_body(&mut ctx, 200, &headers, br#"{"ok":true}"#)
        .await;
    assert_eq!(audit_meta(&ctx, SINK_KEY).as_deref(), Some("skipped"));
    assert_eq!(plugin.capture_counters(), (0, 1));
    tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    let requests = server.received_requests().await.unwrap_or_default();
    assert!(requests.is_empty(), "no record may be exported");
}

/// An unchanged request body is HMACed exactly once across the whole hook
/// chain: staging defers it, the final request-body hook performs it, and the
/// reject-path and synthetic-short-circuit refresh hooks are no-ops instead of
/// a second cryptographic pass followed by an equality comparison.
#[tokio::test]
async fn unchanged_request_body_is_hmaced_once_across_every_hook() {
    let server = mock_sink().await;
    let endpoint = format!("{}/ingest", server.uri());
    let secret = "fleet-stable-hmac-key-once";
    let overrides = json!({ "redaction": { "hash_secret": secret } });
    let plugin = AiTranscriptAudit::new(
        &config_with_sink(&endpoint, overrides),
        loopback_http_client(),
    )
    .expect("valid config");
    plugin.start_background_tasks().expect("live start");
    plugin.commit_background_tasks();

    let mut ctx = make_ctx();
    set_prebuffered_body(&mut ctx, ai_request_body());
    let mut proxy_headers = ctx.headers.clone();
    plugin.before_proxy(&mut ctx, &mut proxy_headers).await;
    assert_eq!(
        plugin.capture_counters(),
        (0, 0),
        "staging must not hash the pre-transform body"
    );

    let headers = json_headers();
    plugin
        .on_final_request_body_with_context(&mut ctx, &headers, ai_request_body())
        .await;
    assert_eq!(plugin.capture_counters(), (1, 0));
    let reference = keyed_reference(secret);
    let expected = reference.keyed_hash_hex(ai_request_body());
    assert_eq!(audit_meta(&ctx, HASH_KEY).as_deref(), Some(&*expected));

    // The reject-path refresh and the synthetic-short-circuit refresh both see
    // the same bytes again; neither may re-hash them.
    let mut response_headers = HashMap::new();
    plugin
        .after_proxy(&mut ctx, 200, &mut response_headers)
        .await;
    let synthetic = "ferrum:synthetic_short_circuit".to_string();
    ctx.metadata.insert(synthetic, "true".to_string());
    plugin
        .capture_final_response_body(&mut ctx, 200, &headers, br#"{"ok":true}"#)
        .await;
    assert_eq!(
        plugin.capture_counters(),
        (1, 0),
        "an unchanged body must be HMACed exactly once"
    );

    let records = wait_for_records(&server).await;
    assert_eq!(records.len(), 1);
    assert_eq!(records[0]["request_hash"], json!(expected));
    assert_eq!(records[0]["model"], "gpt-4o");
}

/// A `before_proxy` short-circuit never reaches the final request-body hook, so
/// `after_proxy` performs the single capture over the provider-visible body and
/// the later synthetic response hook does not repeat it.
#[tokio::test]
async fn short_circuit_capture_runs_once_on_the_reject_path() {
    let server = mock_sink().await;
    let endpoint = format!("{}/ingest", server.uri());
    let plugin = AiTranscriptAudit::new(
        &config_with_sink(&endpoint, json!({})),
        loopback_http_client(),
    )
    .expect("valid config");
    plugin.start_background_tasks().expect("live start");
    plugin.commit_background_tasks();

    let mut ctx = make_ctx();
    set_prebuffered_body(&mut ctx, ai_request_body());
    let mut proxy_headers = ctx.headers.clone();
    plugin.before_proxy(&mut ctx, &mut proxy_headers).await;
    assert_eq!(plugin.capture_counters(), (0, 0));

    // A terminator rewrote the provider-visible body before responding.
    let terminated =
        br#"{"model":"gpt-4o-mini","messages":[{"role":"user","content":"terminator"}]}"#;
    set_prebuffered_body(&mut ctx, terminated);
    let mut response_headers = HashMap::new();
    plugin
        .after_proxy(&mut ctx, 502, &mut response_headers)
        .await;
    assert_eq!(
        plugin.capture_counters(),
        (1, 0),
        "the short-circuit path must capture the final body once"
    );

    let synthetic = "ferrum:synthetic_short_circuit".to_string();
    ctx.metadata.insert(synthetic, "true".to_string());
    let headers = json_headers();
    plugin
        .capture_final_response_body(&mut ctx, 502, &headers, br#"{"error":"x"}"#)
        .await;
    assert_eq!(plugin.capture_counters(), (1, 0));

    let records = wait_for_records(&server).await;
    assert_eq!(records.len(), 1);
    assert_eq!(records[0]["model"], "gpt-4o-mini");
    let excerpt = records[0]["request_body"].as_str().expect("request body");
    assert!(excerpt.contains("terminator"), "got: {excerpt}");
}

/// A saturated `max_records_per_minute` window stops paying capture cost: the
/// limiter atomically reserves when the backend-visible body arrives, so dropped
/// transactions never hash, redact, excerpt, or assemble anything — and no
/// hash-less envelope is exported in their place. The first record's reservation
/// is committed at enqueue (not acquired again), which is why it can still queue
/// after the window count is already 1.
#[tokio::test]
async fn saturated_records_per_minute_skips_capture_before_hashing() {
    let server = mock_sink().await;
    let endpoint = format!("{}/ingest", server.uri());
    let plugin = AiTranscriptAudit::new(
        &config_with_sink(
            &endpoint,
            json!({ "sampling": { "max_records_per_minute": 1 } }),
        ),
        loopback_http_client(),
    )
    .expect("valid config");
    plugin.start_background_tasks().expect("live start");
    plugin.commit_background_tasks();
    let headers = json_headers();

    let mut outcomes = Vec::new();
    for _ in 0..3 {
        let mut ctx = make_ctx();
        plugin
            .on_final_request_body_with_context(&mut ctx, &headers, ai_request_body())
            .await;
        plugin
            .capture_final_response_body(&mut ctx, 200, &headers, br#"{"ok":true}"#)
            .await;
        let status = audit_meta(&ctx, SINK_KEY).unwrap_or_default();
        let hashed = audit_meta(&ctx, HASH_KEY).is_some();
        outcomes.push((status, hashed));
    }

    assert_eq!(
        plugin.capture_counters(),
        (1, 2),
        "only the record that reserves window budget may pay capture cost"
    );
    assert_eq!(outcomes[0], ("queued".to_string(), true));
    assert_eq!(outcomes[1], ("dropped".to_string(), false));
    assert_eq!(outcomes[2], ("dropped".to_string(), false));

    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    let received = server.received_requests().await.unwrap_or_default();
    let total: usize = received
        .iter()
        .filter_map(|request| serde_json::from_slice::<Value>(&request.body).ok())
        .filter_map(|body| body.as_array().map(Vec::len))
        .sum();
    assert_eq!(total, 1, "no body-less envelope may be exported");
}

/// `streaming_response: true` tees every staged candidate — except one whose
/// record can never be emitted. Hashing and accumulating an SSE prefix for it
/// would be pure amplification, and it must also stay off the reqwest-pinned
/// dispatch path.
#[tokio::test]
async fn unemittable_candidate_is_not_teed_with_streaming_capture_on() {
    let plugin = AiTranscriptAudit::new(
        &config_with_sink(
            "https://audit.example.com/x",
            json!({
                "capture": { "streaming_response": true },
                "sampling": {
                    "rate": 0.0,
                    "always_capture_on_guardrail": false,
                    "always_capture_on_error": false
                }
            }),
        ),
        loopback_http_client(),
    )
    .expect("valid config");
    let mut ctx = make_ctx();
    set_prebuffered_body(&mut ctx, ai_request_body());
    let mut headers = ctx.headers.clone();
    plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_eq!(audit_meta(&ctx, CANDIDATE_KEY).as_deref(), Some("true"));
    assert!(!plugin.forces_reqwest_dispatch(&ctx));
    let sse = Some("text/event-stream");
    assert!(plugin.response_stream_inspector(&ctx, 200, sse).is_none());

    // A sampled candidate under the same streaming policy still tees.
    let sampled = AiTranscriptAudit::new(
        &config_with_sink(
            "https://audit.example.com/x",
            json!({ "capture": { "streaming_response": true } }),
        ),
        loopback_http_client(),
    )
    .expect("valid config");
    let mut hit = make_ctx();
    set_prebuffered_body(&mut hit, ai_request_body());
    let mut hit_headers = hit.headers.clone();
    sampled.before_proxy(&mut hit, &mut hit_headers).await;
    assert!(sampled.forces_reqwest_dispatch(&hit));
    assert!(sampled.response_stream_inspector(&hit, 200, sse).is_some());
}

/// Two candidates may reach capture admission before either enqueues. With
/// `max_records_per_minute = 1`, only the admitted/reserved candidate may pay
/// capture cost; the loser's staging carries `capture_skipped` so streaming
/// capture neither pins reqwest dispatch nor installs an SSE inspector. The
/// reserved winner must still enqueue by committing its existing reservation
/// (a second limiter acquisition would fail because the window count is already
/// 1), while an independently configured admissible candidate still tees.
#[tokio::test]
async fn rate_limited_candidate_is_not_teed_with_streaming_capture_on() {
    let server = mock_sink().await;
    let endpoint = format!("{}/ingest", server.uri());
    let stream_body =
        br#"{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}],"stream":true}"#;
    let plugin = AiTranscriptAudit::new(
        &config_with_sink(
            &endpoint,
            json!({
                "capture": { "streaming_response": true },
                "sampling": { "max_records_per_minute": 1 }
            }),
        ),
        loopback_http_client(),
    )
    .expect("valid config");
    plugin.start_background_tasks().expect("live start");
    plugin.commit_background_tasks();
    let headers = json_headers();
    let sse = Some("text/event-stream");

    // Concurrent-admission window: both reach capture before either enqueues.
    let mut first = make_ctx();
    plugin
        .on_final_request_body_with_context(&mut first, &headers, ai_request_body())
        .await;
    assert_eq!(plugin.capture_counters(), (1, 0));
    assert!(audit_meta(&first, HASH_KEY).is_some());

    let mut limited = make_ctx();
    plugin
        .on_final_request_body_with_context(&mut limited, &headers, stream_body)
        .await;
    assert_eq!(
        plugin.capture_counters(),
        (1, 1),
        "only the reserved candidate may capture once the window is saturated"
    );
    assert_eq!(audit_meta(&limited, HASH_KEY), None);
    assert!(
        !plugin.forces_reqwest_dispatch(&limited),
        "rate-limited candidate must not pin reqwest dispatch"
    );
    assert!(
        plugin
            .response_stream_inspector(&limited, 200, sse)
            .is_none(),
        "rate-limited candidate must not install an SSE inspector"
    );

    // The reserved first record commits its existing reservation at enqueue —
    // it must not attempt a second acquisition against the already-full window.
    plugin
        .capture_final_response_body(&mut first, 200, &headers, br#"{"ok":true}"#)
        .await;
    assert_eq!(audit_meta(&first, SINK_KEY).as_deref(), Some("queued"));
    let records = wait_for_records(&server).await;
    assert_eq!(
        records.len(),
        1,
        "reserved capture must still be exportable"
    );

    let admissible = AiTranscriptAudit::new(
        &config_with_sink(
            "https://audit.example.com/x",
            json!({ "capture": { "streaming_response": true } }),
        ),
        loopback_http_client(),
    )
    .expect("valid config");
    let mut hit = make_ctx();
    set_prebuffered_body(&mut hit, stream_body);
    let mut hit_headers = hit.headers.clone();
    admissible.before_proxy(&mut hit, &mut hit_headers).await;
    admissible
        .on_final_request_body_with_context(&mut hit, &headers, stream_body)
        .await;
    assert!(admissible.forces_reqwest_dispatch(&hit));
    assert!(
        admissible
            .response_stream_inspector(&hit, 200, sse)
            .is_some()
    );
}

/// A capture-time reservation that never emits must release its slot so a later
/// candidate in the same window can be admitted. Configured as a sampling loser
/// that only *might* emit via `always_capture_on_error`; a successful 200 path
/// does not emit, drops staging, and frees the reservation.
#[tokio::test]
async fn discarded_rate_reservation_is_released_for_later_candidate() {
    let server = mock_sink().await;
    let endpoint = format!("{}/ingest", server.uri());
    let plugin = AiTranscriptAudit::new(
        &config_with_sink(
            &endpoint,
            json!({
                "sampling": {
                    "rate": 0.0,
                    "always_capture_on_guardrail": false,
                    "always_capture_on_error": true,
                    "max_records_per_minute": 1
                }
            }),
        ),
        loopback_http_client(),
    )
    .expect("valid config");
    plugin.start_background_tasks().expect("live start");
    plugin.commit_background_tasks();
    let headers = json_headers();

    let mut first = make_ctx();
    plugin
        .on_final_request_body_with_context(&mut first, &headers, ai_request_body())
        .await;
    assert_eq!(
        plugin.capture_counters(),
        (1, 0),
        "override-eligible loser still reserves and captures"
    );
    plugin
        .capture_final_response_body(&mut first, 200, &headers, br#"{"ok":true}"#)
        .await;
    assert_eq!(
        audit_meta(&first, SINK_KEY).as_deref(),
        Some("skipped"),
        "successful response without error/guardrail must not emit"
    );

    let mut second = make_ctx();
    plugin
        .on_final_request_body_with_context(&mut second, &headers, ai_request_body())
        .await;
    assert_eq!(
        plugin.capture_counters(),
        (2, 0),
        "released reservation must admit a later candidate in the same window"
    );
    plugin
        .capture_final_response_body(&mut second, 500, &headers, br#"{"error":"x"}"#)
        .await;
    assert_eq!(audit_meta(&second, SINK_KEY).as_deref(), Some("queued"));
    let records = wait_for_records(&server).await;
    assert_eq!(records.len(), 1);
    assert_eq!(records[0]["capture_reason"], "error");
}

/// A streamed (`stream: true`) transaction also pays exactly one request
/// capture: staging classifies, the final request-body hook captures, and the
/// SSE tee plus the stream-terminal record assembly add none.
#[tokio::test]
async fn streamed_transaction_pays_one_request_capture() {
    let server = mock_sink().await;
    let endpoint = format!("{}/ingest", server.uri());
    let plugin = AiTranscriptAudit::new(
        &config_with_sink(
            &endpoint,
            json!({ "capture": { "streaming_response": true } }),
        ),
        loopback_http_client(),
    )
    .expect("valid config");
    plugin.start_background_tasks().expect("live start");
    plugin.commit_background_tasks();

    let streamed =
        br#"{"model":"gpt-4o","stream":true,"messages":[{"role":"user","content":"hi"}]}"#;
    let mut ctx = make_ctx();
    set_prebuffered_body(&mut ctx, streamed);
    let mut proxy_headers = ctx.headers.clone();
    plugin.before_proxy(&mut ctx, &mut proxy_headers).await;
    assert_eq!(plugin.capture_counters(), (0, 0));

    plugin
        .on_final_request_body_with_context(&mut ctx, &json_headers(), streamed)
        .await;
    assert_eq!(plugin.capture_counters(), (1, 0));

    let sse = Some("text/event-stream");
    let inspector = plugin
        .response_stream_inspector(&ctx, 200, sse)
        .expect("sampled SSE must be teed");
    let mut chain = chain_response_stream_inspectors(vec![inspector]).expect("chain");
    let body = b"data: {\"choices\":[{\"delta\":{\"content\":\"ok\"}}]}\n\ndata: [DONE]\n\n";
    let _ = chain.on_chunk(body).await;
    let _ = chain.on_end().await;
    let outcome = BodyOutcome::success(body.len() as u64);
    plugin
        .on_response_stream_terminated(&mut ctx, 200, &outcome)
        .await;
    assert_eq!(
        plugin.capture_counters(),
        (1, 0),
        "the response path must not re-capture the request"
    );

    let records = wait_for_records(&server).await;
    assert_eq!(records.len(), 1);
    assert!(records[0]["request_hash"].is_string());
    assert!(records[0]["response_hash"].is_string());
}
