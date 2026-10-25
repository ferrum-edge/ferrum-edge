//! Tests for response_size_limiting plugin

use bytes::Bytes;
use ferrum_edge::_test_support::finalize_synthetic_response_for_test;
use ferrum_edge::plugins::response_size_limiting::ResponseSizeLimiting;
use ferrum_edge::plugins::{Plugin, PluginResult, RequestContext, validate_plugin_config};
use serde_json::json;
use std::collections::HashMap;
use std::sync::Arc;

fn make_ctx() -> RequestContext {
    make_ctx_with_method("GET")
}

fn make_ctx_with_method(method: &str) -> RequestContext {
    RequestContext::new(
        "127.0.0.1".to_string(),
        method.to_string(),
        "/api".to_string(),
    )
}

// === Plugin creation ===

#[tokio::test]
async fn test_creation_defaults() {
    let plugin = ResponseSizeLimiting::new(&json!({"max_bytes": 1024})).unwrap();
    assert_eq!(plugin.name(), "response_size_limiting");
    assert_eq!(plugin.priority(), 3490);
}

#[tokio::test]
async fn test_zero_max_bytes_returns_error() {
    let result = ResponseSizeLimiting::new(&json!({}));
    assert!(result.is_err());
    let err = result.err().unwrap();
    assert!(err.contains("max_bytes"));
}

#[tokio::test]
async fn test_non_object_config_returns_error() {
    let result = ResponseSizeLimiting::new(&json!("bad"));
    assert!(result.is_err());
    assert!(result.err().unwrap().contains("config must be an object"));
}

#[tokio::test]
async fn test_invalid_require_buffered_check_type_returns_error() {
    let result = ResponseSizeLimiting::new(&json!({
        "max_bytes": 1024,
        "require_buffered_check": "yes"
    }));
    assert!(result.is_err());
    assert!(result.err().unwrap().contains("require_buffered_check"));
}

#[test]
fn test_unknown_config_keys_rejected_with_spelling_suggestion() {
    let err = ResponseSizeLimiting::new(&json!({
        "max_bytes": 1024,
        "require_buffered_checks": true
    }))
    .err()
    .expect("misspelled strict-check key must be rejected");
    assert!(err.contains("unknown configuration key"), "{err}");
    assert!(err.contains("require_buffered_checks"), "{err}");
    assert!(
        err.contains("did you mean `require_buffered_check`?"),
        "{err}"
    );

    let shared = validate_plugin_config(
        "response_size_limiting",
        &json!({
            "max_bytes": 1024,
            "require_buffered_checks": true
        }),
    )
    .expect_err("shared admission must reject the same typo");
    assert!(shared.contains("require_buffered_checks"), "{shared}");
}

#[test]
fn test_explicit_null_require_buffered_check_rejected() {
    let err = ResponseSizeLimiting::new(&json!({
        "max_bytes": 1024,
        "require_buffered_check": null
    }))
    .err()
    .expect("explicit null must be rejected");
    assert!(
        err.contains("`require_buffered_check` must be a boolean"),
        "{err}"
    );
    assert!(
        !err.contains("unknown configuration key"),
        "recognized-field null must not be mislabeled as unknown: {err}"
    );
}

#[test]
fn test_omitted_require_buffered_check_defaults_false() {
    let plugin = ResponseSizeLimiting::new(&json!({"max_bytes": 1024}))
        .expect("omitted strict-check flag must keep default");
    assert!(!plugin.requires_response_body_buffering());
}

// === Content-Length fast path (after_proxy) ===

#[tokio::test]
async fn test_content_length_under_limit_passes() {
    let plugin = ResponseSizeLimiting::new(&json!({"max_bytes": 1024})).unwrap();
    let mut ctx = make_ctx();
    let mut headers = HashMap::new();
    headers.insert("content-length".to_string(), "512".to_string());

    let result = plugin.after_proxy(&mut ctx, 200, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
}

#[tokio::test]
async fn test_content_length_at_limit_passes() {
    let plugin = ResponseSizeLimiting::new(&json!({"max_bytes": 1024})).unwrap();
    let mut ctx = make_ctx();
    let mut headers = HashMap::new();
    headers.insert("content-length".to_string(), "1024".to_string());

    let result = plugin.after_proxy(&mut ctx, 200, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
}

#[tokio::test]
async fn test_content_length_over_limit_rejects_502() {
    let plugin = ResponseSizeLimiting::new(&json!({"max_bytes": 1024})).unwrap();
    let mut ctx = make_ctx();
    let mut headers = HashMap::new();
    headers.insert("content-length".to_string(), "1025".to_string());

    match plugin.after_proxy(&mut ctx, 200, &mut headers).await {
        PluginResult::Reject {
            status_code, body, ..
        } => {
            assert_eq!(status_code, 502);
            assert!(body.contains("Response body too large"));
            assert!(body.contains("1024"));
        }
        _ => panic!("Expected Reject"),
    }
}

#[tokio::test]
async fn test_no_content_length_header_passes() {
    let plugin = ResponseSizeLimiting::new(&json!({"max_bytes": 1024})).unwrap();
    let mut ctx = make_ctx();
    let mut headers = HashMap::new();

    let result = plugin.after_proxy(&mut ctx, 200, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
}

#[tokio::test]
async fn test_invalid_content_length_fails_closed() {
    let plugin = ResponseSizeLimiting::new(&json!({"max_bytes": 1024})).unwrap();
    let mut ctx = make_ctx();
    let mut headers = HashMap::new();
    headers.insert("content-length".to_string(), "bad".to_string());

    match plugin.after_proxy(&mut ctx, 200, &mut headers).await {
        PluginResult::Reject { status_code, .. } => assert_eq!(status_code, 502),
        other => panic!("Expected 502 Reject, got {other:?}"),
    }
}

// === Bodyless response semantics (issue #2343) ===
// after_proxy is the shared H1/H2/H3 Content-Length fast path; method/status
// coverage here applies to every HTTP-family protocol path.

#[tokio::test]
async fn test_oversized_content_length_on_head_passes() {
    let plugin = ResponseSizeLimiting::new(&json!({"max_bytes": 1024})).unwrap();
    let mut ctx = make_ctx_with_method("HEAD");
    let mut headers = HashMap::new();
    headers.insert("content-length".to_string(), "10485760".to_string());

    let result = plugin.after_proxy(&mut ctx, 200, &mut headers).await;
    assert!(
        matches!(result, PluginResult::Continue),
        "HEAD may advertise representation Content-Length without a body"
    );
}

#[tokio::test]
async fn test_oversized_content_length_on_304_passes() {
    let plugin = ResponseSizeLimiting::new(&json!({"max_bytes": 1024})).unwrap();
    let mut ctx = make_ctx();
    let mut headers = HashMap::new();
    headers.insert("content-length".to_string(), "10485760".to_string());

    let result = plugin.after_proxy(&mut ctx, 304, &mut headers).await;
    assert!(
        matches!(result, PluginResult::Continue),
        "304 may carry representation Content-Length with no message body"
    );
}

#[tokio::test]
async fn test_oversized_content_length_on_206_still_rejects() {
    // Body-bearing control: partial content still transfers body bytes.
    let plugin = ResponseSizeLimiting::new(&json!({"max_bytes": 1024})).unwrap();
    let mut ctx = make_ctx();
    let mut headers = HashMap::new();
    headers.insert("content-length".to_string(), "10485760".to_string());

    match plugin.after_proxy(&mut ctx, 206, &mut headers).await {
        PluginResult::Reject { status_code, .. } => {
            assert_eq!(status_code, 502);
        }
        _ => panic!("Expected Reject for oversized body-bearing 206"),
    }
}

#[tokio::test]
async fn test_body_bearing_exact_boundary_still_passes_for_206() {
    let plugin = ResponseSizeLimiting::new(&json!({"max_bytes": 1024})).unwrap();
    let mut ctx = make_ctx();
    let mut headers = HashMap::new();
    headers.insert("content-length".to_string(), "1024".to_string());

    let result = plugin.after_proxy(&mut ctx, 206, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
}

// === Final body check (on_final_response_body) ===

#[tokio::test]
async fn test_buffered_body_under_limit_passes() {
    let plugin =
        ResponseSizeLimiting::new(&json!({"max_bytes": 100, "require_buffered_check": true}))
            .unwrap();
    let mut ctx = make_ctx();
    let headers = HashMap::new();
    let body = b"short";

    let result = plugin
        .on_final_response_body(&mut ctx, 200, &headers, body)
        .await;
    assert!(matches!(result, PluginResult::Continue));
}

#[tokio::test]
async fn test_buffered_body_over_limit_rejects() {
    let plugin =
        ResponseSizeLimiting::new(&json!({"max_bytes": 10, "require_buffered_check": true}))
            .unwrap();
    let mut ctx = make_ctx();
    let headers = HashMap::new();
    let body = b"this response body is definitely longer than ten bytes";

    match plugin
        .on_final_response_body(&mut ctx, 200, &headers, body)
        .await
    {
        PluginResult::Reject {
            status_code, body, ..
        } => {
            assert_eq!(status_code, 502);
            assert!(body.contains("Response body too large"));
        }
        _ => panic!("Expected Reject"),
    }
}

#[tokio::test]
async fn test_buffered_body_at_limit_passes() {
    let plugin = ResponseSizeLimiting::new(&json!({"max_bytes": 5})).unwrap();
    let mut ctx = make_ctx();
    let headers = HashMap::new();
    let body = b"12345";

    let result = plugin
        .on_final_response_body(&mut ctx, 200, &headers, body)
        .await;
    assert!(matches!(result, PluginResult::Continue));
}

// === Response body buffering flag ===

#[tokio::test]
async fn test_requires_buffering_when_configured() {
    let plugin =
        ResponseSizeLimiting::new(&json!({"max_bytes": 1024, "require_buffered_check": true}))
            .unwrap();
    assert!(plugin.requires_response_body_buffering());
}

#[tokio::test]
async fn test_no_buffering_by_default() {
    let plugin = ResponseSizeLimiting::new(&json!({"max_bytes": 1024})).unwrap();
    assert!(!plugin.requires_response_body_buffering());
}

#[tokio::test]
async fn test_max_bytes_zero_returns_error() {
    let result =
        ResponseSizeLimiting::new(&json!({"max_bytes": 0, "require_buffered_check": true}));
    assert!(result.is_err());
}

// === Protocol support ===

#[tokio::test]
async fn test_supports_http_and_grpc() {
    let plugin = ResponseSizeLimiting::new(&json!({"max_bytes": 1024})).unwrap();
    let protocols = plugin.supported_protocols();
    assert!(protocols.contains(&ferrum_edge::plugins::ProxyProtocol::Http));
    assert!(protocols.contains(&ferrum_edge::plugins::ProxyProtocol::Grpc));
    assert!(!protocols.contains(&ferrum_edge::plugins::ProxyProtocol::WebSocket));
}

// === Rejection body format ===

#[tokio::test]
async fn test_rejection_body_is_valid_json() {
    let plugin = ResponseSizeLimiting::new(&json!({"max_bytes": 10})).unwrap();
    let mut ctx = make_ctx();
    let mut headers = HashMap::new();
    headers.insert("content-length".to_string(), "100".to_string());

    match plugin.after_proxy(&mut ctx, 200, &mut headers).await {
        PluginResult::Reject { body, .. } => {
            let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
            assert_eq!(parsed["error"], "Response body too large");
            assert_eq!(parsed["limit"], 10);
        }
        _ => panic!("Expected Reject"),
    }
}

// === Large response ===

#[tokio::test]
async fn test_large_content_length_rejects() {
    let plugin = ResponseSizeLimiting::new(&json!({"max_bytes": 1048576})).unwrap(); // 1 MiB
    let mut ctx = make_ctx();
    let mut headers = HashMap::new();
    headers.insert("content-length".to_string(), "10485760".to_string()); // 10 MiB

    match plugin.after_proxy(&mut ctx, 200, &mut headers).await {
        PluginResult::Reject { status_code, .. } => {
            assert_eq!(status_code, 502);
        }
        _ => panic!("Expected Reject"),
    }
}

// === SSE policy boundary ===

#[tokio::test]
async fn test_sse_request_intent_cannot_skip_strict_response_limit() {
    let plugin =
        ResponseSizeLimiting::new(&json!({"max_bytes": 1024, "require_buffered_check": true}))
            .unwrap();
    assert!(plugin.requires_response_body_buffering());

    let mut ctx = make_ctx();
    ctx.headers
        .insert("accept".to_string(), "text/event-stream".to_string());

    assert!(plugin.should_buffer_response_body(&ctx));
    let response_headers =
        HashMap::from([("content-type".to_string(), "text/event-stream".to_string())]);
    assert!(!plugin.should_buffer_response_body_for_content_type(
        &ctx,
        Some("text/event-stream"),
        200,
        &response_headers,
    ));
    assert!(plugin.should_buffer_response_body_for_content_type(&ctx, None, 200, &HashMap::new(),));
    assert!(plugin.should_buffer_response_body_for_content_type(
        &ctx,
        Some("application/json; profile=event-stream"),
        200,
        &HashMap::new(),
    ));
}

#[tokio::test]
async fn test_non_sse_request_still_buffers() {
    let plugin =
        ResponseSizeLimiting::new(&json!({"max_bytes": 1024, "require_buffered_check": true}))
            .unwrap();

    let mut ctx = make_ctx();
    ctx.headers
        .insert("accept".to_string(), "application/json".to_string());

    assert!(plugin.should_buffer_response_body(&ctx));
}

#[tokio::test]
async fn test_buffering_disabled_stays_disabled_for_sse() {
    // When require_buffered_check is off the buffer flag is false; SSE
    // detection must not flip it on.
    let plugin = ResponseSizeLimiting::new(&json!({"max_bytes": 1024})).unwrap();
    assert!(!plugin.requires_response_body_buffering());

    let mut ctx = make_ctx();
    ctx.headers
        .insert("accept".to_string(), "text/event-stream".to_string());

    assert!(!plugin.should_buffer_response_body(&ctx));
}

#[tokio::test]
async fn test_sse_content_length_fast_path_still_runs() {
    // Backends that advertise a Content-Length larger than the limit retain
    // the ordinary fast-path rejection before the SSE-specific boundary.
    let plugin =
        ResponseSizeLimiting::new(&json!({"max_bytes": 1024, "require_buffered_check": true}))
            .unwrap();
    let mut ctx = make_ctx();
    ctx.headers
        .insert("accept".to_string(), "text/event-stream".to_string());
    let mut headers = HashMap::new();
    headers.insert("content-length".to_string(), "2048".to_string());

    match plugin.after_proxy(&mut ctx, 200, &mut headers).await {
        PluginResult::Reject { status_code, .. } => {
            assert_eq!(status_code, 502);
        }
        _ => panic!("Expected Reject when Content-Length exceeds limit"),
    }
}

#[tokio::test]
async fn test_genuine_sse_fails_closed_at_strict_route_limit() {
    let plugin =
        ResponseSizeLimiting::new(&json!({"max_bytes": 1024, "require_buffered_check": true}))
            .unwrap();
    let mut ctx = make_ctx();
    let mut headers =
        HashMap::from([("content-type".to_string(), "text/event-stream".to_string())]);

    match plugin.after_proxy(&mut ctx, 200, &mut headers).await {
        PluginResult::Reject {
            status_code, body, ..
        } => {
            assert_eq!(status_code, 502);
            assert!(body.contains("Streaming response size cannot be verified"));
            assert!(body.contains("1024"));
        }
        _ => panic!("Expected fail-closed event-stream rejection"),
    }
}

/// Keep `docs/size_limits.md` aligned with the streaming runtime contract that
/// `response_size_limiting` points operators at (issue #2346). Unknown-length
/// responses must not be documented as a full-buffer fallback that promises a
/// post-commit JSON 502.
#[test]
fn test_size_limits_guide_matches_streaming_runtime_contract() {
    let size_limits = include_str!("../../../docs/size_limits.md");
    let streaming = include_str!("../../../docs/response_body_streaming.md");
    let plugin_docs = include_str!("../../../docs/plugins.md");

    assert!(
        !size_limits.contains("falls back to buffering"),
        "size_limits.md must not claim unknown-length responses fall back to buffering"
    );
    assert!(
        size_limits.contains("SizeLimitedStreamingResponse"),
        "size_limits.md must name SizeLimitedStreamingResponse for unknown-length streaming"
    );
    assert!(
        size_limits.contains("post-commit"),
        "size_limits.md must distinguish post-commit stream termination from pre-commit rejection"
    );
    assert!(
        size_limits.contains("response_body_streaming.md#interaction-with-response-size-limits"),
        "size_limits.md must link the streaming size-limit section"
    );
    assert!(
        size_limits.contains("plugins.md#response_size_limiting"),
        "size_limits.md must link the response_size_limiting plugin reference"
    );

    // Counterpart docs already describe the streaming adapter; keep the shared
    // terminology from drifting back to a buffering-only story.
    assert!(streaming.contains("SizeLimitedStreamingResponse"));
    assert!(
        plugin_docs.contains("SizeLimitedStreamingResponse"),
        "response_size_limiting reference must mention the global streaming adapter"
    );
}

// === Route ceiling publication (GHSA-xrfj-852f-645j) ===

/// Publication is deliberately independent of `require_buffered_check`. It gives
/// the core two things the hooks cannot express: buffered collection aborts at
/// this ceiling instead of retaining up to the larger global allowance, and an
/// already-buffered synthetic body is governed without another plugin having to
/// activate the response body-hook gate.
#[test]
fn enforced_response_body_limit_is_published_without_forcing_buffering() {
    let plugin = ResponseSizeLimiting::new(&json!({"max_bytes": 1024})).unwrap();
    assert_eq!(plugin.enforced_response_body_limit(), Some(1024));
    // The default instance advertises no buffering — that was exactly why the
    // synthetic body-hook gate stayed closed before the fix.
    assert!(!plugin.requires_response_body_buffering());
    // It is a response-side policy only.
    assert_eq!(plugin.enforced_request_body_limit(), None);
}

#[test]
fn strict_instance_publishes_the_same_ceiling_and_forces_buffering() {
    let plugin =
        ResponseSizeLimiting::new(&json!({"max_bytes": 1024, "require_buffered_check": true}))
            .unwrap();
    assert_eq!(plugin.enforced_response_body_limit(), Some(1024));
    assert!(plugin.requires_response_body_buffering());
}

// === Already-buffered synthetic response enforcement ===

#[tokio::test]
async fn synthetic_response_uses_strictest_global_and_route_ceiling() {
    for (global_limit, route_limit, body, expected_status) in [
        // A looser route policy cannot relax the global ceiling.
        (4usize, Some(10u64), b"12345".as_slice(), 502u16),
        // An unlimited global cannot disable the route ceiling.
        (0usize, Some(4u64), b"12345".as_slice(), 502u16),
        // The exact effective boundary is permitted.
        (4usize, Some(10u64), b"1234".as_slice(), 200u16),
    ] {
        let plugin_limit = route_limit.unwrap_or(10);
        let plugin: Arc<dyn Plugin> =
            Arc::new(ResponseSizeLimiting::new(&json!({"max_bytes": plugin_limit})).unwrap());
        let plugins = vec![plugin];
        let mut ctx = make_ctx();
        ctx.max_response_body_size_bytes = global_limit;
        ctx.route_response_body_limit_bytes = route_limit;
        let mut status = 200;
        let mut headers = HashMap::new();
        let mut response_body = Bytes::copy_from_slice(body);

        finalize_synthetic_response_for_test(
            &plugins,
            &mut ctx,
            &mut status,
            &mut headers,
            &mut response_body,
        )
        .await;

        assert_eq!(
            status,
            expected_status,
            "global={global_limit}, route={route_limit:?}, body_len={}",
            body.len()
        );
    }
}

#[tokio::test]
async fn synthetic_response_without_route_plugin_still_honors_global_ceiling() {
    let mut ctx = make_ctx();
    ctx.max_response_body_size_bytes = 4;
    ctx.route_response_body_limit_bytes = None;
    let mut status = 200;
    let mut headers = HashMap::new();
    let mut response_body = Bytes::from_static(b"12345");

    finalize_synthetic_response_for_test(
        &[],
        &mut ctx,
        &mut status,
        &mut headers,
        &mut response_body,
    )
    .await;

    assert_eq!(status, 502);
    assert!(
        String::from_utf8_lossy(&response_body).contains("Response body too large"),
        "global-only rejection must replace the synthetic body"
    );
}

// === Repeated / ambiguous response Content-Length (GHSA-xrfj-852f-645j) ===

/// Hyper accepts a backend response whose `Content-Length` repeats with
/// identical values, and the shared collector folds those repeats with `", "`.
/// Parsing the whole folded list as one integer used to fail, so the fast path
/// missed an oversized coalesced declaration.
#[tokio::test]
async fn test_repeated_identical_response_content_length_rejects_502() {
    let plugin = ResponseSizeLimiting::new(&json!({"max_bytes": 1024})).unwrap();
    let mut ctx = make_ctx();
    let mut headers = HashMap::new();
    headers.insert("content-length".to_string(), "2048, 2048".to_string());

    match plugin.after_proxy(&mut ctx, 200, &mut headers).await {
        PluginResult::Reject { status_code, .. } => assert_eq!(status_code, 502),
        other => panic!("Expected 502 Reject, got {other:?}"),
    }
}

#[tokio::test]
async fn test_repeated_identical_response_content_length_at_boundary_passes() {
    let plugin = ResponseSizeLimiting::new(&json!({"max_bytes": 1024})).unwrap();
    let mut ctx = make_ctx();
    let mut headers = HashMap::new();
    headers.insert("content-length".to_string(), "1024, 1024".to_string());

    assert!(matches!(
        plugin.after_proxy(&mut ctx, 200, &mut headers).await,
        PluginResult::Continue
    ));
}

/// A response declared length that cannot be reduced to one value fails closed.
#[tokio::test]
async fn test_ambiguous_response_content_length_fails_closed_with_502() {
    let plugin = ResponseSizeLimiting::new(&json!({"max_bytes": 1024})).unwrap();
    for value in ["2048, 4096", "+2048"] {
        let mut ctx = make_ctx();
        let mut headers = HashMap::new();
        headers.insert("content-length".to_string(), value.to_string());

        match plugin.after_proxy(&mut ctx, 200, &mut headers).await {
            PluginResult::Reject {
                status_code, body, ..
            } => {
                assert_eq!(status_code, 502, "{value:?} must fail closed");
                let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
                assert_eq!(parsed["error"], "Response Content-Length is ambiguous");
            }
            other => panic!("Expected 502 Reject for {value:?}, got {other:?}"),
        }
    }
}

/// Bodyless semantics are unaffected: their `Content-Length` describes a
/// representation, not transferred bytes, so neither an oversized value nor an
/// ambiguous fold is a body-size violation.
#[tokio::test]
async fn test_bodyless_responses_ignore_repeated_and_ambiguous_lengths() {
    let plugin = ResponseSizeLimiting::new(&json!({"max_bytes": 10})).unwrap();
    for (method, status, value) in [
        ("HEAD", 200u16, "2048, 2048"),
        ("GET", 304, "2048, 2048"),
        ("GET", 204, "2048, 4096"),
        ("HEAD", 200, "2048, 4096"),
    ] {
        let mut ctx = make_ctx_with_method(method);
        let mut headers = HashMap::new();
        headers.insert("content-length".to_string(), value.to_string());

        assert!(
            matches!(
                plugin.after_proxy(&mut ctx, status, &mut headers).await,
                PluginResult::Continue
            ),
            "bodyless {method} {status} with {value:?} must not trip a body-size limit"
        );
    }
}

/// A chunked / unknown-length response has no declared length: the fast path
/// stays quiet and the bounded collector enforces the ceiling.
#[tokio::test]
async fn test_unknown_length_response_passes_the_header_fast_path() {
    let plugin = ResponseSizeLimiting::new(&json!({"max_bytes": 1024})).unwrap();
    let mut ctx = make_ctx();
    let mut headers = HashMap::new();

    assert!(matches!(
        plugin.after_proxy(&mut ctx, 200, &mut headers).await,
        PluginResult::Continue
    ));
}

/// Post-transform enforcement is preserved: a body that expands past the ceiling
/// after response transforms is still refused.
#[tokio::test]
async fn test_final_response_body_over_limit_still_rejects_after_transforms() {
    let plugin = ResponseSizeLimiting::new(&json!({"max_bytes": 8})).unwrap();
    let mut ctx = make_ctx();
    let headers = HashMap::new();

    assert!(matches!(
        plugin
            .on_final_response_body(&mut ctx, 200, &headers, b"12345678")
            .await,
        PluginResult::Continue
    ));
    match plugin
        .on_final_response_body(&mut ctx, 200, &headers, b"123456789")
        .await
    {
        PluginResult::Reject { status_code, .. } => assert_eq!(status_code, 502),
        other => panic!("Expected 502 Reject, got {other:?}"),
    }
}

#[test]
fn configuration_diagnostics_keep_schema_and_withhold_supplied_values() {
    for (config, field, reason) in [
        (
            json!({"max_bytes": false}),
            "`max_bytes`",
            "must be greater than zero",
        ),
        (
            json!({"max_bytes": 1, "require_buffered_check": 918273641}),
            "`require_buffered_check`",
            "must be a boolean",
        ),
    ] {
        let error = ferrum_edge::plugins::validate_plugin_config("response_size_limiting", &config)
            .expect_err("invalid configuration must still be rejected");
        let rendered = ferrum_edge::startup::render_startup_error(anyhow::anyhow!(error), &[]);
        assert!(rendered.contains(field), "{rendered}");
        assert!(rendered.contains(reason), "{rendered}");
        for withheld in ["UNREGISTERED_TRAFFIC_TOKEN", "918273641", "true", "false"] {
            assert!(!rendered.contains(withheld), "{withheld}: {rendered}");
        }
    }
}

// === Strict mode: an event stream that proves its size is admitted ===

/// A request context stamped by the PRODUCTION route-policy stamp
/// (`PluginCacheRequestView::stamp_route_body_policy`) for a proxy whose
/// plugin chain is exactly `plugins` (`(name, config)` pairs).
fn route_stamped_ctx(plugins: &[(&str, serde_json::Value)]) -> RequestContext {
    use chrono::Utc;
    use ferrum_edge::config::types::{
        GatewayConfig, PluginAssociation, PluginConfig, PluginScope, default_namespace,
    };

    let mut proxy = super::plugin_utils::create_test_proxy();
    let plugin_configs: Vec<PluginConfig> = plugins
        .iter()
        .enumerate()
        .map(|(index, (name, config))| PluginConfig {
            labels: Default::default(),
            id: format!("plugin-{index}"),
            namespace: default_namespace(),
            plugin_name: (*name).to_string(),
            config: config.clone(),
            scope: PluginScope::Proxy,
            proxy_id: Some(proxy.id.clone()),
            enabled: true,
            priority_override: None,
            trigger: None,
            api_spec_id: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        })
        .collect();
    proxy.plugins = plugin_configs
        .iter()
        .map(|plugin| PluginAssociation {
            plugin_config_id: plugin.id.clone(),
        })
        .collect();
    let proxy_id = proxy.id.clone();
    let config = GatewayConfig {
        version: "1".to_string(),
        proxies: vec![proxy],
        plugin_configs,
        loaded_at: Utc::now(),
        ..Default::default()
    };
    let cache = ferrum_edge::PluginCache::new(&config).expect("route plugin chain must admit");
    let mut ctx = make_ctx();
    cache
        .request_view(
            &default_namespace(),
            &proxy_id,
            ferrum_edge::plugins::ProxyProtocol::Http,
        )
        .stamp_route_body_policy(&mut ctx);
    ctx
}

/// A strict 1024-byte limiter alone: nothing on the route rewrites the stream.
fn pass_through_route_ctx() -> RequestContext {
    let ctx = route_stamped_ctx(&[(
        "response_size_limiting",
        json!({"max_bytes": 1024, "require_buffered_check": true}),
    )]);
    assert_eq!(ctx.route_may_rewrite_response_stream, Some(false));
    ctx
}

fn strict_limiter(max_bytes: u64) -> ResponseSizeLimiting {
    ResponseSizeLimiting::new(&json!({"max_bytes": max_bytes, "require_buffered_check": true}))
        .unwrap()
}

fn sse_headers_with_length(content_length: Option<&str>) -> HashMap<String, String> {
    let mut headers =
        HashMap::from([("content-type".to_string(), "text/event-stream".to_string())]);
    if let Some(content_length) = content_length {
        headers.insert("content-length".to_string(), content_length.to_string());
    }
    headers
}

fn assert_unverifiable_stream_refusal(result: PluginResult, limit: &str) {
    match result {
        PluginResult::Reject {
            status_code, body, ..
        } => {
            assert_eq!(status_code, 502);
            assert!(
                body.contains("Streaming response size cannot be verified"),
                "{body}"
            );
            assert!(body.contains(limit), "{body}");
        }
        other => panic!("expected the strict event-stream refusal, got {other:?}"),
    }
}

/// A finite event stream whose backend declared one exact, in-limit length has
/// already proven its complete size, so strict mode admits it instead of
/// refusing every known-length SSE response (DEEPSEEK-FLASH-1).
#[tokio::test]
async fn strict_sse_with_exact_in_limit_content_length_is_admitted() {
    let plugin = strict_limiter(1024);
    for declared in ["512", "1024"] {
        let mut headers = sse_headers_with_length(Some(declared));
        // A backend response: the pristine snapshot carries the same length.
        let mut ctx = pass_through_route_ctx();
        ferrum_edge::_test_support::stamp_original_response_metadata_for_test(
            &mut ctx, 200, &headers,
        );
        assert!(
            matches!(
                plugin.after_proxy(&mut ctx, 200, &mut headers).await,
                PluginResult::Continue
            ),
            "a backend event stream declaring {declared} <= 1024 bytes proves its size"
        );
        // A synthetic response has no backend snapshot; its live map is the
        // representation.
        let mut ctx = pass_through_route_ctx();
        assert!(matches!(
            plugin.after_proxy(&mut ctx, 200, &mut headers).await,
            PluginResult::Continue
        ));
    }
}

/// Only an exact, in-limit, BACKEND-declared length proves anything: an absent
/// length, an ambiguous or over-limit one, and a length an earlier
/// `after_proxy` hook authored over an indefinite backend stream all keep the
/// pre-commit refusal.
#[tokio::test]
async fn strict_sse_without_a_provable_backend_length_is_still_refused() {
    let plugin = strict_limiter(1024);

    let mut absent = sse_headers_with_length(None);
    let mut ctx = pass_through_route_ctx();
    ferrum_edge::_test_support::stamp_original_response_metadata_for_test(&mut ctx, 200, &absent);
    assert_unverifiable_stream_refusal(
        plugin.after_proxy(&mut ctx, 200, &mut absent).await,
        "1024",
    );

    // The backend sent no length; a hook then wrote one into the live map.
    let mut ctx = pass_through_route_ctx();
    ferrum_edge::_test_support::stamp_original_response_metadata_for_test(&mut ctx, 200, &absent);
    let mut hook_authored = sse_headers_with_length(Some("10"));
    assert_unverifiable_stream_refusal(
        plugin.after_proxy(&mut ctx, 200, &mut hook_authored).await,
        "1024",
    );

    // The backend declared one length; a hook shrank it in the live map.
    let backend = sse_headers_with_length(Some("900"));
    let mut ctx = pass_through_route_ctx();
    ferrum_edge::_test_support::stamp_original_response_metadata_for_test(&mut ctx, 200, &backend);
    let mut shrunk = sse_headers_with_length(Some("10"));
    assert_unverifiable_stream_refusal(
        plugin.after_proxy(&mut ctx, 200, &mut shrunk).await,
        "1024",
    );

    // Ambiguous and over-limit declarations are refused by the fast path.
    for declared in ["512, 513", "2048"] {
        let mut headers = sse_headers_with_length(Some(declared));
        let mut ctx = pass_through_route_ctx();
        match plugin.after_proxy(&mut ctx, 200, &mut headers).await {
            PluginResult::Reject { status_code, .. } => assert_eq!(status_code, 502),
            other => panic!("{declared}: expected a fast-path refusal, got {other:?}"),
        }
    }
}

/// PR6880-SOL-1: a backend `Content-Length` proves only the BACKEND bytes. An
/// `sse` instance with `retry_ms` prepends `retry: 1000\n` to the stream after
/// headers commit, so a 1024-byte backend body becomes 1036 client bytes;
/// strict mode must refuse it before commit instead of cutting it mid-stream.
#[tokio::test]
async fn strict_sse_length_is_not_a_proof_when_a_stream_inspector_rewrites_it() {
    let plugin = strict_limiter(1024);
    let mut ctx = route_stamped_ctx(&[
        (
            "response_size_limiting",
            json!({"max_bytes": 1024, "require_buffered_check": true}),
        ),
        (
            "sse",
            json!({"retry_ms": 1000, "strip_content_length": false}),
        ),
    ]);
    assert_eq!(
        ctx.route_may_rewrite_response_stream,
        Some(true),
        "an sse retry prefix is a streaming response rewrite"
    );
    let mut headers = sse_headers_with_length(Some("1024"));
    ferrum_edge::_test_support::stamp_original_response_metadata_for_test(&mut ctx, 200, &headers);
    assert_unverifiable_stream_refusal(
        plugin.after_proxy(&mut ctx, 200, &mut headers).await,
        "1024",
    );

    // The same plugin without a stream rewrite leaves the proof intact.
    let mut ctx = route_stamped_ctx(&[
        (
            "response_size_limiting",
            json!({"max_bytes": 1024, "require_buffered_check": true}),
        ),
        ("sse", json!({"strip_content_length": false})),
    ]);
    assert_eq!(ctx.route_may_rewrite_response_stream, Some(false));
    ferrum_edge::_test_support::stamp_original_response_metadata_for_test(&mut ctx, 200, &headers);
    assert!(matches!(
        plugin.after_proxy(&mut ctx, 200, &mut headers).await,
        PluginResult::Continue
    ));
}

/// A context no handler stamped cannot prove that nothing rewrites the stream.
#[tokio::test]
async fn strict_sse_length_is_not_a_proof_on_an_unstamped_route() {
    let plugin = strict_limiter(1024);
    let mut ctx = make_ctx();
    assert_eq!(ctx.route_may_rewrite_response_stream, None);
    let mut headers = sse_headers_with_length(Some("512"));
    ferrum_edge::_test_support::stamp_original_response_metadata_for_test(&mut ctx, 200, &headers);
    assert_unverifiable_stream_refusal(
        plugin.after_proxy(&mut ctx, 200, &mut headers).await,
        "1024",
    );
}

/// PR6880-SOL-2: agreeing repeated `Content-Length` members are one exact
/// length to the canonical parser, so the pristine snapshot records it and the
/// proof holds; disagreeing members stay refused.
#[tokio::test]
async fn strict_sse_with_agreeing_repeated_content_length_is_admitted() {
    let plugin = strict_limiter(1024);
    let mut headers = sse_headers_with_length(Some("512, 512"));
    let mut ctx = pass_through_route_ctx();
    ferrum_edge::_test_support::stamp_original_response_metadata_for_test(&mut ctx, 200, &headers);
    assert_eq!(
        ctx.metadata
            .get("ferrum:original_response_content_length")
            .map(String::as_str),
        Some("512"),
        "the pristine snapshot must record the folded length"
    );
    assert!(matches!(
        plugin.after_proxy(&mut ctx, 200, &mut headers).await,
        PluginResult::Continue
    ));

    let mut disagreeing = sse_headers_with_length(Some("512, 513"));
    let mut ctx = pass_through_route_ctx();
    ferrum_edge::_test_support::stamp_original_response_metadata_for_test(
        &mut ctx,
        200,
        &disagreeing,
    );
    assert!(
        !ctx.metadata
            .contains_key("ferrum:original_response_content_length"),
        "disagreeing members are no length at all"
    );
    match plugin.after_proxy(&mut ctx, 200, &mut disagreeing).await {
        PluginResult::Reject { status_code, .. } => assert_eq!(status_code, 502),
        other => panic!("expected the ambiguous-length refusal, got {other:?}"),
    }
}

/// The strict instance declares the whole-body proof it cannot obtain from a
/// gateway-generated indefinite stream; a default instance does not.
#[test]
fn only_a_strict_instance_refuses_unprovable_gateway_streams() {
    let ctx = make_ctx();
    assert_eq!(
        strict_limiter(1024).refuses_unprovable_response_stream(&ctx),
        Some(1024)
    );
    let default = ResponseSizeLimiting::new(&json!({"max_bytes": 1024})).unwrap();
    assert_eq!(default.refuses_unprovable_response_stream(&ctx), None);
    // No body is transferred for HEAD, so there is nothing to prove.
    let head = make_ctx_with_method("HEAD");
    assert_eq!(
        strict_limiter(1024).refuses_unprovable_response_stream(&head),
        None
    );
}

// === Output-side ceiling: rewrites that expand the stream (SOL-1) ===

/// Releases every chunk twice: a stand-in for a streaming normalizer that wraps
/// each small provider delta in a larger envelope.
struct DoublingInspector;

#[async_trait::async_trait]
impl ferrum_edge::plugins::ResponseStreamInspector for DoublingInspector {
    async fn on_chunk(&mut self, chunk: &[u8]) -> ferrum_edge::plugins::ResponseStreamAction {
        let mut out = Vec::with_capacity(chunk.len() * 2);
        out.extend_from_slice(chunk);
        out.extend_from_slice(chunk);
        ferrum_edge::plugins::ResponseStreamAction::Forward(Bytes::from(out))
    }
}

/// Holds every chunk and releases it, doubled, from `on_end()`.
struct ExpandAtEnd(Vec<u8>);

#[async_trait::async_trait]
impl ferrum_edge::plugins::ResponseStreamInspector for ExpandAtEnd {
    async fn on_chunk(&mut self, chunk: &[u8]) -> ferrum_edge::plugins::ResponseStreamAction {
        self.0.extend_from_slice(chunk);
        ferrum_edge::plugins::ResponseStreamAction::Forward(Bytes::new())
    }

    async fn on_end(&mut self) -> ferrum_edge::plugins::ResponseStreamAction {
        let mut out = self.0.clone();
        out.extend_from_slice(&self.0);
        ferrum_edge::plugins::ResponseStreamAction::Forward(Bytes::from(out))
    }
}

/// Ends the stream on its first chunk with a terminal event larger than the
/// chunk itself.
struct TerminateWithLargeEvent;

#[async_trait::async_trait]
impl ferrum_edge::plugins::ResponseStreamInspector for TerminateWithLargeEvent {
    async fn on_chunk(&mut self, _chunk: &[u8]) -> ferrum_edge::plugins::ResponseStreamAction {
        ferrum_edge::plugins::ResponseStreamAction::Terminate(Some(Bytes::from_static(
            b"event: error\ndata: {\"error\":\"cut\"}\n\n",
        )))
    }
}

/// Drain a client-visible body: the DATA it delivered and its terminal error.
async fn drain_client_body<B>(mut body: B) -> (Vec<u8>, Option<String>)
where
    B: http_body::Body<Data = Bytes> + Unpin,
    B::Error: std::fmt::Display,
{
    use http_body_util::BodyExt;

    let mut delivered = Vec::new();
    while let Some(frame) = body.frame().await {
        match frame {
            Ok(frame) => {
                if let Ok(data) = frame.into_data() {
                    delivered.extend_from_slice(&data);
                }
            }
            Err(error) => return (delivered, Some(error.to_string())),
        }
    }
    (delivered, None)
}

fn assert_size_terminated(error: Option<String>) {
    let error = error.expect("the stream must end with the response-size body error");
    assert!(
        error.contains("response body exceeds maximum size"),
        "unexpected terminal error: {error}"
    );
}

/// The H1/H2 reqwest inspect path charges what the inspector RELEASES, not
/// only what the backend sent: an 8-byte backend body fits a 12-byte ceiling,
/// but its doubled representation does not.
#[tokio::test]
async fn reqwest_inspector_expansion_cannot_cross_the_response_ceiling() {
    use ferrum_edge::_test_support::reqwest_inspected_response_body_for_test;

    let chunks: &[&'static [u8]] = &[b"abcd", b"efgh"];
    let body = reqwest_inspected_response_body_for_test(chunks, Box::new(DoublingInspector), 12);
    let (delivered, error) = drain_client_body(body).await;
    assert_eq!(delivered, b"abcdabcd", "the crossing release is never sent");
    assert_size_terminated(error);

    // Exact boundary: 16 released bytes fit a 16-byte ceiling.
    let body = reqwest_inspected_response_body_for_test(chunks, Box::new(DoublingInspector), 16);
    let (delivered, error) = drain_client_body(body).await;
    assert_eq!(delivered, b"abcdabcdefghefgh");
    assert_eq!(error, None);

    // `0` is unlimited.
    let body = reqwest_inspected_response_body_for_test(chunks, Box::new(DoublingInspector), 0);
    let (delivered, error) = drain_client_body(body).await;
    assert_eq!(delivered.len(), 16);
    assert_eq!(error, None);
}

/// The `on_end()` flush and a `Terminate` payload are client-visible DATA too.
#[tokio::test]
async fn reqwest_inspector_terminal_releases_are_charged_against_the_ceiling() {
    use ferrum_edge::_test_support::reqwest_inspected_response_body_for_test;

    let chunks: &[&'static [u8]] = &[b"abcd", b"efgh"];
    let body =
        reqwest_inspected_response_body_for_test(chunks, Box::new(ExpandAtEnd(Vec::new())), 12);
    let (delivered, error) = drain_client_body(body).await;
    assert!(
        delivered.is_empty(),
        "the oversized end-of-stream flush is withheld"
    );
    assert_size_terminated(error);

    let body =
        reqwest_inspected_response_body_for_test(chunks, Box::new(TerminateWithLargeEvent), 12);
    let (delivered, error) = drain_client_body(body).await;
    assert!(
        delivered.is_empty(),
        "the oversized terminal event is withheld"
    );
    assert_size_terminated(error);
}

fn native_grpc_source(message: &'static [u8]) -> ferrum_edge::proxy::ProxyBody {
    use futures_util::stream;
    use http::{HeaderMap, HeaderValue};
    use http_body::Frame;
    use http_body_util::StreamBody;

    let mut trailers = HeaderMap::new();
    trailers.insert("grpc-status", HeaderValue::from_static("0"));
    let source = StreamBody::new(stream::iter(vec![
        Ok::<_, ferrum_edge::proxy::body::ProxyBodyError>(Frame::data(Bytes::from_static(message))),
        Ok(Frame::trailers(trailers)),
    ]));
    ferrum_edge::_test_support::proxy_body_streaming_for_test(Box::pin(source))
}

/// gRPC-Web translation is charged on the representation the client receives:
/// base64 text expansion of an in-limit message, and the generated trailer
/// frame after an in-limit binary body, both end the stream at the ceiling.
#[tokio::test]
async fn grpc_web_translation_cannot_expand_past_the_response_ceiling() {
    use ferrum_edge::_test_support::proxy_body_into_grpc_web_streaming_with_response_limit_for_test as translate;

    // 30 source bytes fit a 30-byte ceiling; their 40-byte base64 text does not.
    // A 5-byte gRPC frame header plus a 25-byte message: 30 bytes.
    const MESSAGE: &[u8] = b"\x00\x00\x00\x00\x19abcdefghijklmnopqrstuvwxy";
    let body = translate(
        native_grpc_source(MESSAGE),
        "application/grpc-web-text",
        200,
        None,
        30,
    );
    let (delivered, error) = drain_client_body(body).await;
    assert!(delivered.is_empty(), "the expanded text frame is withheld");
    assert_size_terminated(error);

    // Binary mode: measure the complete translation, then show the exact total
    // is accepted and one byte less refuses the generated trailer frame.
    let unlimited = translate(
        native_grpc_source(MESSAGE),
        "application/grpc-web+proto",
        200,
        None,
        0,
    );
    let (complete, error) = drain_client_body(unlimited).await;
    assert_eq!(error, None);
    assert!(
        complete.len() > MESSAGE.len(),
        "binary mode appends a trailer frame"
    );

    let exact = translate(
        native_grpc_source(MESSAGE),
        "application/grpc-web+proto",
        200,
        None,
        complete.len(),
    );
    let (delivered, error) = drain_client_body(exact).await;
    assert_eq!(error, None);
    assert_eq!(delivered, complete);

    let short = translate(
        native_grpc_source(MESSAGE),
        "application/grpc-web+proto",
        200,
        None,
        complete.len() - 1,
    );
    let (delivered, error) = drain_client_body(short).await;
    assert_eq!(
        delivered, MESSAGE,
        "the in-limit message is delivered unchanged"
    );
    assert_size_terminated(error);
}

/// Every production response-inspector driver charges each release — every
/// `Forward`, every `Terminate` payload, on chunk and at end of stream —
/// against the output ceiling BEFORE writing it: the reqwest and proxy-body
/// drivers, the native H3 → native H3 relay, and the H3 cross-protocol relay
/// (PR6880-SOL-3). The H3 relays write straight to QUIC streams with no live
/// harness here, so the invariant is pinned per release site: between each
/// `ResponseStreamAction` arm and its first write, the file's charge must run.
/// A new driver or a new arm without the charge fails this table.
#[test]
fn every_inspector_release_is_charged_before_it_is_written() {
    let drivers: [(&str, &str, &str, &str); 3] = [
        (
            "src/proxy/body.rs",
            include_str!("../../../src/proxy/body.rs"),
            "response_output_crosses_ceiling(",
            "tx.send(Ok(Frame::data(",
        ),
        (
            "src/http3/server.rs",
            include_str!("../../../src/http3/server.rs"),
            "inspected_output_exceeds_ceiling!(",
            "send_data(",
        ),
        (
            "src/http3/cross_protocol.rs",
            include_str!("../../../src/http3/cross_protocol.rs"),
            "inspected_emitted_response_limit_exceeded(",
            "send_data(",
        ),
    ];
    for (path, source, charge, write) in drivers {
        let mut releases = 0;
        for arm in [
            "ResponseStreamAction::Forward(",
            "ResponseStreamAction::Terminate(",
        ] {
            for (start, _) in source.match_indices(arm) {
                let line = source[..start].matches('\n').count() + 1;
                let release = &source[start..];
                let end = release
                    .find(write)
                    .unwrap_or_else(|| panic!("{path}:{line}: release arm with no write"));
                assert!(
                    release[..end].contains(charge),
                    "{path}:{line}: inspector release is written without the output-ceiling charge"
                );
                releases += 1;
            }
        }
        assert!(
            releases >= 4,
            "{path}: inspector release arms moved ({releases})"
        );
    }
    // The cross-protocol helper is the shared boundary, not a second copy.
    let cross = include_str!("../../../src/http3/cross_protocol.rs");
    let helper = cross
        .split("fn inspected_emitted_response_limit_exceeded(")
        .nth(1)
        .expect("cross-protocol emitted-limit helper")
        .split("\n}\n")
        .next()
        .expect("helper body");
    assert!(helper.contains("crate::proxy::body::response_output_crosses_ceiling("));
}

/// The native-H3 cross-protocol gRPC-Web relay writes straight to the QUIC
/// stream, so its output-side ceiling is pinned structurally: every translated
/// write and the generated terminal frame go through the shared boundary.
#[test]
fn h3_cross_protocol_grpc_web_relay_charges_translated_output() {
    let source = include_str!("../../../src/http3/cross_protocol.rs");
    let relay = source
        .split("async fn stream_hyper_incoming<S>(")
        .nth(1)
        .expect("H3 cross-protocol gRPC relay")
        .split("fn should_finish_h3_stream_without_trailers(")
        .next()
        .expect("bounded relay body");
    let encodes = relay.matches("encode_streaming_data(").count();
    let charges = relay
        .matches("if output_exceeds_ceiling!(out.len())")
        .count();
    assert!(encodes >= 4, "relay encode sites moved: {encodes}");
    assert_eq!(
        charges, encodes,
        "every translated relay write must be charged against the response ceiling"
    );
    let terminal = source
        .split("async fn handle_h3_grpc_streaming_response<S>(")
        .nth(1)
        .expect("H3 gRPC streaming response")
        .split("build_streaming_trailer_data(")
        .nth(1)
        .expect("translated terminal frame")
        .split("stream.send_data(terminal_data)")
        .next()
        .expect("terminal write");
    assert!(
        terminal.contains("response_output_crosses_ceiling("),
        "the generated gRPC-Web terminal frame must be charged before it is written"
    );
}
