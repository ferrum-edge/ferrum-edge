use ferrum_edge::plugins::{PluginResult, create_plugin};
use serde_json::json;
use std::collections::HashMap;

use super::plugin_utils::{assert_continue, assert_reject, create_test_context};

fn create_grpc_context_with_timeout(timeout: Option<&str>) -> ferrum_edge::plugins::RequestContext {
    let mut ctx = create_test_context();
    ctx.method = "POST".to_string();
    ctx.path = "/my.Service/MyMethod".to_string();
    ctx.headers
        .insert("content-type".to_string(), "application/grpc".to_string());
    if let Some(t) = timeout {
        ctx.headers
            .insert("grpc-timeout".to_string(), t.to_string());
    }
    ctx
}

// ── Plugin creation ──

#[test]
fn test_plugin_creation() {
    let config = json!({
        "max_deadline_ms": 30000
    });
    let plugin = create_plugin("grpc_deadline", &config).unwrap().unwrap();
    assert_eq!(plugin.name(), "grpc_deadline");
    assert_eq!(plugin.priority(), 3050);
}

#[test]
fn test_in_available_plugins() {
    let plugins = ferrum_edge::plugins::available_plugins();
    assert!(plugins.contains(&"grpc_deadline"));
}

#[test]
fn test_supported_protocols() {
    let config = json!({});
    let plugin = create_plugin("grpc_deadline", &config).unwrap().unwrap();
    let protocols = plugin.supported_protocols();
    assert_eq!(protocols.len(), 1);
    assert_eq!(protocols[0], ferrum_edge::plugins::ProxyProtocol::Grpc);
}

#[test]
fn test_modifies_request_headers() {
    let config = json!({});
    let plugin = create_plugin("grpc_deadline", &config).unwrap().unwrap();
    assert!(plugin.modifies_request_headers());
}

// ── grpc-timeout parsing ──

#[tokio::test]
async fn test_parse_hours() {
    let config = json!({ "max_deadline_ms": 999999999 });
    let plugin = create_plugin("grpc_deadline", &config).unwrap().unwrap();

    let mut ctx = create_grpc_context_with_timeout(Some("2H"));
    let mut headers = HashMap::new();
    headers.insert("grpc-timeout".to_string(), "2H".to_string());
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);

    // 2 hours = 7,200,000 ms
    assert_eq!(
        ctx.metadata.get("grpc_original_deadline_ms").unwrap(),
        "7200000"
    );
    assert_eq!(headers.get("grpc-timeout").unwrap(), "7200000m");
}

#[tokio::test]
async fn test_parse_minutes() {
    let config = json!({ "max_deadline_ms": 999999999 });
    let plugin = create_plugin("grpc_deadline", &config).unwrap().unwrap();

    let mut ctx = create_grpc_context_with_timeout(Some("5M"));
    let mut headers = HashMap::new();
    headers.insert("grpc-timeout".to_string(), "5M".to_string());
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);

    assert_eq!(
        ctx.metadata.get("grpc_original_deadline_ms").unwrap(),
        "300000"
    );
}

#[tokio::test]
async fn test_parse_seconds() {
    let config = json!({ "max_deadline_ms": 999999999 });
    let plugin = create_plugin("grpc_deadline", &config).unwrap().unwrap();

    let mut ctx = create_grpc_context_with_timeout(Some("30S"));
    let mut headers = HashMap::new();
    headers.insert("grpc-timeout".to_string(), "30S".to_string());
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);

    assert_eq!(
        ctx.metadata.get("grpc_original_deadline_ms").unwrap(),
        "30000"
    );
}

#[tokio::test]
async fn test_parse_milliseconds() {
    let config = json!({ "max_deadline_ms": 999999999 });
    let plugin = create_plugin("grpc_deadline", &config).unwrap().unwrap();

    let mut ctx = create_grpc_context_with_timeout(Some("5000m"));
    let mut headers = HashMap::new();
    headers.insert("grpc-timeout".to_string(), "5000m".to_string());
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);

    assert_eq!(
        ctx.metadata.get("grpc_original_deadline_ms").unwrap(),
        "5000"
    );
    assert_eq!(headers.get("grpc-timeout").unwrap(), "5000m");
}

#[tokio::test]
async fn test_parse_microseconds() {
    let config = json!({ "max_deadline_ms": 999999999 });
    let plugin = create_plugin("grpc_deadline", &config).unwrap().unwrap();

    let mut ctx = create_grpc_context_with_timeout(Some("5000000u"));
    let mut headers = HashMap::new();
    headers.insert("grpc-timeout".to_string(), "5000000u".to_string());
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);

    // 5,000,000 us = 5,000 ms
    assert_eq!(
        ctx.metadata.get("grpc_original_deadline_ms").unwrap(),
        "5000"
    );
}

#[tokio::test]
async fn test_parse_nanoseconds() {
    let config = json!({ "max_deadline_ms": 999999999 });
    let plugin = create_plugin("grpc_deadline", &config).unwrap().unwrap();

    let mut ctx = create_grpc_context_with_timeout(Some("1000000000n"));
    let mut headers = HashMap::new();
    headers.insert("grpc-timeout".to_string(), "1000000000n".to_string());
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);

    // 1,000,000,000 ns = 1,000 ms
    assert_eq!(
        ctx.metadata.get("grpc_original_deadline_ms").unwrap(),
        "1000"
    );
}

// ── Default deadline injection ──

#[tokio::test]
async fn test_default_deadline_injected_when_missing() {
    let config = json!({ "default_deadline_ms": 5000 });
    let plugin = create_plugin("grpc_deadline", &config).unwrap().unwrap();

    let mut ctx = create_grpc_context_with_timeout(None);
    let mut headers = HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);

    assert_eq!(headers.get("grpc-timeout").unwrap(), "5000m");
    assert_eq!(
        ctx.metadata.get("grpc_adjusted_deadline_ms").unwrap(),
        "5000"
    );
}

#[tokio::test]
async fn test_default_deadline_not_used_when_present() {
    let config = json!({
        "default_deadline_ms": 5000,
        "max_deadline_ms": 999999999
    });
    let plugin = create_plugin("grpc_deadline", &config).unwrap().unwrap();

    let mut ctx = create_grpc_context_with_timeout(Some("10000m"));
    let mut headers = HashMap::new();
    headers.insert("grpc-timeout".to_string(), "10000m".to_string());
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);

    // Should use the client's timeout, not the default
    assert_eq!(
        ctx.metadata.get("grpc_adjusted_deadline_ms").unwrap(),
        "10000"
    );
}

// ── Max deadline capping ──

#[tokio::test]
async fn test_max_deadline_caps_high_timeout() {
    let config = json!({ "max_deadline_ms": 30000 });
    let plugin = create_plugin("grpc_deadline", &config).unwrap().unwrap();

    let mut ctx = create_grpc_context_with_timeout(Some("60S")); // 60,000 ms
    let mut headers = HashMap::new();
    headers.insert("grpc-timeout".to_string(), "60S".to_string());
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);

    // Should be capped to 30,000 ms
    assert_eq!(
        ctx.metadata.get("grpc_adjusted_deadline_ms").unwrap(),
        "30000"
    );
    assert_eq!(headers.get("grpc-timeout").unwrap(), "30000m");
}

#[tokio::test]
async fn test_max_deadline_does_not_increase_low_timeout() {
    let config = json!({ "max_deadline_ms": 30000 });
    let plugin = create_plugin("grpc_deadline", &config).unwrap().unwrap();

    let mut ctx = create_grpc_context_with_timeout(Some("5000m")); // 5,000 ms
    let mut headers = HashMap::new();
    headers.insert("grpc-timeout".to_string(), "5000m".to_string());
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);

    // Should stay at 5,000 ms (under the cap)
    assert_eq!(
        ctx.metadata.get("grpc_adjusted_deadline_ms").unwrap(),
        "5000"
    );
}

// ── reject_no_deadline ──

#[tokio::test]
async fn test_reject_no_deadline_rejects_missing() {
    let config = json!({ "reject_no_deadline": true });
    let plugin = create_plugin("grpc_deadline", &config).unwrap().unwrap();

    let mut ctx = create_grpc_context_with_timeout(None);
    let mut headers = HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_reject(result, Some(400));
}

#[tokio::test]
async fn test_reject_no_deadline_allows_present() {
    let config = json!({
        "reject_no_deadline": true,
        "max_deadline_ms": 999999999
    });
    let plugin = create_plugin("grpc_deadline", &config).unwrap().unwrap();

    let mut ctx = create_grpc_context_with_timeout(Some("5000m"));
    let mut headers = HashMap::new();
    headers.insert("grpc-timeout".to_string(), "5000m".to_string());
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);
}

// ── subtract_gateway_processing ──

#[tokio::test]
async fn test_subtract_gateway_processing() {
    let config = json!({
        "default_deadline_ms": 60000,
        "subtract_gateway_processing": true
    });
    let plugin = create_plugin("grpc_deadline", &config).unwrap().unwrap();

    let mut ctx = create_grpc_context_with_timeout(None);
    let mut headers = HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);

    // The adjusted deadline should be <= default_deadline_ms (some processing time subtracted)
    let adjusted: u64 = ctx
        .metadata
        .get("grpc_adjusted_deadline_ms")
        .unwrap()
        .parse()
        .unwrap();
    assert!(adjusted <= 60000);
    assert!(adjusted > 0);
}

#[tokio::test]
async fn test_subtract_gateway_processing_deadline_exceeded() {
    let config = json!({
        "default_deadline_ms": 0,
        "subtract_gateway_processing": true
    });
    let plugin = create_plugin("grpc_deadline", &config).unwrap().unwrap();

    let mut ctx = create_grpc_context_with_timeout(None);
    let mut headers = HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;

    // Deadline of 0ms should be exceeded immediately
    match result {
        PluginResult::Reject {
            status_code,
            headers,
            ..
        } => {
            assert_eq!(status_code, 200); // gRPC trailers-only response
            assert_eq!(headers.get("grpc-status").unwrap(), "4"); // DEADLINE_EXCEEDED
            assert!(headers.contains_key("grpc-message"));
        }
        _ => panic!("Expected Reject with DEADLINE_EXCEEDED"),
    }
}

// ── Combined config ──

#[tokio::test]
async fn test_combined_default_and_max() {
    let config = json!({
        "default_deadline_ms": 60000,
        "max_deadline_ms": 30000
    });
    let plugin = create_plugin("grpc_deadline", &config).unwrap().unwrap();

    // No timeout provided: default (60000) gets capped to max (30000)
    let mut ctx = create_grpc_context_with_timeout(None);
    let mut headers = HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);

    assert_eq!(
        ctx.metadata.get("grpc_adjusted_deadline_ms").unwrap(),
        "30000"
    );
}

// ── Empty config passes through ──

#[tokio::test]
async fn test_empty_config_passes_through() {
    let config = json!({});
    let plugin = create_plugin("grpc_deadline", &config).unwrap().unwrap();

    let mut ctx = create_grpc_context_with_timeout(Some("5000m"));
    let mut headers = HashMap::new();
    headers.insert("grpc-timeout".to_string(), "5000m".to_string());
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);

    // Should still set the header (pass through the parsed value)
    assert_eq!(headers.get("grpc-timeout").unwrap(), "5000m");
}

#[tokio::test]
async fn test_modified_timeout_header_takes_precedence_over_original_request() {
    let config = json!({ "max_deadline_ms": 999999999 });
    let plugin = create_plugin("grpc_deadline", &config).unwrap().unwrap();

    let mut ctx = create_grpc_context_with_timeout(Some("60S"));
    let mut headers = HashMap::new();
    headers.insert("grpc-timeout".to_string(), "60S".to_string());
    headers.insert("grpc-timeout".to_string(), "5000m".to_string());
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);

    assert_eq!(
        ctx.metadata.get("grpc_original_deadline_ms").unwrap(),
        "5000"
    );
    assert_eq!(headers.get("grpc-timeout").unwrap(), "5000m");
}

#[tokio::test]
async fn test_empty_config_no_timeout_passes() {
    let config = json!({});
    let plugin = create_plugin("grpc_deadline", &config).unwrap().unwrap();

    let mut ctx = create_grpc_context_with_timeout(None);
    let mut headers = HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);

    // No timeout to set
    assert!(!headers.contains_key("grpc-timeout"));
}

// ── Invalid timeout header ──

#[tokio::test]
async fn test_invalid_timeout_treated_as_missing() {
    let config = json!({ "default_deadline_ms": 5000 });
    let plugin = create_plugin("grpc_deadline", &config).unwrap().unwrap();

    let mut ctx = create_grpc_context_with_timeout(Some("invalid"));
    let mut headers = HashMap::new();
    headers.insert("grpc-timeout".to_string(), "invalid".to_string());
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);

    // Should fall back to default
    assert_eq!(
        ctx.metadata.get("grpc_adjusted_deadline_ms").unwrap(),
        "5000"
    );
}

// ── Rejection body format ──

#[tokio::test]
async fn test_reject_no_deadline_body_format() {
    let config = json!({ "reject_no_deadline": true });
    let plugin = create_plugin("grpc_deadline", &config).unwrap().unwrap();

    let mut ctx = create_grpc_context_with_timeout(None);
    let mut headers = HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;

    match result {
        PluginResult::Reject {
            status_code,
            body,
            headers,
        } => {
            assert_eq!(status_code, 400);
            let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
            assert!(parsed.get("error").is_some());
            assert_eq!(headers.get("content-type").unwrap(), "application/grpc");
        }
        _ => panic!("Expected Reject"),
    }
}

// ── reject_no_deadline takes precedence over default_deadline_ms ──

#[tokio::test]
async fn test_reject_no_deadline_wins_over_default() {
    let config = json!({
        "reject_no_deadline": true,
        "default_deadline_ms": 5000
    });
    let plugin = create_plugin("grpc_deadline", &config).unwrap().unwrap();

    let mut ctx = create_grpc_context_with_timeout(None);
    let mut headers = HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;

    // Should reject despite default being configured — reject_no_deadline takes precedence
    assert_reject(result, Some(400));
}

// ── Empty string timeout ──

#[tokio::test]
async fn test_empty_string_timeout_treated_as_missing() {
    let config = json!({ "default_deadline_ms": 3000 });
    let plugin = create_plugin("grpc_deadline", &config).unwrap().unwrap();

    let mut ctx = create_grpc_context_with_timeout(Some(""));
    let mut headers = HashMap::new();
    headers.insert("grpc-timeout".to_string(), "".to_string());
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);

    // Empty string can't be parsed, falls back to default
    assert_eq!(
        ctx.metadata.get("grpc_adjusted_deadline_ms").unwrap(),
        "3000"
    );
}

// ── Very large timeout values (overflow protection) ──

#[tokio::test]
async fn test_very_large_hour_timeout_saturates() {
    let config = json!({ "max_deadline_ms": 999999999 });
    let plugin = create_plugin("grpc_deadline", &config).unwrap().unwrap();

    // u64::MAX / 3600 would overflow without saturating_mul
    let mut ctx = create_grpc_context_with_timeout(Some("999999999H"));
    let mut headers = HashMap::new();
    headers.insert("grpc-timeout".to_string(), "999999999H".to_string());
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);

    // Should not panic — saturating_mul prevents overflow
    assert!(ctx.metadata.contains_key("grpc_original_deadline_ms"));
    assert_eq!(headers.get("grpc-timeout").unwrap(), "1000000S");
}

// ── subtract_gateway_processing + max_deadline_ms combined ──

#[tokio::test]
async fn test_subtract_after_max_cap() {
    let config = json!({
        "max_deadline_ms": 5000,
        "subtract_gateway_processing": true
    });
    let plugin = create_plugin("grpc_deadline", &config).unwrap().unwrap();

    // Client sends 60s, capped to 5s, then processing time subtracted
    let mut ctx = create_grpc_context_with_timeout(Some("60S"));
    let mut headers = HashMap::new();
    headers.insert("grpc-timeout".to_string(), "60S".to_string());
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);

    let adjusted: u64 = ctx
        .metadata
        .get("grpc_adjusted_deadline_ms")
        .unwrap()
        .parse()
        .unwrap();
    // Should be capped to 5000 then subtracted — must be <= 5000
    assert!(adjusted <= 5000);
    assert!(adjusted > 0);
}

// ── Single-character unit only (no multi-char units) ──

#[tokio::test]
async fn test_multi_char_unit_rejected() {
    let config = json!({ "default_deadline_ms": 1000 });
    let plugin = create_plugin("grpc_deadline", &config).unwrap().unwrap();

    // "ms" is not a valid gRPC timeout unit — only single-char units
    let mut ctx = create_grpc_context_with_timeout(Some("5000ms"));
    let mut headers = HashMap::new();
    headers.insert("grpc-timeout".to_string(), "5000ms".to_string());
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);

    // "5000ms" fails to parse (last char 's', digits "5000m" fails u64 parse)
    // Falls back to default
    assert_eq!(
        ctx.metadata.get("grpc_adjusted_deadline_ms").unwrap(),
        "1000"
    );
}

// ── Metadata tracking ──

#[tokio::test]
async fn test_original_and_adjusted_metadata() {
    let config = json!({ "max_deadline_ms": 10000 });
    let plugin = create_plugin("grpc_deadline", &config).unwrap().unwrap();

    let mut ctx = create_grpc_context_with_timeout(Some("30S")); // 30,000 ms
    let mut headers = HashMap::new();
    headers.insert("grpc-timeout".to_string(), "30S".to_string());
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);

    assert_eq!(
        ctx.metadata.get("grpc_original_deadline_ms").unwrap(),
        "30000"
    );
    assert_eq!(
        ctx.metadata.get("grpc_adjusted_deadline_ms").unwrap(),
        "10000"
    );
}
