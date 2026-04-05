//! Tests for the Bot Detection plugin

use ferrum_edge::plugins::bot_detection::{BOT_DETECTION_PRIORITY, BotDetection};
use ferrum_edge::plugins::{Plugin, PluginResult, RequestContext};
use serde_json::json;

use super::plugin_utils;

fn make_ctx_with_ua(user_agent: &str) -> RequestContext {
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/test".to_string(),
    );
    ctx.headers
        .insert("user-agent".to_string(), user_agent.to_string());
    ctx
}

fn make_ctx_without_ua() -> RequestContext {
    RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/test".to_string(),
    )
}

// ── Plugin metadata ─────────────────────────────────────────────────────

#[test]
fn test_plugin_name() {
    let plugin = BotDetection::new(&json!({})).unwrap();
    assert_eq!(plugin.name(), "bot_detection");
}

#[test]
fn test_plugin_priority() {
    let plugin = BotDetection::new(&json!({})).unwrap();
    assert_eq!(plugin.priority(), BOT_DETECTION_PRIORITY);
    assert_eq!(plugin.priority(), 200);
}

// ── Normal browser user-agents pass ─────────────────────────────────────

#[tokio::test]
async fn test_normal_browser_chrome_passes() {
    let plugin = BotDetection::new(&json!({})).unwrap();
    let mut ctx = make_ctx_with_ua(
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    );
    let result = plugin.on_request_received(&mut ctx).await;
    plugin_utils::assert_continue(result);
}

#[tokio::test]
async fn test_normal_browser_firefox_passes() {
    let plugin = BotDetection::new(&json!({})).unwrap();
    let mut ctx =
        make_ctx_with_ua("Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0");
    let result = plugin.on_request_received(&mut ctx).await;
    plugin_utils::assert_continue(result);
}

#[tokio::test]
async fn test_normal_browser_safari_passes() {
    let plugin = BotDetection::new(&json!({})).unwrap();
    let mut ctx = make_ctx_with_ua(
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    );
    let result = plugin.on_request_received(&mut ctx).await;
    plugin_utils::assert_continue(result);
}

// ── Default blocked patterns ────────────────────────────────────────────

#[tokio::test]
async fn test_default_blocks_curl() {
    let plugin = BotDetection::new(&json!({})).unwrap();
    let mut ctx = make_ctx_with_ua("curl/7.88.1");
    let result = plugin.on_request_received(&mut ctx).await;
    plugin_utils::assert_reject(result, Some(403));
}

#[tokio::test]
async fn test_default_blocks_wget() {
    let plugin = BotDetection::new(&json!({})).unwrap();
    let mut ctx = make_ctx_with_ua("Wget/1.21");
    let result = plugin.on_request_received(&mut ctx).await;
    plugin_utils::assert_reject(result, Some(403));
}

#[tokio::test]
async fn test_default_blocks_python_requests() {
    let plugin = BotDetection::new(&json!({})).unwrap();
    let mut ctx = make_ctx_with_ua("python-requests/2.31.0");
    let result = plugin.on_request_received(&mut ctx).await;
    plugin_utils::assert_reject(result, Some(403));
}

#[tokio::test]
async fn test_default_blocks_python_urllib() {
    let plugin = BotDetection::new(&json!({})).unwrap();
    let mut ctx = make_ctx_with_ua("Python-urllib/3.11");
    let result = plugin.on_request_received(&mut ctx).await;
    plugin_utils::assert_reject(result, Some(403));
}

#[tokio::test]
async fn test_default_blocks_scrapy() {
    let plugin = BotDetection::new(&json!({})).unwrap();
    let mut ctx = make_ctx_with_ua("Scrapy/2.11.0");
    let result = plugin.on_request_received(&mut ctx).await;
    plugin_utils::assert_reject(result, Some(403));
}

#[tokio::test]
async fn test_default_blocks_httpclient() {
    let plugin = BotDetection::new(&json!({})).unwrap();
    let mut ctx = make_ctx_with_ua("HTTPClient/1.0");
    let result = plugin.on_request_received(&mut ctx).await;
    plugin_utils::assert_reject(result, Some(403));
}

#[tokio::test]
async fn test_default_blocks_java() {
    let plugin = BotDetection::new(&json!({})).unwrap();
    let mut ctx = make_ctx_with_ua("Java/17.0.1");
    let result = plugin.on_request_received(&mut ctx).await;
    plugin_utils::assert_reject(result, Some(403));
}

#[tokio::test]
async fn test_default_blocks_libwww_perl() {
    let plugin = BotDetection::new(&json!({})).unwrap();
    let mut ctx = make_ctx_with_ua("libwww-perl/6.72");
    let result = plugin.on_request_received(&mut ctx).await;
    plugin_utils::assert_reject(result, Some(403));
}

#[tokio::test]
async fn test_default_blocks_mechanize() {
    let plugin = BotDetection::new(&json!({})).unwrap();
    let mut ctx = make_ctx_with_ua("mechanize/0.4.9");
    let result = plugin.on_request_received(&mut ctx).await;
    plugin_utils::assert_reject(result, Some(403));
}

#[tokio::test]
async fn test_default_blocks_php() {
    let plugin = BotDetection::new(&json!({})).unwrap();
    let mut ctx = make_ctx_with_ua("PHP/8.2.0");
    let result = plugin.on_request_received(&mut ctx).await;
    plugin_utils::assert_reject(result, Some(403));
}

// ── Custom blocked patterns override defaults ───────────────────────────

#[tokio::test]
async fn test_custom_patterns_replace_defaults() {
    let plugin = BotDetection::new(&json!({
        "blocked_patterns": ["mybot", "badcrawler"]
    }))
    .unwrap();

    // Default pattern "curl" should no longer be blocked
    let mut ctx = make_ctx_with_ua("curl/7.88.1");
    let result = plugin.on_request_received(&mut ctx).await;
    plugin_utils::assert_continue(result);

    // Custom pattern should be blocked
    let mut ctx = make_ctx_with_ua("MyBot/1.0");
    let result = plugin.on_request_received(&mut ctx).await;
    plugin_utils::assert_reject(result, Some(403));

    let mut ctx = make_ctx_with_ua("BadCrawler/2.0");
    let result = plugin.on_request_received(&mut ctx).await;
    plugin_utils::assert_reject(result, Some(403));
}

#[tokio::test]
async fn test_empty_custom_patterns_blocks_nothing() {
    let plugin = BotDetection::new(&json!({
        "blocked_patterns": []
    }))
    .unwrap();

    let mut ctx = make_ctx_with_ua("curl/7.88.1");
    let result = plugin.on_request_received(&mut ctx).await;
    plugin_utils::assert_continue(result);
}

// ── Allow-list overrides blocked patterns ───────────────────────────────

#[tokio::test]
async fn test_allow_list_permits_otherwise_blocked_agent() {
    let plugin = BotDetection::new(&json!({
        "allow_list": ["curl"]
    }))
    .unwrap();

    let mut ctx = make_ctx_with_ua("curl/7.88.1");
    let result = plugin.on_request_received(&mut ctx).await;
    plugin_utils::assert_continue(result);
}

#[tokio::test]
async fn test_allow_list_does_not_affect_other_blocked() {
    let plugin = BotDetection::new(&json!({
        "allow_list": ["curl"]
    }))
    .unwrap();

    // wget is still blocked
    let mut ctx = make_ctx_with_ua("Wget/1.21");
    let result = plugin.on_request_received(&mut ctx).await;
    plugin_utils::assert_reject(result, Some(403));
}

#[tokio::test]
async fn test_allow_list_with_custom_patterns() {
    let plugin = BotDetection::new(&json!({
        "blocked_patterns": ["bot"],
        "allow_list": ["googlebot"]
    }))
    .unwrap();

    // googlebot matches allow list first, so it passes
    let mut ctx = make_ctx_with_ua("Googlebot/2.1");
    let result = plugin.on_request_received(&mut ctx).await;
    plugin_utils::assert_continue(result);

    // generic bot is still blocked
    let mut ctx = make_ctx_with_ua("EvilBot/1.0");
    let result = plugin.on_request_received(&mut ctx).await;
    plugin_utils::assert_reject(result, Some(403));
}

// ── Missing user-agent header ───────────────────────────────────────────
// Default behavior: allow missing User-Agent (for health checks / LB probes)

#[tokio::test]
async fn test_missing_user_agent_allowed_by_default() {
    // Default: allow_missing_user_agent = true (health checks, load balancers, internal services)
    let plugin = BotDetection::new(&json!({})).unwrap();
    let mut ctx = make_ctx_without_ua();
    let result = plugin.on_request_received(&mut ctx).await;
    plugin_utils::assert_continue(result);
}

#[tokio::test]
async fn test_missing_user_agent_rejected_when_configured() {
    let plugin = BotDetection::new(&json!({
        "allow_missing_user_agent": false
    }))
    .unwrap();
    let mut ctx = make_ctx_without_ua();
    let result = plugin.on_request_received(&mut ctx).await;
    plugin_utils::assert_reject(result, Some(403));
}

#[tokio::test]
async fn test_missing_user_agent_uses_custom_response_code() {
    let plugin = BotDetection::new(&json!({
        "allow_missing_user_agent": false,
        "custom_response_code": 429
    }))
    .unwrap();
    let mut ctx = make_ctx_without_ua();
    let result = plugin.on_request_received(&mut ctx).await;
    plugin_utils::assert_reject(result, Some(429));
}

#[tokio::test]
async fn test_missing_user_agent_returns_forbidden_body() {
    let plugin = BotDetection::new(&json!({
        "allow_missing_user_agent": false
    }))
    .unwrap();
    let mut ctx = make_ctx_without_ua();
    let result = plugin.on_request_received(&mut ctx).await;
    match result {
        PluginResult::Reject { body, .. } => {
            assert_eq!(body, r#"{"error":"Forbidden"}"#);
        }
        _ => panic!("Expected Reject, got {:?}", result),
    }
}

// ── Custom response code configuration ──────────────────────────────────

#[tokio::test]
async fn test_custom_response_code_on_blocked_agent() {
    let plugin = BotDetection::new(&json!({
        "custom_response_code": 429
    }))
    .unwrap();
    let mut ctx = make_ctx_with_ua("curl/7.88.1");
    let result = plugin.on_request_received(&mut ctx).await;
    plugin_utils::assert_reject(result, Some(429));
}

#[tokio::test]
async fn test_custom_response_code_404() {
    let plugin = BotDetection::new(&json!({
        "custom_response_code": 404
    }))
    .unwrap();
    let mut ctx = make_ctx_with_ua("wget/1.21");
    let result = plugin.on_request_received(&mut ctx).await;
    plugin_utils::assert_reject(result, Some(404));
}

#[tokio::test]
async fn test_custom_response_code_boundary_100() {
    let plugin = BotDetection::new(&json!({
        "custom_response_code": 100
    }))
    .unwrap();
    let mut ctx = make_ctx_with_ua("curl/7.88.1");
    let result = plugin.on_request_received(&mut ctx).await;
    plugin_utils::assert_reject(result, Some(100));
}

#[tokio::test]
async fn test_custom_response_code_boundary_599() {
    let plugin = BotDetection::new(&json!({
        "custom_response_code": 599
    }))
    .unwrap();
    let mut ctx = make_ctx_with_ua("curl/7.88.1");
    let result = plugin.on_request_received(&mut ctx).await;
    plugin_utils::assert_reject(result, Some(599));
}

// ── Invalid custom response code gets clamped to 403 ────────────────────

#[tokio::test]
async fn test_invalid_response_code_below_range_defaults_to_403() {
    let plugin = BotDetection::new(&json!({
        "custom_response_code": 99
    }))
    .unwrap();
    let mut ctx = make_ctx_with_ua("curl/7.88.1");
    let result = plugin.on_request_received(&mut ctx).await;
    plugin_utils::assert_reject(result, Some(403));
}

#[tokio::test]
async fn test_invalid_response_code_above_range_defaults_to_403() {
    let plugin = BotDetection::new(&json!({
        "custom_response_code": 600
    }))
    .unwrap();
    let mut ctx = make_ctx_with_ua("curl/7.88.1");
    let result = plugin.on_request_received(&mut ctx).await;
    plugin_utils::assert_reject(result, Some(403));
}

#[tokio::test]
async fn test_invalid_response_code_zero_defaults_to_403() {
    let plugin = BotDetection::new(&json!({
        "custom_response_code": 0
    }))
    .unwrap();
    let mut ctx = make_ctx_with_ua("curl/7.88.1");
    let result = plugin.on_request_received(&mut ctx).await;
    plugin_utils::assert_reject(result, Some(403));
}

#[tokio::test]
async fn test_invalid_response_code_string_defaults_to_403() {
    let plugin = BotDetection::new(&json!({
        "custom_response_code": "not_a_number"
    }))
    .unwrap();
    let mut ctx = make_ctx_with_ua("curl/7.88.1");
    let result = plugin.on_request_received(&mut ctx).await;
    plugin_utils::assert_reject(result, Some(403));
}

#[tokio::test]
async fn test_missing_response_code_defaults_to_403() {
    let plugin = BotDetection::new(&json!({})).unwrap();
    let mut ctx = make_ctx_with_ua("curl/7.88.1");
    let result = plugin.on_request_received(&mut ctx).await;
    plugin_utils::assert_reject(result, Some(403));
}

// ── Case-insensitive matching ───────────────────────────────────────────

#[tokio::test]
async fn test_case_insensitive_blocks_uppercase_curl() {
    let plugin = BotDetection::new(&json!({})).unwrap();
    let mut ctx = make_ctx_with_ua("CURL/7.88.1");
    let result = plugin.on_request_received(&mut ctx).await;
    plugin_utils::assert_reject(result, Some(403));
}

#[tokio::test]
async fn test_case_insensitive_blocks_mixed_case() {
    let plugin = BotDetection::new(&json!({})).unwrap();
    let mut ctx = make_ctx_with_ua("Python-Requests/2.31.0");
    let result = plugin.on_request_received(&mut ctx).await;
    plugin_utils::assert_reject(result, Some(403));
}

#[tokio::test]
async fn test_case_insensitive_allow_list() {
    let plugin = BotDetection::new(&json!({
        "allow_list": ["goodbot"]
    }))
    .unwrap();
    let mut ctx = make_ctx_with_ua("GoodBot/1.0");
    let result = plugin.on_request_received(&mut ctx).await;
    plugin_utils::assert_continue(result);
}

#[tokio::test]
async fn test_case_insensitive_custom_pattern() {
    let plugin = BotDetection::new(&json!({
        "blocked_patterns": ["evilcrawler"]
    }))
    .unwrap();
    let mut ctx = make_ctx_with_ua("EvilCrawler/3.0");
    let result = plugin.on_request_received(&mut ctx).await;
    plugin_utils::assert_reject(result, Some(403));
}

// ── Edge cases ──────────────────────────────────────────────────────────

#[tokio::test]
async fn test_empty_user_agent_passes_with_defaults() {
    let plugin = BotDetection::new(&json!({})).unwrap();
    let mut ctx = make_ctx_with_ua("");
    let result = plugin.on_request_received(&mut ctx).await;
    plugin_utils::assert_continue(result);
}

#[tokio::test]
async fn test_user_agent_containing_blocked_pattern_as_substring() {
    let plugin = BotDetection::new(&json!({})).unwrap();
    // "curl" appears as substring
    let mut ctx = make_ctx_with_ua("my-custom-curl-wrapper/1.0");
    let result = plugin.on_request_received(&mut ctx).await;
    plugin_utils::assert_reject(result, Some(403));
}

#[tokio::test]
async fn test_reject_body_is_json_error() {
    let plugin = BotDetection::new(&json!({})).unwrap();
    let mut ctx = make_ctx_with_ua("curl/7.88.1");
    let result = plugin.on_request_received(&mut ctx).await;
    match result {
        PluginResult::Reject { body, headers, .. } => {
            assert_eq!(body, r#"{"error":"Forbidden"}"#);
            assert!(headers.is_empty());
        }
        _ => panic!("Expected Reject, got {:?}", result),
    }
}
