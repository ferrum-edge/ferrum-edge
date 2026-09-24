//! Tests for the Bot Detection plugin

use ferrum_edge::_test_support::normalize_reject_response;
use ferrum_edge::plugins::bot_detection::{
    BOT_DETECTION_CONFIG_KEYS, BOT_DETECTION_PRIORITY, BotDetection,
};
use ferrum_edge::plugins::{
    HTTP_FAMILY_PROTOCOLS, Plugin, PluginResult, ProxyProtocol, RequestContext, priority,
};
use ferrum_edge::proxy::grpc_proxy::grpc_status;
use hyper::StatusCode;
use serde_json::{Value, json};

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
    assert_eq!(plugin.priority(), priority::BOT_DETECTION);
    assert_eq!(plugin.priority(), 200);
    assert!(!plugin.modifies_request_headers());
    assert!(!plugin.applies_after_proxy_on_reject());
    assert!(!plugin.is_auth_plugin());
}

#[test]
fn test_supported_protocols_cover_every_http_family_transport_only() {
    let plugin = BotDetection::new(&json!({})).unwrap();
    let protocols = plugin.supported_protocols();

    // ProxyProtocol::Http selects HTTP/1.1, HTTP/2, and HTTP/3. The other two
    // variants select native gRPC and WebSocket handshake request paths.
    assert_eq!(protocols, HTTP_FAMILY_PROTOCOLS);
    assert_eq!(
        protocols,
        &[
            ProxyProtocol::Http,
            ProxyProtocol::Grpc,
            ProxyProtocol::WebSocket,
        ]
    );
    assert!(!protocols.contains(&ProxyProtocol::Tcp));
    assert!(!protocols.contains(&ProxyProtocol::Udp));
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
async fn test_empty_blocked_patterns_with_missing_user_agent_allowed_rejected() {
    // #49: an explicit empty `blocked_patterns` while missing User-Agent
    // headers are allowed is a no-op (matches nothing, always Continue), so
    // the constructor must reject it rather than silently disabling the control.
    let err = BotDetection::new(&json!({
        "blocked_patterns": []
    }))
    .err()
    .expect("empty blocked_patterns with no allow_list must be rejected");
    assert!(
        err.contains("no effect") || err.contains("blocked_patterns"),
        "got: {err}"
    );
}

#[tokio::test]
async fn test_empty_blocked_patterns_with_allow_list_still_rejected() {
    // An allow-list alone only permits requests; it does not create a reject
    // path when there are no blocked patterns.
    let err = BotDetection::new(&json!({
        "blocked_patterns": [],
        "allow_list": ["googlebot"]
    }))
    .err()
    .expect("allow-list-only config should be rejected");
    assert!(err.contains("no effect"), "got: {err}");
}

#[tokio::test]
async fn test_empty_blocked_patterns_with_missing_user_agent_rejection_accepted() {
    // Missing User-Agent rejection is an actual enforcement path even without
    // blocked pattern matches.
    let plugin = BotDetection::new(&json!({
        "blocked_patterns": [],
        "allow_missing_user_agent": false
    }))
    .expect("presence-only config should be accepted");

    // Present arbitrary UAs pass because there are no blocked patterns.
    let mut ctx = make_ctx_with_ua("curl/7.88.1");
    let result = plugin.on_request_received(&mut ctx).await;
    plugin_utils::assert_continue(result);

    let mut missing = make_ctx_without_ua();
    let missing_result = plugin.on_request_received(&mut missing).await;
    plugin_utils::assert_reject(missing_result, Some(403));
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

#[tokio::test]
async fn test_allow_list_word_boundary_blocks_embedded_token_smuggling() {
    // #50: allow-list entries are word-boundary anchored, so an attacker
    // cannot smuggle an allowed token as a substring of an otherwise-blocked
    // User-Agent. With the old unanchored substring match, "curl evilChrome"
    // would match allow="Chrome" and bypass the "curl" block.
    let plugin = BotDetection::new(&json!({
        "allow_list": ["Chrome"]
    }))
    .unwrap();

    // "Chrome" only appears embedded inside "evilChrome" (no word boundary),
    // so the allow-list does NOT match and the default "curl" block applies.
    let mut ctx = make_ctx_with_ua("curl evilChrome");
    let result = plugin.on_request_received(&mut ctx).await;
    plugin_utils::assert_reject(result, Some(403));

    // A real browser UA where "Chrome" is a standalone token is still allowed
    // (allow-list wins over the blocked "curl" substring), confirming the
    // legitimate whole-token allow-list use keeps working.
    let mut ctx = make_ctx_with_ua("Mozilla/5.0 curl Chrome/120.0");
    let result = plugin.on_request_received(&mut ctx).await;
    plugin_utils::assert_continue(result);
}

#[tokio::test]
async fn test_allow_list_entries_with_punctuation_edges_match() {
    // `\b` next to a punctuation edge needs a word character outside the
    // entry, so full-UA fragments like these previously never matched.
    let plugin = BotDetection::new(&json!({
        "blocked_patterns": ["bot"],
        "allow_list": [
            "(compatible; UptimeRobot/2.0; http://www.uptimerobot.com/)",
            "+http://www.google.com/bot.html)",
            "Slackbot/"
        ]
    }))
    .unwrap();

    for ua in [
        "Mozilla/5.0+(compatible; UptimeRobot/2.0; http://www.uptimerobot.com/)",
        "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
        "Slackbot/ 1.0",
    ] {
        let mut ctx = make_ctx_with_ua(ua);
        let result = plugin.on_request_received(&mut ctx).await;
        plugin_utils::assert_continue(result);
    }

    // Word-character edges stay anchored: `Slackbot/` must not match when
    // embedded after another word character.
    let mut ctx = make_ctx_with_ua("evilSlackbot/ 1.0");
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
async fn test_custom_response_code_boundary_400() {
    let plugin = BotDetection::new(&json!({
        "custom_response_code": 400
    }))
    .unwrap();
    let mut ctx = make_ctx_with_ua("curl/7.88.1");
    let result = plugin.on_request_received(&mut ctx).await;
    plugin_utils::assert_reject(result, Some(400));
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

#[tokio::test]
async fn test_custom_response_code_zero_fraction_is_accepted() {
    let plugin = BotDetection::new(&json!({
        "custom_response_code": 403.0
    }))
    .unwrap();
    let mut ctx = make_ctx_with_ua("curl/7.88.1");
    let result = plugin.on_request_received(&mut ctx).await;
    plugin_utils::assert_reject(result, Some(403));
}

// ── Invalid config is rejected at construction ──────────────────────────

#[test]
fn test_config_requires_a_top_level_object() {
    for config in [
        Value::Null,
        json!([]),
        json!("blocked_patterns"),
        json!(false),
        json!(42),
    ] {
        let err = BotDetection::new(&config)
            .err()
            .expect("non-object config must be rejected");
        assert!(err.contains("JSON object"), "got: {err}");
        for &key in BOT_DETECTION_CONFIG_KEYS {
            assert!(err.contains(key), "missing allowed key {key} in: {err}");
        }
    }
}

#[test]
fn test_policy_affecting_unknown_keys_are_rejected() {
    for (config, typo) in [
        (
            json!({"blocked_paterns": ["FerrumAuditCrawler"]}),
            "blocked_paterns",
        ),
        (json!({"allowlist": ["GoodBot"]}), "allowlist"),
        (json!({"custom_reponse_code": 451}), "custom_reponse_code"),
        (
            json!({"allow_missing_useragent": false}),
            "allow_missing_useragent",
        ),
        (json!({"deny": ["FerrumAuditCrawler"]}), "deny"),
        (json!({"mode": "deny"}), "mode"),
        (
            json!({
                "blocked_patterns": ["FerrumAuditCrawler"],
                "allow_missing_useragent": false
            }),
            "allow_missing_useragent",
        ),
    ] {
        let err = BotDetection::new(&config)
            .err()
            .expect("unknown config key must be rejected");
        assert!(err.contains("unknown config key"), "got: {err}");
        assert!(err.contains(typo), "got: {err}");
        for &key in BOT_DETECTION_CONFIG_KEYS {
            assert!(err.contains(key), "missing allowed key {key} in: {err}");
        }
    }
}

#[tokio::test]
async fn test_field_nulls_intentionally_select_documented_defaults() {
    let plugin = BotDetection::new(&json!({
        "blocked_patterns": null,
        "allow_list": null,
        "custom_response_code": null,
        "allow_missing_user_agent": null
    }))
    .expect("field-level nulls should select defaults");

    let mut blocked = make_ctx_with_ua("curl/7.88.1");
    plugin_utils::assert_reject(plugin.on_request_received(&mut blocked).await, Some(403));

    let mut missing = make_ctx_without_ua();
    plugin_utils::assert_continue(plugin.on_request_received(&mut missing).await);
}

#[test]
fn test_null_missing_user_agent_policy_does_not_make_empty_patterns_effective() {
    let err = BotDetection::new(&json!({
        "blocked_patterns": [],
        "allow_missing_user_agent": null
    }))
    .err()
    .expect("null selects the default true policy, leaving this config a no-op");
    assert!(err.contains("no effect"), "got: {err}");
}

#[test]
fn test_each_field_rejects_wrong_types() {
    for (config, field) in [
        (json!({"blocked_patterns": "curl"}), "blocked_patterns"),
        (json!({"blocked_patterns": [42]}), "blocked_patterns"),
        (json!({"allow_list": "GoodBot"}), "allow_list"),
        (json!({"allow_list": [false]}), "allow_list"),
        (
            json!({"allow_missing_user_agent": "false"}),
            "allow_missing_user_agent",
        ),
        (
            json!({"custom_response_code": "451"}),
            "custom_response_code",
        ),
        (
            json!({"custom_response_code": 451.5}),
            "custom_response_code",
        ),
        (
            json!({"custom_response_code": false}),
            "custom_response_code",
        ),
    ] {
        let err = BotDetection::new(&config)
            .err()
            .expect("wrong field type must be rejected");
        assert!(err.contains(field), "got: {err}");
    }
}

#[test]
fn test_informational_no_body_and_out_of_range_statuses_are_rejected() {
    for code in [-1, 99, 100, 199, 204, 205, 304, 399, 600] {
        let err = BotDetection::new(&json!({"custom_response_code": code}))
            .err()
            .expect("non-4xx/5xx status must be rejected");
        assert!(err.contains("400 to 599"), "status {code}: {err}");
    }
}

#[test]
fn test_hostile_numeric_response_code_is_rejected() {
    let err = BotDetection::new(&json!({"custom_response_code": 1e100}))
        .err()
        .expect("hostile numeric status must be rejected");
    assert!(err.contains("400 to 599"), "got: {err}");
}

#[test]
fn test_invalid_response_code_below_range_rejects_creation() {
    let err = BotDetection::new(&json!({
        "custom_response_code": 99
    }))
    .err()
    .expect("below-range status code must be rejected");
    assert!(err.contains("custom_response_code"), "got: {err}");
}

#[test]
fn test_invalid_response_code_above_range_rejects_creation() {
    let err = BotDetection::new(&json!({
        "custom_response_code": 600
    }))
    .err()
    .expect("above-range status code must be rejected");
    assert!(err.contains("custom_response_code"), "got: {err}");
}

#[test]
fn test_invalid_response_code_zero_rejects_creation() {
    let err = BotDetection::new(&json!({
        "custom_response_code": 0
    }))
    .err()
    .expect("zero status code must be rejected");
    assert!(err.contains("custom_response_code"), "got: {err}");
}

#[test]
fn test_invalid_response_code_string_rejects_creation() {
    let err = BotDetection::new(&json!({
        "custom_response_code": "not_a_number"
    }))
    .err()
    .expect("non-integer status code must be rejected");
    assert!(err.contains("custom_response_code"), "got: {err}");
}

#[tokio::test]
async fn test_missing_response_code_defaults_to_403() {
    let plugin = BotDetection::new(&json!({})).unwrap();
    let mut ctx = make_ctx_with_ua("curl/7.88.1");
    let result = plugin.on_request_received(&mut ctx).await;
    plugin_utils::assert_reject(result, Some(403));
}

#[test]
fn test_non_array_blocked_patterns_rejects_creation() {
    let err = BotDetection::new(&json!({
        "blocked_patterns": "curl"
    }))
    .err()
    .expect("blocked_patterns must be an array");
    assert!(err.contains("blocked_patterns"), "got: {err}");
}

#[test]
fn test_non_string_allow_list_entry_rejects_creation() {
    let err = BotDetection::new(&json!({
        "allow_list": [42]
    }))
    .err()
    .expect("allow_list entries must be strings");
    assert!(err.contains("allow_list"), "got: {err}");
}

#[test]
fn test_empty_blocked_pattern_rejects_creation() {
    let err = BotDetection::new(&json!({
        "blocked_patterns": [""]
    }))
    .err()
    .expect("empty blocked pattern must be rejected");
    assert!(err.contains("non-whitespace"), "got: {err}");
}

#[test]
fn test_blank_pattern_entries_are_rejected_after_trimming() {
    for (config, field) in [
        (json!({"blocked_patterns": [" \t "]}), "blocked_patterns"),
        (json!({"allow_list": ["\n"]}), "allow_list"),
    ] {
        let err = BotDetection::new(&config)
            .err()
            .expect("blank pattern must be rejected");
        assert!(err.contains(field), "got: {err}");
        assert!(err.contains("non-whitespace"), "got: {err}");
    }
}

#[test]
fn test_non_bool_allow_missing_user_agent_rejects_creation() {
    let err = BotDetection::new(&json!({
        "allow_missing_user_agent": "false"
    }))
    .err()
    .expect("allow_missing_user_agent must be boolean");
    assert!(err.contains("allow_missing_user_agent"), "got: {err}");
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

#[tokio::test]
async fn test_custom_patterns_treat_regex_metacharacters_as_literals() {
    let plugin = BotDetection::new(&json!({
        "blocked_patterns": ["bot.*"]
    }))
    .unwrap();

    let mut ctx = make_ctx_with_ua("bot-123");
    let result = plugin.on_request_received(&mut ctx).await;
    plugin_utils::assert_continue(result);

    let mut ctx = make_ctx_with_ua("bot.*/1.0");
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
    let hostile_user_agent = r#"curl/7.88.1 <script>alert("reflected")</script>"#;
    let mut ctx = make_ctx_with_ua(hostile_user_agent);
    let result = plugin.on_request_received(&mut ctx).await;
    match result {
        PluginResult::Reject { body, headers, .. } => {
            assert_eq!(body, r#"{"error":"Forbidden"}"#);
            assert_eq!(
                serde_json::from_str::<Value>(&body).expect("rejection body must be valid JSON"),
                json!({"error": "Forbidden"})
            );
            assert!(!body.contains(hostile_user_agent));
            assert!(headers.is_empty());
        }
        _ => panic!("Expected Reject, got {:?}", result),
    }
}

#[tokio::test]
async fn test_native_grpc_rejection_is_normalized_without_json_body() {
    let plugin = BotDetection::new(&json!({"custom_response_code": 429})).unwrap();
    let mut ctx = make_ctx_with_ua("curl/7.88.1");
    let PluginResult::Reject {
        status_code,
        body,
        headers,
    } = plugin.on_request_received(&mut ctx).await
    else {
        panic!("blocked User-Agent must be rejected");
    };

    let normalized = normalize_reject_response(
        StatusCode::from_u16(status_code).unwrap(),
        body.as_bytes(),
        &headers,
        true,
    );
    assert_eq!(normalized.http_status, StatusCode::OK);
    assert!(normalized.body.is_empty());
    assert_eq!(
        normalized.grpc_status,
        Some(grpc_status::RESOURCE_EXHAUSTED)
    );
    assert_eq!(normalized.grpc_message.as_deref(), Some("Forbidden"));
    assert_eq!(
        normalized.headers.get("content-type").map(String::as_str),
        Some("application/grpc")
    );
    assert_eq!(
        normalized.headers.get("grpc-status").map(String::as_str),
        Some("8")
    );
}

#[test]
fn configuration_diagnostics_keep_schema_and_withhold_supplied_values() {
    let canary = "'SECURITY_DIAGNOSTIC_CANARY\"`\n\\payload";
    let cases: &[(serde_json::Value, &[&str])] = &[
        (
            json!({(canary): true}),
            &["unknown config key", "`blocked_patterns`"],
        ),
        (
            json!({"custom_response_code": 8675309}),
            &["`custom_response_code`", "400 to 599"],
        ),
        (
            json!({"blocked_patterns": [true]}),
            &["`blocked_patterns`", "index 0", "must be a string"],
        ),
    ];

    for (config, expected) in cases {
        let error = ferrum_edge::plugins::validate_plugin_config("bot_detection", config)
            .expect_err("invalid configuration must still be rejected");
        let rendered = ferrum_edge::startup::render_startup_error(anyhow::Error::msg(error), &[]);
        for &fragment in *expected {
            assert!(
                rendered.contains(fragment),
                "missing {fragment:?}: {rendered}"
            );
        }
        for supplied in [
            "SECURITY_DIAGNOSTIC_CANARY",
            "security-diagnostic-canary",
            "8675309",
            "54321",
            "16384",
            "true",
        ] {
            assert!(
                !rendered.contains(supplied),
                "leaked {supplied:?}: {rendered}"
            );
        }
    }
}
