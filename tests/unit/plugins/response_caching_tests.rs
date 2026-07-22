//! Tests for response_caching plugin

use super::plugin_utils::create_test_proxy;
use chrono::Utc;
use ferrum_edge::_test_support::{
    advance_response_caching_clock_for_test, clone_log_metadata,
    response_caching_current_total_size_for_test, response_caching_instance_id_for_test,
    response_caching_size_accounting_snapshot_for_test,
    response_caching_staging_metadata_key_for_test,
};
use ferrum_edge::config::types::Consumer;
use ferrum_edge::plugins::response_caching::{RESPONSE_CACHING_CONFIG_KEYS, ResponseCaching};
use ferrum_edge::plugins::{
    Plugin, PluginFailurePolicy, PluginResult, RequestContext, plugin_failure_policy,
    validate_plugin_config,
};
use serde_json::json;
use std::collections::HashMap;
use std::sync::Arc;

fn make_consumer(id: &str, username: &str) -> Consumer {
    Consumer {
        id: id.to_string(),
        namespace: ferrum_edge::config::types::default_namespace(),
        username: username.to_string(),
        custom_id: None,
        credentials: HashMap::new(),
        acl_groups: Vec::new(),
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

fn make_ctx(method: &str, path: &str) -> RequestContext {
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        method.to_string(),
        path.to_string(),
    );
    ctx.matched_proxy = Some(std::sync::Arc::new(create_test_proxy()));
    ctx
}

fn make_ctx_with_query(method: &str, path: &str, query: &[(&str, &str)]) -> RequestContext {
    let raw_query = query
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("&");
    make_ctx_with_raw_query(method, path, &raw_query)
}

fn make_ctx_with_raw_query(method: &str, path: &str, raw_query: &str) -> RequestContext {
    let mut ctx = make_ctx(method, path);
    ctx.set_raw_query_string(raw_query.to_string());
    ctx
}

fn default_plugin() -> ResponseCaching {
    ResponseCaching::new(&json!({})).unwrap()
}

fn plugin_with_config(config: serde_json::Value) -> ResponseCaching {
    ResponseCaching::new(&config).unwrap()
}

fn staging_key(plugin: &ResponseCaching, suffix: &str) -> String {
    response_caching_staging_metadata_key_for_test(plugin, suffix)
}

fn assert_status(plugin: &ResponseCaching, ctx: &RequestContext, expected: &str) {
    assert_eq!(
        ctx.metadata
            .get(&staging_key(plugin, "cache_status"))
            .map(String::as_str),
        Some(expected)
    );
}

fn expect_reject(result: PluginResult) -> (u16, Vec<u8>, HashMap<String, String>) {
    match result {
        PluginResult::Reject {
            status_code,
            body,
            headers,
        } => (status_code, body.into_bytes(), headers),
        PluginResult::RejectBinary {
            status_code,
            body,
            headers,
        } => (status_code, body.to_vec(), headers),
        PluginResult::Continue => panic!("Expected cache hit"),
    }
}

fn is_reject(result: &PluginResult) -> bool {
    matches!(
        result,
        PluginResult::Reject { .. } | PluginResult::RejectBinary { .. }
    )
}

fn cached_age(headers: &HashMap<String, String>) -> u64 {
    headers
        .get("age")
        .expect("cached response should include Age")
        .parse()
        .expect("Age should be a decimal second count")
}

fn assert_size_accounting_exact(plugin: &ResponseCaching) -> usize {
    let (tracked, actual) = response_caching_size_accounting_snapshot_for_test(plugin);
    assert_eq!(
        tracked, actual,
        "tracked response-cache size must match actual retained entry size"
    );
    tracked
}

fn http_date_seconds_ago(seconds: i64) -> String {
    (Utc::now() - chrono::Duration::seconds(seconds))
        .format("%a, %d %b %Y %H:%M:%S GMT")
        .to_string()
}

// Helper to simulate a full cache flow: before_proxy (miss) -> after_proxy -> on_final_response_body
async fn cache_response(
    plugin: &ResponseCaching,
    method: &str,
    path: &str,
    status: u16,
    response_headers: &HashMap<String, String>,
    body: &[u8],
) {
    let mut ctx = make_ctx(method, path);
    let mut headers = HashMap::new();

    // before_proxy (should be MISS)
    plugin.before_proxy(&mut ctx, &mut headers).await;

    // after_proxy
    let mut resp_headers = response_headers.clone();
    plugin
        .after_proxy(&mut ctx, status, &mut resp_headers)
        .await;

    // on_final_response_body
    plugin
        .on_final_response_body(&mut ctx, status, &resp_headers, body)
        .await;
}

// Simulate a backend refresh of an existing entry. A normal lookup would HIT
// and short-circuit before any backend response exists; request no-cache keeps
// the instance's store staging while bypassing that fresh entry.
async fn replace_cached_response(
    plugin: &ResponseCaching,
    method: &str,
    path: &str,
    status: u16,
    response_headers: &HashMap<String, String>,
    body: &[u8],
) {
    let mut ctx = make_ctx(method, path);
    let mut request_headers =
        HashMap::from([("cache-control".to_string(), "no-cache".to_string())]);
    assert!(matches!(
        plugin.before_proxy(&mut ctx, &mut request_headers).await,
        PluginResult::Continue
    ));

    let mut response_headers = response_headers.clone();
    plugin
        .after_proxy(&mut ctx, status, &mut response_headers)
        .await;
    plugin
        .on_final_response_body(&mut ctx, status, &response_headers, body)
        .await;
}

// === Plugin creation ===

#[tokio::test]
async fn test_creation_defaults() {
    let plugin = default_plugin();
    assert_eq!(plugin.name(), "response_caching");
    assert_eq!(plugin.priority(), 3500);
    assert!(plugin.requires_response_body_buffering());
}

#[test]
fn test_non_object_config_rejected() {
    let err = ResponseCaching::new(&json!("bad"))
        .err()
        .expect("non-object config must be rejected");
    assert!(err.contains("config must be an object"), "got: {err}");
}

#[test]
fn test_invalid_bool_config_rejected() {
    let err = ResponseCaching::new(&json!({
        "respect_cache_control": "true"
    }))
    .err()
    .expect("bad bool config must be rejected");
    assert!(err.contains("respect_cache_control"), "got: {err}");
}

#[test]
fn test_invalid_cacheable_methods_config_rejected() {
    let err = ResponseCaching::new(&json!({
        "cacheable_methods": ["GET", 42]
    }))
    .err()
    .expect("non-string method must be rejected");
    assert!(err.contains("cacheable_methods[1]"), "got: {err}");
}

#[test]
fn test_invalid_cacheable_status_codes_config_rejected() {
    let err = ResponseCaching::new(&json!({
        "cacheable_status_codes": [200, 700]
    }))
    .err()
    .expect("invalid status code must be rejected");
    assert!(err.contains("cacheable_status_codes[1]"), "got: {err}");
}

#[test]
fn test_invalid_vary_header_config_rejected() {
    let err = ResponseCaching::new(&json!({
        "vary_by_headers": ["bad header"]
    }))
    .err()
    .expect("invalid header name must be rejected");
    assert!(err.contains("vary_by_headers[0]"), "got: {err}");
}

#[test]
fn test_zero_cache_size_config_rejected() {
    let err = ResponseCaching::new(&json!({
        "max_entries": 0
    }))
    .err()
    .expect("zero max_entries must be rejected");
    assert!(err.contains("max_entries"), "got: {err}");
}

#[test]
fn test_unknown_root_keys_are_rejected_with_path_qualified_suggestions() {
    assert_eq!(
        plugin_failure_policy("response_caching"),
        Some(PluginFailurePolicy::KeepLastKnownGood)
    );

    let typos = [
        ("vary_by_headers", "vary_by_header"),
        ("cache_key_include_consumer", "cache_key_include_consumr"),
        ("cache_key_include_query", "cache_key_include_quer"),
        ("respect_cache_control", "respect_cache_contro"),
        ("respect_no_cache", "respect_no_cach"),
        ("cacheable_status_codes", "cacheable_status_code"),
        ("cacheable_methods", "cacheable_method"),
        ("ttl_seconds", "ttl_second"),
        ("max_entries", "max_entrie"),
        ("max_entry_size_bytes", "max_entry_size_byte"),
        ("max_total_size_bytes", "max_total_size_byte"),
        ("add_cache_status_header", "add_cache_status_heade"),
        (
            "invalidate_on_unsafe_methods",
            "invalidate_on_unsafe_method",
        ),
    ];
    assert_eq!(
        typos.len(),
        RESPONSE_CACHING_CONFIG_KEYS.len(),
        "every recognized key needs a one-character misspelling case"
    );

    for (canonical, typo) in typos {
        assert!(
            RESPONSE_CACHING_CONFIG_KEYS.contains(&canonical),
            "typo fixture must target a recognized key: {canonical}"
        );
        let mut config = json!({"ttl_seconds": 60});
        config
            .as_object_mut()
            .expect("config object")
            .insert(typo.to_string(), json!(true));
        let err = ResponseCaching::new(&config)
            .err()
            .unwrap_or_else(|| panic!("expected unknown-key rejection for {typo}"));
        assert!(
            err.contains("unknown configuration key"),
            "missing unknown-key wording: {err}"
        );
        assert!(
            err.contains(&format!("'config.{typo}'")),
            "error must path-qualify the typo: {err}"
        );
        assert!(
            err.contains("did you mean"),
            "typo diagnostics should include a suggestion: {err}"
        );
        assert!(
            err.contains(canonical),
            "suggestion should name the canonical key {canonical}: {err}"
        );

        let shared = validate_plugin_config("response_caching", &config)
            .expect_err("shared admission must reject the same typo");
        assert!(
            shared.contains(&format!("'config.{typo}'")),
            "shared path must surface the same diagnostic: {shared}"
        );
    }
}

#[test]
fn test_multiple_unknown_root_keys_are_sorted_and_path_qualified() {
    let err = ResponseCaching::new(&json!({
        "ttl_seconds": 60,
        "zzz_extra": true,
        "aaa_extra": false,
        "vary_by_header": ["x-tenant"]
    }))
    .err()
    .expect("multiple unknown keys must be rejected");
    assert!(err.contains("'config.aaa_extra'"), "got: {err}");
    assert!(err.contains("'config.vary_by_header'"), "got: {err}");
    assert!(err.contains("'config.zzz_extra'"), "got: {err}");
    assert!(
        err.contains("did you mean 'vary_by_headers'?"),
        "near-miss Vary typo should suggest the canonical key: {err}"
    );
    let aaa = err.find("aaa_extra").expect("aaa_extra present");
    let vary = err.find("vary_by_header").expect("vary_by_header present");
    let zzz = err.find("zzz_extra").expect("zzz_extra present");
    assert!(
        aaa < vary && vary < zzz,
        "unknown keys should be sorted in the error: {err}"
    );
}

#[test]
fn test_recognized_field_null_and_type_behavior_is_preserved() {
    ResponseCaching::new(&json!({
        "ttl_seconds": null,
        "max_entries": null,
        "max_entry_size_bytes": null,
        "max_total_size_bytes": null,
        "respect_cache_control": null,
        "respect_no_cache": null,
        "cache_key_include_query": null,
        "cache_key_include_consumer": null,
        "add_cache_status_header": null,
        "invalidate_on_unsafe_methods": null
    }))
    .expect("scalar nulls must continue to select documented defaults");

    for (config, needle) in [
        (json!({"ttl_seconds": true}), "ttl_seconds"),
        (json!({"max_entries": 0}), "max_entries"),
        (json!({"max_entry_size_bytes": -1}), "max_entry_size_bytes"),
        (
            json!({"respect_cache_control": "true"}),
            "respect_cache_control",
        ),
        (json!({"cacheable_methods": null}), "cacheable_methods"),
        (json!({"cacheable_methods": []}), "cacheable_methods"),
        (
            json!({"cacheable_status_codes": null}),
            "cacheable_status_codes",
        ),
        (
            json!({"cacheable_status_codes": [700]}),
            "cacheable_status_codes",
        ),
        (json!({"vary_by_headers": null}), "vary_by_headers"),
    ] {
        let err = ResponseCaching::new(&config)
            .err()
            .unwrap_or_else(|| panic!("expected type/range rejection for {needle}"));
        assert!(
            err.contains(needle),
            "type/range diagnostic must name {needle}: {err}"
        );
        assert!(
            !err.contains("unknown configuration key"),
            "recognized-field failures must not be mislabeled as unknown keys: {err}"
        );
    }
}

#[tokio::test]
async fn test_supported_protocols() {
    let plugin = default_plugin();
    let protocols = plugin.supported_protocols();
    assert_eq!(protocols.len(), 1);
    assert_eq!(protocols[0], ferrum_edge::plugins::ProxyProtocol::Http);
}

// === Cache miss on first request ===

#[tokio::test]
async fn test_cache_miss_first_request() {
    let plugin = default_plugin();
    let mut ctx = make_ctx("GET", "/api/data");
    let mut headers = HashMap::new();

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
    assert_eq!(
        ctx.metadata
            .get(&staging_key(&plugin, "cache_status"))
            .unwrap(),
        "MISS"
    );
    assert!(
        ctx.metadata
            .contains_key(&staging_key(&plugin, "cache_base_key"))
    );
}

#[tokio::test]
async fn test_query_cache_key_avoids_raw_delimiter_collision() {
    let plugin = default_plugin();

    let mut attacker_ctx = make_ctx_with_raw_query("GET", "/api/data", "a=1%26b=2");
    let mut attacker_headers = HashMap::new();
    let attacker_result = plugin
        .before_proxy(&mut attacker_ctx, &mut attacker_headers)
        .await;
    assert!(matches!(attacker_result, PluginResult::Continue));
    let attacker_key = attacker_ctx
        .metadata
        .get(&staging_key(&plugin, "cache_base_key"))
        .expect("cache key should be stored")
        .clone();

    let mut victim_ctx = make_ctx_with_raw_query("GET", "/api/data", "a=1&b=2");
    let mut victim_headers = HashMap::new();
    let victim_result = plugin
        .before_proxy(&mut victim_ctx, &mut victim_headers)
        .await;
    assert!(matches!(victim_result, PluginResult::Continue));
    let victim_key = victim_ctx
        .metadata
        .get(&staging_key(&plugin, "cache_base_key"))
        .expect("cache key should be stored")
        .clone();

    assert_ne!(attacker_key, victim_key);
}

async fn base_cache_key_for_raw_query(plugin: &ResponseCaching, raw_query: &str) -> String {
    let mut ctx = make_ctx_with_raw_query("GET", "/api/data", raw_query);
    let mut headers = HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
    ctx.metadata
        .get(&staging_key(plugin, "cache_base_key"))
        .expect("cache key should be stored")
        .clone()
}

#[tokio::test]
async fn test_raw_query_cache_key_preserves_exact_semantics() {
    let plugin = default_plugin();

    let duplicate_pair = base_cache_key_for_raw_query(&plugin, "a=1&a=2").await;
    let single_pair = base_cache_key_for_raw_query(&plugin, "a=2").await;
    assert_ne!(duplicate_pair, single_pair);

    let reordered_pair = base_cache_key_for_raw_query(&plugin, "a=2&a=1").await;
    assert_ne!(duplicate_pair, reordered_pair);

    let percent_encoded = base_cache_key_for_raw_query(&plugin, "%61=1").await;
    let plain = base_cache_key_for_raw_query(&plugin, "a=1").await;
    assert_ne!(percent_encoded, plain);

    let bare_flag = base_cache_key_for_raw_query(&plugin, "flag").await;
    let empty_flag = base_cache_key_for_raw_query(&plugin, "flag=").await;
    assert_ne!(bare_flag, empty_flag);

    let same_again = base_cache_key_for_raw_query(&plugin, "a=1&a=2").await;
    assert_eq!(duplicate_pair, same_again);
}

// === Cache hit on second request ===

#[tokio::test]
async fn test_cache_hit_second_request() {
    let plugin = default_plugin();
    let mut resp_headers = HashMap::new();
    resp_headers.insert("content-type".to_string(), "application/json".to_string());

    cache_response(
        &plugin,
        "GET",
        "/api/data",
        200,
        &resp_headers,
        b"{\"key\":\"value\"}",
    )
    .await;

    // Second request should be a HIT
    let mut ctx = make_ctx("GET", "/api/data");
    let mut headers = HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    let (status_code, body, headers) = expect_reject(result);
    assert_eq!(status_code, 200);
    assert_eq!(body, b"{\"key\":\"value\"}");
    assert_eq!(headers.get("content-type").unwrap(), "application/json");
    assert_eq!(headers.get("x-cache-status").unwrap(), "HIT");
}

#[tokio::test]
async fn test_cache_hit_replaces_stored_age_with_current_age() {
    let plugin = default_plugin();
    let mut resp_headers = HashMap::new();
    resp_headers.insert("cache-control".to_string(), "max-age=60".to_string());
    resp_headers.insert("age".to_string(), "10".to_string());

    cache_response(&plugin, "GET", "/api/age", 200, &resp_headers, b"cached").await;

    let mut ctx = make_ctx("GET", "/api/age");
    let mut headers = HashMap::new();
    let (_, _, headers) = expect_reject(plugin.before_proxy(&mut ctx, &mut headers).await);
    let age = cached_age(&headers);
    assert!(
        (10..60).contains(&age),
        "expected current Age to include upstream Age and remain fresh, got {age}"
    );
}

#[tokio::test]
async fn test_age_increases_during_cache_residency_without_sleep() {
    let plugin = default_plugin();
    let mut resp_headers = HashMap::new();
    resp_headers.insert("cache-control".to_string(), "max-age=60".to_string());
    resp_headers.insert("age".to_string(), "10".to_string());

    cache_response(
        &plugin,
        "GET",
        "/api/resident",
        200,
        &resp_headers,
        b"cached",
    )
    .await;
    advance_response_caching_clock_for_test(&plugin, std::time::Duration::from_secs(5));

    let mut ctx = make_ctx("GET", "/api/resident");
    let mut headers = HashMap::new();
    let (_, _, headers) = expect_reject(plugin.before_proxy(&mut ctx, &mut headers).await);
    let age = cached_age(&headers);
    assert!(
        (15..60).contains(&age),
        "expected resident time to increase Age from 10 by about 5 seconds, got {age}"
    );
}

#[tokio::test]
async fn test_upstream_age_near_freshness_expires_after_residency() {
    let plugin = default_plugin();
    let mut resp_headers = HashMap::new();
    resp_headers.insert("cache-control".to_string(), "max-age=60".to_string());
    resp_headers.insert("age".to_string(), "59".to_string());

    cache_response(
        &plugin,
        "GET",
        "/api/nearly-stale",
        200,
        &resp_headers,
        b"cached",
    )
    .await;

    let mut fresh_ctx = make_ctx("GET", "/api/nearly-stale");
    let mut fresh_headers = HashMap::new();
    let fresh_result = plugin
        .before_proxy(&mut fresh_ctx, &mut fresh_headers)
        .await;
    assert!(is_reject(&fresh_result));

    advance_response_caching_clock_for_test(&plugin, std::time::Duration::from_secs(2));

    let mut stale_ctx = make_ctx("GET", "/api/nearly-stale");
    let mut stale_headers = HashMap::new();
    let result = plugin
        .before_proxy(&mut stale_ctx, &mut stale_headers)
        .await;
    assert!(matches!(result, PluginResult::Continue));
    assert_eq!(
        stale_ctx
            .metadata
            .get(&staging_key(&plugin, "cache_status"))
            .unwrap(),
        "MISS"
    );
    assert_eq!(assert_size_accounting_exact(&plugin), 0);
}

// === TTL expiry ===

#[tokio::test]
async fn test_ttl_expiry() {
    let plugin = plugin_with_config(json!({
        "ttl_seconds": 0  // Immediate expiry
    }));

    cache_response(&plugin, "GET", "/api/data", 200, &HashMap::new(), b"cached").await;

    let mut ctx = make_ctx("GET", "/api/data");
    let mut headers = HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
    let status = ctx
        .metadata
        .get(&staging_key(&plugin, "cache_status"))
        .unwrap()
        .as_str();
    assert!(
        status == "MISS" || status == "PREDICTED-BYPASS",
        "expected MISS or PREDICTED-BYPASS, got {status}"
    );
}

// === Cache-Control: no-store ===

#[tokio::test]
async fn test_cache_control_no_store_response() {
    let plugin = default_plugin();
    let mut resp_headers = HashMap::new();
    resp_headers.insert("cache-control".to_string(), "no-store".to_string());

    cache_response(
        &plugin,
        "GET",
        "/api/secret",
        200,
        &resp_headers,
        b"secret data",
    )
    .await;

    // Should not be cached
    let mut ctx = make_ctx("GET", "/api/secret");
    let mut headers = HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
}

// === Cache-Control: private ===

#[tokio::test]
async fn test_cache_control_private_response() {
    let plugin = default_plugin();
    let mut resp_headers = HashMap::new();
    resp_headers.insert("cache-control".to_string(), "private".to_string());

    cache_response(
        &plugin,
        "GET",
        "/api/private",
        200,
        &resp_headers,
        b"private data",
    )
    .await;

    // Should not be cached
    let mut ctx = make_ctx("GET", "/api/private");
    let mut headers = HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
}

// === Cache-Control: max-age ===

#[tokio::test]
async fn test_cache_control_max_age() {
    let plugin = plugin_with_config(json!({
        "ttl_seconds": 1  // Short default
    }));

    let mut resp_headers = HashMap::new();
    resp_headers.insert("cache-control".to_string(), "max-age=3600".to_string());

    cache_response(
        &plugin,
        "GET",
        "/api/data",
        200,
        &resp_headers,
        b"long-lived",
    )
    .await;

    // Should still be cached (max-age=3600 overrides ttl_seconds=1)
    let mut ctx = make_ctx("GET", "/api/data");
    let mut headers = HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(is_reject(&result));
}

#[tokio::test]
async fn test_old_date_reduces_remaining_freshness() {
    let plugin = default_plugin();
    let mut resp_headers = HashMap::new();
    resp_headers.insert("cache-control".to_string(), "max-age=60".to_string());
    resp_headers.insert("date".to_string(), http_date_seconds_ago(120));

    cache_response(
        &plugin,
        "GET",
        "/api/old-date",
        200,
        &resp_headers,
        b"stale",
    )
    .await;

    let mut ctx = make_ctx("GET", "/api/old-date");
    let mut headers = HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
    assert_eq!(
        ctx.metadata
            .get(&staging_key(&plugin, "cache_status"))
            .unwrap(),
        "PREDICTED-BYPASS"
    );
}

#[tokio::test]
async fn test_date_dominated_age_does_not_double_count_response_delay() {
    let plugin = default_plugin();
    let mut ctx = make_ctx("GET", "/api/date-delay");
    let mut headers = HashMap::new();
    assert!(matches!(
        plugin.before_proxy(&mut ctx, &mut headers).await,
        PluginResult::Continue
    ));

    advance_response_caching_clock_for_test(&plugin, std::time::Duration::from_secs(5));

    let mut resp_headers = HashMap::new();
    resp_headers.insert("cache-control".to_string(), "max-age=60".to_string());
    // The plugin clock is advanced by 5s above, making this Date appear 58s old.
    resp_headers.insert("date".to_string(), http_date_seconds_ago(53));
    plugin.after_proxy(&mut ctx, 200, &mut resp_headers).await;
    plugin
        .on_final_response_body(&mut ctx, 200, &resp_headers, b"stale")
        .await;

    let mut hit_ctx = make_ctx("GET", "/api/date-delay");
    let mut hit_headers = HashMap::new();
    let (status, body, headers) =
        expect_reject(plugin.before_proxy(&mut hit_ctx, &mut hit_headers).await);
    assert_eq!(status, 200);
    assert_eq!(body, b"stale");
    assert_eq!(headers.get("x-cache-status"), Some(&"HIT".to_string()));
}

#[tokio::test]
async fn test_malformed_age_does_not_panic_or_prevent_fresh_hit() {
    let plugin = default_plugin();
    let mut resp_headers = HashMap::new();
    resp_headers.insert("cache-control".to_string(), "max-age=60".to_string());
    resp_headers.insert("age".to_string(), "not-a-number".to_string());

    cache_response(
        &plugin,
        "GET",
        "/api/malformed-age",
        200,
        &resp_headers,
        b"cached",
    )
    .await;

    let mut ctx = make_ctx("GET", "/api/malformed-age");
    let mut headers = HashMap::new();
    let (_, _, headers) = expect_reject(plugin.before_proxy(&mut ctx, &mut headers).await);
    assert!(
        cached_age(&headers) < 60,
        "malformed Age should be ignored instead of wrapping or panicking"
    );
}

#[tokio::test]
async fn test_overflowing_age_does_not_wrap_to_fresh() {
    let plugin = default_plugin();
    let mut resp_headers = HashMap::new();
    resp_headers.insert("cache-control".to_string(), "max-age=60".to_string());
    resp_headers.insert("age".to_string(), format!("{}0", u64::MAX));

    cache_response(
        &plugin,
        "GET",
        "/api/overflow-age",
        200,
        &resp_headers,
        b"stale",
    )
    .await;

    let mut ctx = make_ctx("GET", "/api/overflow-age");
    let mut headers = HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
    assert_eq!(
        ctx.metadata
            .get(&staging_key(&plugin, "cache_status"))
            .unwrap(),
        "PREDICTED-BYPASS"
    );
}

// === Cache-Control: s-maxage takes precedence ===

#[tokio::test]
async fn test_cache_control_s_maxage_precedence() {
    let plugin = plugin_with_config(json!({
        "ttl_seconds": 0  // Would expire immediately
    }));

    let mut resp_headers = HashMap::new();
    resp_headers.insert(
        "cache-control".to_string(),
        "max-age=0, s-maxage=3600".to_string(),
    );

    cache_response(
        &plugin,
        "GET",
        "/api/data",
        200,
        &resp_headers,
        b"s-maxage wins",
    )
    .await;

    // s-maxage=3600 should override max-age=0
    let mut ctx = make_ctx("GET", "/api/data");
    let mut headers = HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(is_reject(&result));
}

#[tokio::test]
async fn test_s_maxage_freshness_accounts_for_age() {
    let plugin = plugin_with_config(json!({
        "ttl_seconds": 0
    }));

    let mut resp_headers = HashMap::new();
    resp_headers.insert(
        "cache-control".to_string(),
        "max-age=0, s-maxage=60".to_string(),
    );
    resp_headers.insert("age".to_string(), "30".to_string());

    cache_response(
        &plugin,
        "GET",
        "/api/s-maxage-age",
        200,
        &resp_headers,
        b"cached",
    )
    .await;
    advance_response_caching_clock_for_test(&plugin, std::time::Duration::from_secs(20));

    let mut ctx = make_ctx("GET", "/api/s-maxage-age");
    let mut headers = HashMap::new();
    let (_, _, headers) = expect_reject(plugin.before_proxy(&mut ctx, &mut headers).await);
    let age = cached_age(&headers);
    assert!(
        (50..60).contains(&age),
        "s-maxage should define freshness while Age still advances, got {age}"
    );
}

#[tokio::test]
async fn test_fallback_ttl_freshness_accounts_for_age() {
    let plugin = plugin_with_config(json!({
        "ttl_seconds": 30
    }));

    let mut resp_headers = HashMap::new();
    resp_headers.insert("age".to_string(), "25".to_string());

    cache_response(
        &plugin,
        "GET",
        "/api/fallback-age",
        200,
        &resp_headers,
        b"cached",
    )
    .await;

    let mut fresh_ctx = make_ctx("GET", "/api/fallback-age");
    let mut fresh_headers = HashMap::new();
    let fresh_result = plugin
        .before_proxy(&mut fresh_ctx, &mut fresh_headers)
        .await;
    assert!(is_reject(&fresh_result));

    advance_response_caching_clock_for_test(&plugin, std::time::Duration::from_secs(6));

    let mut stale_ctx = make_ctx("GET", "/api/fallback-age");
    let mut stale_headers = HashMap::new();
    let result = plugin
        .before_proxy(&mut stale_ctx, &mut stale_headers)
        .await;
    assert!(matches!(result, PluginResult::Continue));
    assert_eq!(
        stale_ctx
            .metadata
            .get(&staging_key(&plugin, "cache_status"))
            .unwrap(),
        "MISS"
    );
    assert_eq!(assert_size_accounting_exact(&plugin), 0);
}

// === Client Cache-Control: no-cache bypasses cache ===

#[tokio::test]
async fn test_client_no_cache_bypasses() {
    let plugin = default_plugin();

    cache_response(
        &plugin,
        "GET",
        "/api/data",
        200,
        &HashMap::new(),
        b"cached data",
    )
    .await;

    // Request with Cache-Control: no-cache should bypass
    let mut ctx = make_ctx("GET", "/api/data");
    ctx.headers
        .insert("cache-control".to_string(), "no-cache".to_string());
    let mut headers = HashMap::new();
    headers.insert("cache-control".to_string(), "no-cache".to_string());
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
    assert_eq!(
        ctx.metadata
            .get(&staging_key(&plugin, "cache_status"))
            .unwrap(),
        "BYPASS"
    );
}

#[tokio::test]
async fn test_bypassed_stale_response_does_not_poison_fresh_entry() {
    let plugin = default_plugin();
    let mut resp_headers = HashMap::new();
    resp_headers.insert("cache-control".to_string(), "max-age=60".to_string());
    cache_response(
        &plugin,
        "GET",
        "/api/no-cache-stale",
        200,
        &resp_headers,
        b"fresh",
    )
    .await;

    let mut bypass_ctx = make_ctx("GET", "/api/no-cache-stale");
    bypass_ctx
        .headers
        .insert("cache-control".to_string(), "no-cache".to_string());
    let mut bypass_headers = HashMap::new();
    bypass_headers.insert("cache-control".to_string(), "no-cache".to_string());
    assert!(matches!(
        plugin
            .before_proxy(&mut bypass_ctx, &mut bypass_headers)
            .await,
        PluginResult::Continue
    ));
    assert_eq!(
        bypass_ctx
            .metadata
            .get(&staging_key(&plugin, "cache_status"))
            .unwrap(),
        "BYPASS"
    );

    let mut stale_headers = HashMap::new();
    stale_headers.insert("cache-control".to_string(), "max-age=60".to_string());
    stale_headers.insert("age".to_string(), "61".to_string());
    plugin
        .after_proxy(&mut bypass_ctx, 200, &mut stale_headers)
        .await;
    plugin
        .on_final_response_body(&mut bypass_ctx, 200, &stale_headers, b"stale")
        .await;

    let mut hit_ctx = make_ctx("GET", "/api/no-cache-stale");
    let mut hit_headers = HashMap::new();
    let (status, body, headers) =
        expect_reject(plugin.before_proxy(&mut hit_ctx, &mut hit_headers).await);
    assert_eq!(status, 200);
    assert_eq!(body, b"fresh");
    assert_eq!(headers.get("x-cache-status"), Some(&"HIT".to_string()));
}

#[tokio::test]
async fn test_bypassed_zero_freshness_response_invalidates_existing_entry() {
    let plugin = default_plugin();
    let mut resp_headers = HashMap::new();
    resp_headers.insert("cache-control".to_string(), "max-age=60".to_string());
    cache_response(
        &plugin,
        "GET",
        "/api/no-cache-zero",
        200,
        &resp_headers,
        b"cached",
    )
    .await;

    let mut bypass_ctx = make_ctx("GET", "/api/no-cache-zero");
    bypass_ctx
        .headers
        .insert("cache-control".to_string(), "no-cache".to_string());
    let mut bypass_headers = HashMap::new();
    bypass_headers.insert("cache-control".to_string(), "no-cache".to_string());
    assert!(matches!(
        plugin
            .before_proxy(&mut bypass_ctx, &mut bypass_headers)
            .await,
        PluginResult::Continue
    ));
    assert_eq!(
        bypass_ctx
            .metadata
            .get(&staging_key(&plugin, "cache_status"))
            .unwrap(),
        "BYPASS"
    );

    let mut zero_response_headers = HashMap::new();
    zero_response_headers.insert("cache-control".to_string(), "max-age=0".to_string());
    plugin
        .after_proxy(&mut bypass_ctx, 200, &mut zero_response_headers)
        .await;
    plugin
        .on_final_response_body(&mut bypass_ctx, 200, &zero_response_headers, b"zero")
        .await;

    let mut miss_ctx = make_ctx("GET", "/api/no-cache-zero");
    let mut miss_headers = HashMap::new();
    assert!(matches!(
        plugin.before_proxy(&mut miss_ctx, &mut miss_headers).await,
        PluginResult::Continue
    ));
    let status = miss_ctx
        .metadata
        .get(&staging_key(&plugin, "cache_status"))
        .unwrap();
    assert!(
        status == "MISS" || status == "PREDICTED-BYPASS",
        "expected MISS or PREDICTED-BYPASS after zero-freshness invalidation, got {status}"
    );
}

#[tokio::test]
async fn test_bypassed_zero_freshness_with_new_vary_invalidates_matched_entry() {
    let plugin = default_plugin();
    let path = "/api/no-cache-zero-new-vary";
    let mut resp_headers = HashMap::new();
    resp_headers.insert("cache-control".to_string(), "max-age=60".to_string());
    cache_response(&plugin, "GET", path, 200, &resp_headers, b"cached").await;
    assert!(response_caching_current_total_size_for_test(&plugin) > 0);

    let mut bypass_ctx = make_ctx("GET", path);
    bypass_ctx
        .headers
        .insert("accept-encoding".to_string(), "gzip".to_string());
    bypass_ctx
        .headers
        .insert("cache-control".to_string(), "no-cache".to_string());
    let mut bypass_headers = bypass_ctx.headers.clone();
    assert!(matches!(
        plugin
            .before_proxy(&mut bypass_ctx, &mut bypass_headers)
            .await,
        PluginResult::Continue
    ));
    assert_eq!(
        bypass_ctx
            .metadata
            .get(&staging_key(&plugin, "cache_status"))
            .unwrap(),
        "BYPASS"
    );

    let mut zero_response_headers = HashMap::new();
    zero_response_headers.insert("cache-control".to_string(), "max-age=0".to_string());
    zero_response_headers.insert("vary".to_string(), "Accept-Encoding".to_string());
    plugin
        .after_proxy(&mut bypass_ctx, 200, &mut zero_response_headers)
        .await;
    plugin
        .on_final_response_body(&mut bypass_ctx, 200, &zero_response_headers, b"zero")
        .await;

    assert_eq!(response_caching_current_total_size_for_test(&plugin), 0);
    assert_eq!(assert_size_accounting_exact(&plugin), 0);
}

#[tokio::test]
async fn test_zero_freshness_set_cookie_response_invalidates_existing_entry() {
    let plugin = default_plugin();
    let path = "/api/no-cache-zero-cookie";
    let mut resp_headers = HashMap::new();
    resp_headers.insert("cache-control".to_string(), "max-age=60".to_string());
    cache_response(&plugin, "GET", path, 200, &resp_headers, b"cached").await;
    assert!(response_caching_current_total_size_for_test(&plugin) > 0);

    let mut bypass_ctx = make_ctx("GET", path);
    bypass_ctx
        .headers
        .insert("cache-control".to_string(), "no-cache".to_string());
    let mut bypass_headers = bypass_ctx.headers.clone();
    assert!(matches!(
        plugin
            .before_proxy(&mut bypass_ctx, &mut bypass_headers)
            .await,
        PluginResult::Continue
    ));

    let mut zero_response_headers = HashMap::new();
    zero_response_headers.insert("cache-control".to_string(), "max-age=0".to_string());
    zero_response_headers.insert("set-cookie".to_string(), "sid=rotated".to_string());
    plugin
        .after_proxy(&mut bypass_ctx, 200, &mut zero_response_headers)
        .await;
    plugin
        .on_final_response_body(&mut bypass_ctx, 200, &zero_response_headers, b"zero")
        .await;

    assert_eq!(response_caching_current_total_size_for_test(&plugin), 0);
    assert_eq!(assert_size_accounting_exact(&plugin), 0);
}

#[tokio::test]
async fn test_zero_freshness_auth_rejection_invalidates_existing_entry() {
    let plugin = default_plugin();
    let path = "/api/no-cache-zero-auth";

    let mut cache_ctx = make_ctx("GET", path);
    cache_ctx.authenticated_identity = Some("alice".to_string());
    cache_ctx
        .headers
        .insert("authorization".to_string(), "Bearer token-a".to_string());
    let mut cache_headers = cache_ctx.headers.clone();
    assert!(matches!(
        plugin
            .before_proxy(&mut cache_ctx, &mut cache_headers)
            .await,
        PluginResult::Continue
    ));
    let mut public_response_headers = HashMap::new();
    public_response_headers.insert(
        "cache-control".to_string(),
        "public, max-age=60".to_string(),
    );
    plugin
        .after_proxy(&mut cache_ctx, 200, &mut public_response_headers)
        .await;
    plugin
        .on_final_response_body(&mut cache_ctx, 200, &public_response_headers, b"cached")
        .await;
    assert!(response_caching_current_total_size_for_test(&plugin) > 0);

    let mut bypass_ctx = make_ctx("GET", path);
    bypass_ctx.authenticated_identity = Some("alice".to_string());
    bypass_ctx
        .headers
        .insert("authorization".to_string(), "Bearer token-a".to_string());
    bypass_ctx
        .headers
        .insert("cache-control".to_string(), "no-cache".to_string());
    let mut bypass_headers = bypass_ctx.headers.clone();
    assert!(matches!(
        plugin
            .before_proxy(&mut bypass_ctx, &mut bypass_headers)
            .await,
        PluginResult::Continue
    ));

    let mut zero_response_headers = HashMap::new();
    zero_response_headers.insert("cache-control".to_string(), "max-age=0".to_string());
    plugin
        .after_proxy(&mut bypass_ctx, 200, &mut zero_response_headers)
        .await;
    plugin
        .on_final_response_body(&mut bypass_ctx, 200, &zero_response_headers, b"zero")
        .await;

    assert_eq!(response_caching_current_total_size_for_test(&plugin), 0);
    assert_eq!(assert_size_accounting_exact(&plugin), 0);
}

#[tokio::test]
async fn test_bypassed_fresh_response_clears_stale_predictor() {
    let plugin = default_plugin();

    let mut stale_ctx = make_ctx("GET", "/api/no-cache-refresh");
    let mut stale_request_headers = HashMap::new();
    assert!(matches!(
        plugin
            .before_proxy(&mut stale_ctx, &mut stale_request_headers)
            .await,
        PluginResult::Continue
    ));

    let mut stale_response_headers = HashMap::new();
    stale_response_headers.insert("cache-control".to_string(), "max-age=60".to_string());
    stale_response_headers.insert("age".to_string(), "61".to_string());
    plugin
        .after_proxy(&mut stale_ctx, 200, &mut stale_response_headers)
        .await;
    plugin
        .on_final_response_body(&mut stale_ctx, 200, &stale_response_headers, b"stale")
        .await;

    let mut bypass_ctx = make_ctx("GET", "/api/no-cache-refresh");
    bypass_ctx
        .headers
        .insert("cache-control".to_string(), "no-cache".to_string());
    let mut bypass_headers = HashMap::new();
    bypass_headers.insert("cache-control".to_string(), "no-cache".to_string());
    assert!(matches!(
        plugin
            .before_proxy(&mut bypass_ctx, &mut bypass_headers)
            .await,
        PluginResult::Continue
    ));
    assert_eq!(
        bypass_ctx
            .metadata
            .get(&staging_key(&plugin, "cache_status"))
            .unwrap(),
        "BYPASS"
    );
    assert!(
        bypass_ctx
            .metadata
            .contains_key(&staging_key(&plugin, "cache_predict_key")),
        "client no-cache bypass should preserve the matched cache key for refresh invalidation"
    );

    let mut fresh_response_headers = HashMap::new();
    fresh_response_headers.insert("cache-control".to_string(), "max-age=60".to_string());
    plugin
        .after_proxy(&mut bypass_ctx, 200, &mut fresh_response_headers)
        .await;
    plugin
        .on_final_response_body(&mut bypass_ctx, 200, &fresh_response_headers, b"fresh")
        .await;

    let mut hit_ctx = make_ctx("GET", "/api/no-cache-refresh");
    let mut hit_headers = HashMap::new();
    let (status, body, headers) =
        expect_reject(plugin.before_proxy(&mut hit_ctx, &mut hit_headers).await);
    assert_eq!(status, 200);
    assert_eq!(body, b"fresh");
    assert_eq!(headers.get("x-cache-status"), Some(&"HIT".to_string()));
}

// === Non-cacheable methods ===

#[tokio::test]
async fn test_post_not_cached() {
    let plugin = default_plugin();
    let mut ctx = make_ctx("POST", "/api/data");
    let mut headers = HashMap::new();

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
    assert_eq!(
        ctx.metadata
            .get(&staging_key(&plugin, "cache_status"))
            .unwrap(),
        "BYPASS"
    );
}

#[tokio::test]
async fn test_delete_not_cached() {
    let plugin = default_plugin();
    let mut ctx = make_ctx("DELETE", "/api/data");
    let mut headers = HashMap::new();

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
    assert_eq!(
        ctx.metadata
            .get(&staging_key(&plugin, "cache_status"))
            .unwrap(),
        "BYPASS"
    );
}

// === Non-cacheable status codes ===

#[tokio::test]
async fn test_500_not_cached() {
    let plugin = default_plugin();

    cache_response(
        &plugin,
        "GET",
        "/api/error",
        500,
        &HashMap::new(),
        b"server error",
    )
    .await;

    // Should not be cached
    let mut ctx = make_ctx("GET", "/api/error");
    let mut headers = HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
    assert_eq!(assert_size_accounting_exact(&plugin), 0);
}

// === Cache invalidation on unsafe methods ===

#[tokio::test]
async fn test_post_invalidates_cached_get() {
    let plugin = default_plugin();

    // Cache a GET response
    cache_response(
        &plugin,
        "GET",
        "/api/items",
        200,
        &HashMap::new(),
        b"[\"item1\"]",
    )
    .await;

    // Verify it's cached
    let mut ctx = make_ctx("GET", "/api/items");
    let mut headers = HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(is_reject(&result));

    // POST to the same path should invalidate
    let mut ctx = make_ctx("POST", "/api/items");
    let mut headers = HashMap::new();
    plugin.before_proxy(&mut ctx, &mut headers).await;

    // GET should now be a MISS
    let mut ctx = make_ctx("GET", "/api/items");
    let mut headers = HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
}

#[tokio::test]
async fn test_options_does_not_invalidate_cached_get() {
    let plugin = default_plugin();

    cache_response(
        &plugin,
        "GET",
        "/api/items",
        200,
        &HashMap::new(),
        b"[\"item1\"]",
    )
    .await;

    // OPTIONS is a safe method — it must bypass the cache without invalidating.
    let mut ctx = make_ctx("OPTIONS", "/api/items");
    let mut headers = HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
    assert_eq!(
        ctx.metadata
            .get(&staging_key(&plugin, "cache_status"))
            .unwrap(),
        "BYPASS"
    );

    // GET should still be a HIT — OPTIONS must not have invalidated it.
    let mut ctx = make_ctx("GET", "/api/items");
    let mut headers = HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(is_reject(&result));
}

#[tokio::test]
async fn test_trace_does_not_invalidate_cached_get() {
    let plugin = default_plugin();

    cache_response(
        &plugin,
        "GET",
        "/api/items",
        200,
        &HashMap::new(),
        b"[\"item1\"]",
    )
    .await;

    // TRACE is a safe method — it must bypass the cache without invalidating.
    let mut ctx = make_ctx("TRACE", "/api/items");
    let mut headers = HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
    assert_eq!(
        ctx.metadata
            .get(&staging_key(&plugin, "cache_status"))
            .unwrap(),
        "BYPASS"
    );

    // GET should still be a HIT — TRACE must not have invalidated it.
    let mut ctx = make_ctx("GET", "/api/items");
    let mut headers = HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(is_reject(&result));
}

#[tokio::test]
async fn test_head_non_cacheable_does_not_invalidate_cached_get() {
    // Configure HEAD as non-cacheable (excluded from cacheable_methods).
    let plugin = plugin_with_config(json!({
        "cacheable_methods": ["GET"]
    }));

    cache_response(
        &plugin,
        "GET",
        "/api/items",
        200,
        &HashMap::new(),
        b"[\"item1\"]",
    )
    .await;

    // HEAD is a safe method — even though it is excluded from cacheable_methods,
    // it must bypass the cache without invalidating the cached GET entry.
    let mut ctx = make_ctx("HEAD", "/api/items");
    let mut headers = HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
    assert_eq!(
        ctx.metadata
            .get(&staging_key(&plugin, "cache_status"))
            .unwrap(),
        "BYPASS"
    );

    // GET should still be a HIT — HEAD must not have invalidated it.
    let mut ctx = make_ctx("GET", "/api/items");
    let mut headers = HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(is_reject(&result));
}

#[tokio::test]
async fn test_put_invalidates_cached_get() {
    let plugin = default_plugin();

    cache_response(
        &plugin,
        "GET",
        "/api/items",
        200,
        &HashMap::new(),
        b"[\"item1\"]",
    )
    .await;

    assert!(is_reject(
        plugin
            .before_proxy(&mut make_ctx("GET", "/api/items"), &mut HashMap::new())
            .await,
    ));

    // PUT is unsafe — it must invalidate the cached GET entry.
    plugin
        .before_proxy(&mut make_ctx("PUT", "/api/items"), &mut HashMap::new())
        .await;

    let mut ctx = make_ctx("GET", "/api/items");
    let mut headers = HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
}

#[tokio::test]
async fn test_patch_invalidates_cached_get() {
    let plugin = default_plugin();

    cache_response(
        &plugin,
        "GET",
        "/api/items",
        200,
        &HashMap::new(),
        b"[\"item1\"]",
    )
    .await;

    assert!(is_reject(
        plugin
            .before_proxy(&mut make_ctx("GET", "/api/items"), &mut HashMap::new())
            .await,
    ));

    // PATCH is unsafe — it must invalidate the cached GET entry.
    plugin
        .before_proxy(&mut make_ctx("PATCH", "/api/items"), &mut HashMap::new())
        .await;

    let mut ctx = make_ctx("GET", "/api/items");
    let mut headers = HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
}

#[tokio::test]
async fn test_delete_invalidates_cached_get() {
    let plugin = default_plugin();

    cache_response(
        &plugin,
        "GET",
        "/api/items",
        200,
        &HashMap::new(),
        b"[\"item1\"]",
    )
    .await;

    assert!(is_reject(
        plugin
            .before_proxy(&mut make_ctx("GET", "/api/items"), &mut HashMap::new())
            .await,
    ));

    // DELETE is unsafe — it must invalidate the cached GET entry.
    plugin
        .before_proxy(&mut make_ctx("DELETE", "/api/items"), &mut HashMap::new())
        .await;

    let mut ctx = make_ctx("GET", "/api/items");
    let mut headers = HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
}

#[tokio::test]
async fn test_extension_method_invalidates_cached_get() {
    // Extension methods are treated as unsafe (fail-safe): with no explicit
    // contract declaring them safe, invalidation is the conservative choice.
    let plugin = default_plugin();

    cache_response(
        &plugin,
        "GET",
        "/api/items",
        200,
        &HashMap::new(),
        b"[\"item1\"]",
    )
    .await;

    assert!(is_reject(
        plugin
            .before_proxy(&mut make_ctx("GET", "/api/items"), &mut HashMap::new())
            .await,
    ));

    // PURGE is an extension method not in the safe set — it must invalidate.
    plugin
        .before_proxy(&mut make_ctx("PURGE", "/api/items"), &mut HashMap::new())
        .await;

    let mut ctx = make_ctx("GET", "/api/items");
    let mut headers = HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
}

#[tokio::test]
async fn test_safe_method_bypass_status_is_set() {
    // Safe non-cacheable methods must report BYPASS (not HIT/MISS) and must
    // not leave lookup staging behind.
    let plugin = default_plugin();

    cache_response(
        &plugin,
        "GET",
        "/api/items",
        200,
        &HashMap::new(),
        b"[\"item1\"]",
    )
    .await;

    for method in ["OPTIONS", "TRACE"] {
        let mut ctx = make_ctx(method, "/api/items");
        let mut headers = HashMap::new();
        let result = plugin.before_proxy(&mut ctx, &mut headers).await;
        assert!(
            matches!(result, PluginResult::Continue),
            "{method} should bypass"
        );
        assert_eq!(
            ctx.metadata
                .get(&staging_key(&plugin, "cache_status"))
                .unwrap(),
            "BYPASS",
            "{method} should report BYPASS"
        );
        assert!(
            !ctx.metadata.contains_key(&staging_key(&plugin, "cache_base_key")),
            "{method} must not leave cache_base_key staging behind"
        );
    }

    // GET should still be a HIT.
    let mut ctx = make_ctx("GET", "/api/items");
    let mut headers = HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(is_reject(&result));
}

// === Max entry size ===

#[tokio::test]
async fn test_max_entry_size_exceeded() {
    let plugin = plugin_with_config(json!({
        "max_entry_size_bytes": 10  // Very small
    }));

    cache_response(
        &plugin,
        "GET",
        "/api/large",
        200,
        &HashMap::new(),
        b"this response is way too large for the cache",
    )
    .await;

    // Should not be cached
    let mut ctx = make_ctx("GET", "/api/large");
    let mut headers = HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
}

// === Max entries eviction ===

#[tokio::test]
async fn test_max_entries_eviction() {
    let plugin = plugin_with_config(json!({
        "max_entries": 2,
        "ttl_seconds": 3600
    }));

    // Cache 3 entries (max is 2, so oldest should be evicted)
    for i in 0..3 {
        let path = format!("/api/item/{}", i);
        cache_response(
            &plugin,
            "GET",
            &path,
            200,
            &HashMap::new(),
            format!("data-{}", i).as_bytes(),
        )
        .await;
    }

    // The third entry should be cached
    let mut ctx = make_ctx("GET", "/api/item/2");
    let mut headers = HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(is_reject(&result));
    assert!(assert_size_accounting_exact(&plugin) > 0);
}

// === Vary header ===

#[tokio::test]
async fn test_vary_by_headers() {
    let plugin = plugin_with_config(json!({
        "vary_by_headers": ["accept"]
    }));

    // Cache JSON response
    let mut ctx = make_ctx("GET", "/api/data");
    ctx.headers
        .insert("accept".to_string(), "application/json".to_string());
    ctx.matched_proxy = Some(std::sync::Arc::new(create_test_proxy()));
    let mut headers = HashMap::new();
    headers.insert("accept".to_string(), "application/json".to_string());
    plugin.before_proxy(&mut ctx, &mut headers).await;
    let mut resp_headers = HashMap::new();
    resp_headers.insert("content-type".to_string(), "application/json".to_string());
    plugin.after_proxy(&mut ctx, 200, &mut resp_headers).await;
    plugin
        .on_final_response_body(&mut ctx, 200, &resp_headers, b"{\"json\":true}")
        .await;

    // Cache XML response (different Accept header = different cache key)
    let mut ctx2 = make_ctx("GET", "/api/data");
    ctx2.headers
        .insert("accept".to_string(), "application/xml".to_string());
    ctx2.matched_proxy = Some(std::sync::Arc::new(create_test_proxy()));
    let mut headers2 = HashMap::new();
    headers2.insert("accept".to_string(), "application/xml".to_string());
    plugin.before_proxy(&mut ctx2, &mut headers2).await;
    let mut resp_headers2 = HashMap::new();
    resp_headers2.insert("content-type".to_string(), "application/xml".to_string());
    plugin.after_proxy(&mut ctx2, 200, &mut resp_headers2).await;
    plugin
        .on_final_response_body(&mut ctx2, 200, &resp_headers2, b"<xml/>")
        .await;

    // JSON accept should get JSON response
    let mut ctx_json = make_ctx("GET", "/api/data");
    ctx_json
        .headers
        .insert("accept".to_string(), "application/json".to_string());
    let mut h = HashMap::new();
    h.insert("accept".to_string(), "application/json".to_string());
    let (_, body, _) = expect_reject(plugin.before_proxy(&mut ctx_json, &mut h).await);
    assert_eq!(body, b"{\"json\":true}");

    // XML accept should get XML response
    let mut ctx_xml = make_ctx("GET", "/api/data");
    ctx_xml
        .headers
        .insert("accept".to_string(), "application/xml".to_string());
    let mut h2 = HashMap::new();
    h2.insert("accept".to_string(), "application/xml".to_string());
    let (_, body, _) = expect_reject(plugin.before_proxy(&mut ctx_xml, &mut h2).await);
    assert_eq!(body, b"<xml/>");
}

#[tokio::test]
async fn test_backend_vary_accept_encoding_caches_binary_variant() {
    let plugin = default_plugin();
    let compressed = vec![0x1f, 0x8b, 0x08, 0x00, 0x00, 0xff];

    let mut ctx = make_ctx("GET", "/assets/app.js");
    ctx.headers
        .insert("accept-encoding".to_string(), "gzip".to_string());
    let mut headers = HashMap::new();
    headers.insert("accept-encoding".to_string(), "gzip".to_string());
    plugin.before_proxy(&mut ctx, &mut headers).await;

    let mut response_headers = HashMap::new();
    response_headers.insert("content-encoding".to_string(), "gzip".to_string());
    response_headers.insert("vary".to_string(), "Accept-Encoding".to_string());
    plugin
        .after_proxy(&mut ctx, 200, &mut response_headers)
        .await;
    plugin
        .on_final_response_body(&mut ctx, 200, &response_headers, &compressed)
        .await;

    let mut gzip_ctx = make_ctx("GET", "/assets/app.js");
    gzip_ctx
        .headers
        .insert("accept-encoding".to_string(), "gzip".to_string());
    let mut gzip_headers = HashMap::new();
    gzip_headers.insert("accept-encoding".to_string(), "gzip".to_string());
    let (status_code, body, headers) =
        expect_reject(plugin.before_proxy(&mut gzip_ctx, &mut gzip_headers).await);
    assert_eq!(status_code, 200);
    assert_eq!(body, compressed);
    assert_eq!(headers.get("content-encoding"), Some(&"gzip".to_string()));
    assert_eq!(headers.get("x-cache-status"), Some(&"HIT".to_string()));

    let mut plain_ctx = make_ctx("GET", "/assets/app.js");
    let mut plain_headers = HashMap::new();
    let miss = plugin
        .before_proxy(&mut plain_ctx, &mut plain_headers)
        .await;
    assert!(matches!(miss, PluginResult::Continue));
}

#[tokio::test]
async fn test_vary_wildcard_not_cached() {
    let plugin = default_plugin();
    let mut response_headers = HashMap::new();
    response_headers.insert("vary".to_string(), "*".to_string());

    cache_response(
        &plugin,
        "GET",
        "/api/data",
        200,
        &response_headers,
        b"volatile",
    )
    .await;

    let mut ctx = make_ctx("GET", "/api/data");
    let mut headers = HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
}

#[tokio::test]
async fn test_stale_on_arrival_does_not_evict_other_vary_variants() {
    let plugin = default_plugin();
    let path = "/api/stale-vary";

    let mut gzip_ctx = make_ctx("GET", path);
    gzip_ctx
        .headers
        .insert("accept-encoding".to_string(), "gzip".to_string());
    let mut gzip_headers = HashMap::new();
    gzip_headers.insert("accept-encoding".to_string(), "gzip".to_string());
    assert!(matches!(
        plugin.before_proxy(&mut gzip_ctx, &mut gzip_headers).await,
        PluginResult::Continue
    ));
    let mut gzip_response_headers = HashMap::new();
    gzip_response_headers.insert("cache-control".to_string(), "max-age=60".to_string());
    gzip_response_headers.insert("vary".to_string(), "Accept-Encoding".to_string());
    plugin
        .after_proxy(&mut gzip_ctx, 200, &mut gzip_response_headers)
        .await;
    plugin
        .on_final_response_body(&mut gzip_ctx, 200, &gzip_response_headers, b"gzip")
        .await;

    let mut br_ctx = make_ctx("GET", path);
    br_ctx
        .headers
        .insert("accept-encoding".to_string(), "br".to_string());
    let mut br_headers = HashMap::new();
    br_headers.insert("accept-encoding".to_string(), "br".to_string());
    assert!(matches!(
        plugin.before_proxy(&mut br_ctx, &mut br_headers).await,
        PluginResult::Continue
    ));
    let mut br_response_headers = HashMap::new();
    br_response_headers.insert("cache-control".to_string(), "max-age=60".to_string());
    br_response_headers.insert("vary".to_string(), "Accept-Encoding".to_string());
    br_response_headers.insert("age".to_string(), "61".to_string());
    plugin
        .after_proxy(&mut br_ctx, 200, &mut br_response_headers)
        .await;
    plugin
        .on_final_response_body(&mut br_ctx, 200, &br_response_headers, b"br")
        .await;

    let mut gzip_hit_ctx = make_ctx("GET", path);
    gzip_hit_ctx
        .headers
        .insert("accept-encoding".to_string(), "gzip".to_string());
    let mut gzip_hit_headers = HashMap::new();
    gzip_hit_headers.insert("accept-encoding".to_string(), "gzip".to_string());
    let (status, body, _) = expect_reject(
        plugin
            .before_proxy(&mut gzip_hit_ctx, &mut gzip_hit_headers)
            .await,
    );
    assert_eq!(status, 200);
    assert_eq!(body, b"gzip");
}

#[tokio::test]
async fn test_zero_freshness_invalidates_only_matching_vary_variant() {
    let plugin = default_plugin();
    let path = "/api/zero-vary";

    let mut gzip_ctx = make_ctx("GET", path);
    gzip_ctx
        .headers
        .insert("accept-encoding".to_string(), "gzip".to_string());
    let mut gzip_headers = HashMap::new();
    gzip_headers.insert("accept-encoding".to_string(), "gzip".to_string());
    assert!(matches!(
        plugin.before_proxy(&mut gzip_ctx, &mut gzip_headers).await,
        PluginResult::Continue
    ));
    let mut gzip_response_headers = HashMap::new();
    gzip_response_headers.insert("cache-control".to_string(), "max-age=60".to_string());
    gzip_response_headers.insert("vary".to_string(), "Accept-Encoding".to_string());
    plugin
        .after_proxy(&mut gzip_ctx, 200, &mut gzip_response_headers)
        .await;
    plugin
        .on_final_response_body(&mut gzip_ctx, 200, &gzip_response_headers, b"gzip")
        .await;

    let mut br_ctx = make_ctx("GET", path);
    br_ctx
        .headers
        .insert("accept-encoding".to_string(), "br".to_string());
    let mut br_headers = HashMap::new();
    br_headers.insert("accept-encoding".to_string(), "br".to_string());
    assert!(matches!(
        plugin.before_proxy(&mut br_ctx, &mut br_headers).await,
        PluginResult::Continue
    ));
    let mut br_response_headers = HashMap::new();
    br_response_headers.insert("cache-control".to_string(), "max-age=60".to_string());
    br_response_headers.insert("vary".to_string(), "Accept-Encoding".to_string());
    plugin
        .after_proxy(&mut br_ctx, 200, &mut br_response_headers)
        .await;
    plugin
        .on_final_response_body(&mut br_ctx, 200, &br_response_headers, b"br")
        .await;

    let mut br_bypass_ctx = make_ctx("GET", path);
    br_bypass_ctx
        .headers
        .insert("accept-encoding".to_string(), "br".to_string());
    br_bypass_ctx
        .headers
        .insert("cache-control".to_string(), "no-cache".to_string());
    let mut br_bypass_headers = HashMap::new();
    br_bypass_headers.insert("accept-encoding".to_string(), "br".to_string());
    br_bypass_headers.insert("cache-control".to_string(), "no-cache".to_string());
    assert!(matches!(
        plugin
            .before_proxy(&mut br_bypass_ctx, &mut br_bypass_headers)
            .await,
        PluginResult::Continue
    ));
    let mut zero_response_headers = HashMap::new();
    zero_response_headers.insert("cache-control".to_string(), "max-age=0".to_string());
    zero_response_headers.insert("vary".to_string(), "Accept-Encoding".to_string());
    plugin
        .after_proxy(&mut br_bypass_ctx, 200, &mut zero_response_headers)
        .await;
    plugin
        .on_final_response_body(&mut br_bypass_ctx, 200, &zero_response_headers, b"zero")
        .await;

    let mut gzip_hit_ctx = make_ctx("GET", path);
    gzip_hit_ctx
        .headers
        .insert("accept-encoding".to_string(), "gzip".to_string());
    let mut gzip_hit_headers = HashMap::new();
    gzip_hit_headers.insert("accept-encoding".to_string(), "gzip".to_string());
    let (status, body, _) = expect_reject(
        plugin
            .before_proxy(&mut gzip_hit_ctx, &mut gzip_hit_headers)
            .await,
    );
    assert_eq!(status, 200);
    assert_eq!(body, b"gzip");

    let mut br_miss_ctx = make_ctx("GET", path);
    br_miss_ctx
        .headers
        .insert("accept-encoding".to_string(), "br".to_string());
    let mut br_miss_headers = HashMap::new();
    br_miss_headers.insert("accept-encoding".to_string(), "br".to_string());
    assert!(matches!(
        plugin
            .before_proxy(&mut br_miss_ctx, &mut br_miss_headers)
            .await,
        PluginResult::Continue
    ));
    let status = br_miss_ctx
        .metadata
        .get(&staging_key(&plugin, "cache_status"))
        .unwrap();
    assert!(
        status == "MISS" || status == "PREDICTED-BYPASS",
        "expected MISS or PREDICTED-BYPASS after zero-freshness invalidation, got {status}"
    );
}

#[tokio::test]
async fn test_if_none_match_returns_304_from_cache() {
    let plugin = default_plugin();
    let mut response_headers = HashMap::new();
    response_headers.insert("etag".to_string(), r#"W/"abc123""#.to_string());
    response_headers.insert("cache-control".to_string(), "max-age=60".to_string());
    response_headers.insert("age".to_string(), "4".to_string());

    cache_response(
        &plugin,
        "GET",
        "/api/data",
        200,
        &response_headers,
        b"cached-body",
    )
    .await;
    advance_response_caching_clock_for_test(&plugin, std::time::Duration::from_secs(5));

    let mut ctx = make_ctx("GET", "/api/data");
    ctx.headers
        .insert("if-none-match".to_string(), r#""abc123""#.to_string());
    let mut headers = HashMap::new();
    headers.insert("if-none-match".to_string(), r#""abc123""#.to_string());
    let (status_code, body, headers) =
        expect_reject(plugin.before_proxy(&mut ctx, &mut headers).await);
    assert_eq!(status_code, 304);
    assert!(body.is_empty());
    assert_eq!(headers.get("etag"), Some(&r#"W/"abc123""#.to_string()));
    let age = cached_age(&headers);
    assert!(
        (9..60).contains(&age),
        "local 304 should include current Age, got {age}"
    );
    assert_eq!(
        headers.get("x-cache-status"),
        Some(&"REVALIDATED".to_string())
    );
}

#[tokio::test]
async fn test_authorization_response_not_shared_cached_without_public() {
    let plugin = default_plugin();
    let mut ctx = make_ctx("GET", "/api/private");
    ctx.headers
        .insert("authorization".to_string(), "Bearer token-a".to_string());
    let mut headers = HashMap::new();
    plugin.before_proxy(&mut ctx, &mut headers).await;

    let mut response_headers = HashMap::new();
    response_headers.insert("cache-control".to_string(), "max-age=60".to_string());
    plugin
        .after_proxy(&mut ctx, 200, &mut response_headers)
        .await;
    plugin
        .on_final_response_body(&mut ctx, 200, &response_headers, b"user-a")
        .await;

    let mut second_ctx = make_ctx("GET", "/api/private");
    second_ctx
        .headers
        .insert("authorization".to_string(), "Bearer token-a".to_string());
    let mut second_headers = HashMap::new();
    let result = plugin
        .before_proxy(&mut second_ctx, &mut second_headers)
        .await;
    assert!(matches!(result, PluginResult::Continue));
}

#[tokio::test]
async fn test_authorization_response_with_public_can_be_cached() {
    let plugin = default_plugin();
    let mut ctx = make_ctx("GET", "/api/public-auth");
    ctx.headers
        .insert("authorization".to_string(), "Bearer token-a".to_string());
    let mut headers = HashMap::new();
    headers.insert("authorization".to_string(), "Bearer token-a".to_string());
    plugin.before_proxy(&mut ctx, &mut headers).await;

    let mut response_headers = HashMap::new();
    response_headers.insert(
        "cache-control".to_string(),
        "public, max-age=60".to_string(),
    );
    plugin
        .after_proxy(&mut ctx, 200, &mut response_headers)
        .await;
    plugin
        .on_final_response_body(&mut ctx, 200, &response_headers, b"shared")
        .await;

    // Second request from the SAME bearer token must hit. The plugin auto-merges
    // `authorization` into the Vary list when caching authorized responses, so
    // the second lookup must present the same Authorization value to land on the
    // same cache entry.
    let mut second_ctx = make_ctx("GET", "/api/public-auth");
    second_ctx
        .headers
        .insert("authorization".to_string(), "Bearer token-a".to_string());
    let mut second_headers = HashMap::new();
    second_headers.insert("authorization".to_string(), "Bearer token-a".to_string());
    let (_, body, response_headers) = expect_reject(
        plugin
            .before_proxy(&mut second_ctx, &mut second_headers)
            .await,
    );
    assert_eq!(body, b"shared");
    // The cached response surfaces the auto-merged `Vary: authorization` so
    // downstream caches/clients honor the same dimension.
    let vary = response_headers
        .get("vary")
        .expect("Vary header should be present on cached authorized response");
    assert!(
        vary.split(',')
            .map(str::trim)
            .any(|h| h.eq_ignore_ascii_case("authorization")),
        "expected `Vary` to include `authorization`, got `{}`",
        vary
    );
}

#[tokio::test]
async fn test_identity_without_authorization_header_not_cached_in_shared_cache() {
    let plugin = default_plugin();

    let mut ctx = make_ctx("GET", "/api/private");
    ctx.identified_consumer = Some(Arc::new(make_consumer("a", "alice")));
    let mut headers = HashMap::new();
    headers.insert("x-api-key".to_string(), "alice-key".to_string());
    plugin.before_proxy(&mut ctx, &mut headers).await;

    let mut response_headers = HashMap::new();
    plugin
        .after_proxy(&mut ctx, 200, &mut response_headers)
        .await;
    plugin
        .on_final_response_body(&mut ctx, 200, &response_headers, b"alice-private")
        .await;

    let mut second_ctx = make_ctx("GET", "/api/private");
    second_ctx.identified_consumer = Some(Arc::new(make_consumer("b", "bob")));
    let mut second_headers = HashMap::new();
    second_headers.insert("x-api-key".to_string(), "bob-key".to_string());
    let result = plugin
        .before_proxy(&mut second_ctx, &mut second_headers)
        .await;
    assert!(matches!(result, PluginResult::Continue));
}

/// finding #1: an API-key-authenticated principal (gateway Consumer, no
/// `Authorization` header) whose backend marks the response `Cache-Control:
/// public` must NOT have that per-user response served to a different
/// principal. Before the fix the principal was absent from the cache key
/// (default `cache_key_include_consumer: false`, only `authorization`
/// auto-varied), so Bob received Alice's private body on a HIT.
#[tokio::test]
async fn test_apikey_principal_public_response_not_cross_served() {
    let plugin = default_plugin();

    let mut public_response = HashMap::new();
    public_response.insert(
        "cache-control".to_string(),
        "public, max-age=60".to_string(),
    );

    // Alice authenticates via API key and the backend returns a per-user
    // `public` response that gets cached.
    let mut ctx_alice = make_ctx("GET", "/api/profile");
    ctx_alice.identified_consumer = Some(Arc::new(make_consumer("a", "alice")));
    ctx_alice
        .headers
        .insert("x-api-key".to_string(), "alice-key".to_string());
    let mut h_alice = ctx_alice.headers.clone();
    assert!(matches!(
        plugin.before_proxy(&mut ctx_alice, &mut h_alice).await,
        PluginResult::Continue
    ));
    plugin
        .on_final_response_body(&mut ctx_alice, 200, &public_response, b"alice-private")
        .await;

    // Bob presents a different API key for the same route -> MUST miss.
    let mut ctx_bob = make_ctx("GET", "/api/profile");
    ctx_bob.identified_consumer = Some(Arc::new(make_consumer("b", "bob")));
    ctx_bob
        .headers
        .insert("x-api-key".to_string(), "bob-key".to_string());
    let mut h_bob = ctx_bob.headers.clone();
    assert!(
        matches!(
            plugin.before_proxy(&mut ctx_bob, &mut h_bob).await,
            PluginResult::Continue
        ),
        "Bob must not be served Alice's per-principal `public` response"
    );

    // Alice again -> HIT with her own body (entry is keyed per-principal, not
    // suppressed entirely).
    let mut ctx_alice2 = make_ctx("GET", "/api/profile");
    ctx_alice2.identified_consumer = Some(Arc::new(make_consumer("a", "alice")));
    ctx_alice2
        .headers
        .insert("x-api-key".to_string(), "alice-key".to_string());
    let mut h_alice2 = ctx_alice2.headers.clone();
    let (_, body, _) = expect_reject(plugin.before_proxy(&mut ctx_alice2, &mut h_alice2).await);
    assert_eq!(body, b"alice-private");
}

/// finding #1: same cross-principal isolation guarantee for an external
/// identity surfaced via `authenticated_identity` (e.g. an mTLS SPIFFE ID or
/// a JWT carried in a custom header), which also has no `Authorization`
/// header.
#[tokio::test]
async fn test_external_identity_public_response_not_cross_served() {
    let plugin = default_plugin();

    let mut public_response = HashMap::new();
    public_response.insert(
        "cache-control".to_string(),
        "public, max-age=60".to_string(),
    );

    let mut ctx_a = make_ctx("GET", "/api/profile");
    ctx_a.authenticated_identity = Some("spiffe://example.org/ns/team/sa/alice".to_string());
    let mut h_a = ctx_a.headers.clone();
    plugin.before_proxy(&mut ctx_a, &mut h_a).await;
    plugin
        .on_final_response_body(&mut ctx_a, 200, &public_response, b"alice-private")
        .await;

    let mut ctx_b = make_ctx("GET", "/api/profile");
    ctx_b.authenticated_identity = Some("spiffe://example.org/ns/team/sa/bob".to_string());
    let mut h_b = ctx_b.headers.clone();
    assert!(
        matches!(
            plugin.before_proxy(&mut ctx_b, &mut h_b).await,
            PluginResult::Continue
        ),
        "a different external identity must not hit the first principal's entry"
    );

    let mut ctx_a2 = make_ctx("GET", "/api/profile");
    ctx_a2.authenticated_identity = Some("spiffe://example.org/ns/team/sa/alice".to_string());
    let mut h_a2 = ctx_a2.headers.clone();
    let (_, body, _) = expect_reject(plugin.before_proxy(&mut ctx_a2, &mut h_a2).await);
    assert_eq!(body, b"alice-private");
}

/// finding #15: a `Cookie`-bearing request with no authenticated identity must
/// vary by the cookie so distinct sessions never share a cached `public`
/// response, even when the backend forgets `Vary: Cookie` and emits no
/// `Set-Cookie`.
#[tokio::test]
async fn test_cookie_bearing_request_not_cross_served_across_sessions() {
    let plugin = default_plugin();

    let mut public_response = HashMap::new();
    public_response.insert(
        "cache-control".to_string(),
        "public, max-age=60".to_string(),
    );

    // Session "alice" caches a per-session public response.
    let mut ctx_a = make_ctx("GET", "/dashboard");
    ctx_a
        .headers
        .insert("cookie".to_string(), "session=alice".to_string());
    let mut h_a = ctx_a.headers.clone();
    plugin.before_proxy(&mut ctx_a, &mut h_a).await;
    plugin
        .on_final_response_body(&mut ctx_a, 200, &public_response, b"alice-dashboard")
        .await;

    // A different session cookie -> MISS.
    let mut ctx_b = make_ctx("GET", "/dashboard");
    ctx_b
        .headers
        .insert("cookie".to_string(), "session=bob".to_string());
    let mut h_b = ctx_b.headers.clone();
    assert!(
        matches!(
            plugin.before_proxy(&mut ctx_b, &mut h_b).await,
            PluginResult::Continue
        ),
        "a different session cookie must not hit another session's cached response"
    );

    // Same session cookie -> HIT with its own body.
    let mut ctx_a2 = make_ctx("GET", "/dashboard");
    ctx_a2
        .headers
        .insert("cookie".to_string(), "session=alice".to_string());
    let mut h_a2 = ctx_a2.headers.clone();
    let (_, body, _) = expect_reject(plugin.before_proxy(&mut ctx_a2, &mut h_a2).await);
    assert_eq!(body, b"alice-dashboard");
}

#[tokio::test]
async fn test_cookie_request_does_not_hit_preexisting_anonymous_entry() {
    let plugin = default_plugin();

    let mut public_response = HashMap::new();
    public_response.insert(
        "cache-control".to_string(),
        "public, max-age=60".to_string(),
    );

    let mut anonymous_ctx = make_ctx("GET", "/dashboard");
    let mut anonymous_headers = HashMap::new();
    plugin
        .before_proxy(&mut anonymous_ctx, &mut anonymous_headers)
        .await;
    plugin
        .on_final_response_body(&mut anonymous_ctx, 200, &public_response, b"anon-dashboard")
        .await;

    let mut cookie_ctx = make_ctx("GET", "/dashboard");
    cookie_ctx
        .headers
        .insert("cookie".to_string(), "session=alice".to_string());
    let mut cookie_headers = cookie_ctx.headers.clone();
    assert!(
        matches!(
            plugin
                .before_proxy(&mut cookie_ctx, &mut cookie_headers)
                .await,
            PluginResult::Continue
        ),
        "cookie-bearing request must not hit the unvaried anonymous entry"
    );
}

#[tokio::test]
async fn test_anonymous_store_preserves_existing_cookie_vary_dimension() {
    let plugin = default_plugin();

    let mut public_response = HashMap::new();
    public_response.insert(
        "cache-control".to_string(),
        "public, max-age=60".to_string(),
    );

    let mut cookie_ctx = make_ctx("GET", "/dashboard");
    cookie_ctx
        .headers
        .insert("cookie".to_string(), "session=alice".to_string());
    let mut cookie_headers = cookie_ctx.headers.clone();
    plugin
        .before_proxy(&mut cookie_ctx, &mut cookie_headers)
        .await;
    plugin
        .on_final_response_body(&mut cookie_ctx, 200, &public_response, b"alice-dashboard")
        .await;

    let mut anonymous_ctx = make_ctx("GET", "/dashboard");
    let mut anonymous_headers = HashMap::new();
    assert!(matches!(
        plugin
            .before_proxy(&mut anonymous_ctx, &mut anonymous_headers)
            .await,
        PluginResult::Continue
    ));
    plugin
        .on_final_response_body(&mut anonymous_ctx, 200, &public_response, b"anon-dashboard")
        .await;

    let mut cookie_ctx_2 = make_ctx("GET", "/dashboard");
    cookie_ctx_2
        .headers
        .insert("cookie".to_string(), "session=alice".to_string());
    let mut cookie_headers_2 = cookie_ctx_2.headers.clone();
    let (_, body, _) = expect_reject(
        plugin
            .before_proxy(&mut cookie_ctx_2, &mut cookie_headers_2)
            .await,
    );
    assert_eq!(body, b"alice-dashboard");

    let mut anonymous_ctx_2 = make_ctx("GET", "/dashboard");
    let mut anonymous_headers_2 = HashMap::new();
    let (_, body, response_headers) = expect_reject(
        plugin
            .before_proxy(&mut anonymous_ctx_2, &mut anonymous_headers_2)
            .await,
    );
    assert_eq!(body, b"anon-dashboard");
    assert!(
        response_headers
            .get("vary")
            .is_some_and(|vary| vary.split(',').map(str::trim).any(|h| h == "cookie")),
        "anonymous variant should keep the sticky cookie Vary dimension"
    );
}

#[tokio::test]
async fn test_sensitive_header_snapshot_does_not_store_raw_session_headers() {
    let plugin = default_plugin();

    let mut public_response = HashMap::new();
    public_response.insert(
        "cache-control".to_string(),
        "public, max-age=60".to_string(),
    );

    let cookie = "session=alice; csrf=raw-secret";
    let proxy_auth = "Basic cHJveHk6c2VjcmV0";

    let mut ctx = make_ctx("GET", "/dashboard");
    ctx.headers.insert("cookie".to_string(), cookie.to_string());
    ctx.headers
        .insert("proxy-authorization".to_string(), proxy_auth.to_string());
    let mut headers = ctx.headers.clone();

    assert!(matches!(
        plugin.before_proxy(&mut ctx, &mut headers).await,
        PluginResult::Continue
    ));

    let snapshot = ctx
        .metadata
        .get(&staging_key(&plugin, "cache_request_headers_snapshot"))
        .expect("cache header snapshot should be stashed");
    assert!(snapshot.contains("cookie"));
    assert!(snapshot.contains("proxy-authorization"));
    assert!(snapshot.contains("sha256-"));
    assert!(!snapshot.contains(cookie));
    assert!(!snapshot.contains(proxy_auth));
    assert!(!snapshot.contains("raw-secret"));

    let log_metadata = clone_log_metadata(&ctx);
    let log_metadata_json = serde_json::to_string(&log_metadata).unwrap();
    assert!(!log_metadata_json.contains(cookie));
    assert!(!log_metadata_json.contains(proxy_auth));
    assert!(!log_metadata_json.contains("raw-secret"));

    plugin
        .on_final_response_body(&mut ctx, 200, &public_response, b"alice-dashboard")
        .await;

    let mut same_ctx = make_ctx("GET", "/dashboard");
    same_ctx
        .headers
        .insert("cookie".to_string(), cookie.to_string());
    same_ctx
        .headers
        .insert("proxy-authorization".to_string(), proxy_auth.to_string());
    let mut same_headers = same_ctx.headers.clone();
    let (_, body, _) = expect_reject(plugin.before_proxy(&mut same_ctx, &mut same_headers).await);
    assert_eq!(body, b"alice-dashboard");
}

#[tokio::test]
async fn test_sensitive_configured_vary_header_snapshot_hashes_without_breaking_hits() {
    let plugin = plugin_with_config(json!({
        "vary_by_headers": ["x-api-key"]
    }));

    let mut public_response = HashMap::new();
    public_response.insert(
        "cache-control".to_string(),
        "public, max-age=60".to_string(),
    );

    let api_key = "raw-api-key-secret";
    let mut ctx = make_ctx("GET", "/api/keyed");
    ctx.headers
        .insert("x-api-key".to_string(), api_key.to_string());
    let mut headers = ctx.headers.clone();
    plugin.before_proxy(&mut ctx, &mut headers).await;

    let snapshot = ctx
        .metadata
        .get(&staging_key(&plugin, "cache_request_headers_snapshot"))
        .expect("cache header snapshot should be stashed");
    assert!(snapshot.contains("x-api-key"));
    assert!(snapshot.contains("sha256-"));
    assert!(!snapshot.contains(api_key));

    plugin
        .on_final_response_body(&mut ctx, 200, &public_response, b"keyed")
        .await;

    let mut same_ctx = make_ctx("GET", "/api/keyed");
    same_ctx
        .headers
        .insert("x-api-key".to_string(), api_key.to_string());
    let mut same_headers = same_ctx.headers.clone();
    let (_, body, _) = expect_reject(plugin.before_proxy(&mut same_ctx, &mut same_headers).await);
    assert_eq!(body, b"keyed");

    let mut other_ctx = make_ctx("GET", "/api/keyed");
    other_ctx
        .headers
        .insert("x-api-key".to_string(), "other-api-key".to_string());
    let mut other_headers = other_ctx.headers.clone();
    assert!(matches!(
        plugin
            .before_proxy(&mut other_ctx, &mut other_headers)
            .await,
        PluginResult::Continue
    ));
}

// === X-Cache-Status header ===

#[tokio::test]
async fn test_x_cache_status_miss_header() {
    let plugin = default_plugin();
    let mut ctx = make_ctx("GET", "/api/data");
    let mut headers = HashMap::new();
    plugin.before_proxy(&mut ctx, &mut headers).await;

    let mut resp_headers = HashMap::new();
    plugin.after_proxy(&mut ctx, 200, &mut resp_headers).await;

    assert_eq!(resp_headers.get("x-cache-status").unwrap(), "MISS");
}

#[tokio::test]
async fn test_x_cache_status_disabled() {
    let plugin = plugin_with_config(json!({
        "add_cache_status_header": false
    }));

    let mut ctx = make_ctx("GET", "/api/data");
    let mut headers = HashMap::new();
    plugin.before_proxy(&mut ctx, &mut headers).await;

    let mut resp_headers = HashMap::new();
    plugin.after_proxy(&mut ctx, 200, &mut resp_headers).await;

    assert!(!resp_headers.contains_key("x-cache-status"));
}

// === Consumer-keyed caching ===

#[tokio::test]
async fn test_consumer_keyed_caching() {
    let plugin = plugin_with_config(json!({
        "cache_key_include_consumer": true
    }));

    // Cache response for user A
    let mut ctx_a = make_ctx("GET", "/api/data");
    ctx_a.identified_consumer = Some(Arc::new(make_consumer("a", "alice")));
    let mut h = HashMap::new();
    plugin.before_proxy(&mut ctx_a, &mut h).await;
    let mut rh = HashMap::new();
    plugin.after_proxy(&mut ctx_a, 200, &mut rh).await;
    plugin
        .on_final_response_body(&mut ctx_a, 200, &rh, b"alice-data")
        .await;

    // User B should get a MISS (different consumer = different cache key)
    let mut ctx_b = make_ctx("GET", "/api/data");
    ctx_b.identified_consumer = Some(Arc::new(make_consumer("b", "bob")));
    let mut h2 = HashMap::new();
    let result = plugin.before_proxy(&mut ctx_b, &mut h2).await;
    assert!(matches!(result, PluginResult::Continue));

    // User A should get a HIT
    let mut ctx_a2 = make_ctx("GET", "/api/data");
    ctx_a2.identified_consumer = Some(Arc::new(make_consumer("a", "alice")));
    let mut h3 = HashMap::new();
    let (_, body, _) = expect_reject(plugin.before_proxy(&mut ctx_a2, &mut h3).await);
    assert_eq!(body, b"alice-data");
}

#[tokio::test]
async fn test_consumer_keyed_caching_uses_authenticated_identity_fallback() {
    let plugin = plugin_with_config(json!({
        "cache_key_include_consumer": true
    }));

    let mut ctx_external = make_ctx("GET", "/api/data");
    ctx_external.authenticated_identity = Some("oidc-alice".to_string());
    let mut headers = HashMap::new();
    plugin.before_proxy(&mut ctx_external, &mut headers).await;
    let mut response_headers = HashMap::new();
    plugin
        .after_proxy(&mut ctx_external, 200, &mut response_headers)
        .await;
    plugin
        .on_final_response_body(&mut ctx_external, 200, &response_headers, b"alice-data")
        .await;

    let mut ctx_other = make_ctx("GET", "/api/data");
    ctx_other.authenticated_identity = Some("oidc-bob".to_string());
    let mut miss_headers = HashMap::new();
    let miss = plugin.before_proxy(&mut ctx_other, &mut miss_headers).await;
    assert!(matches!(miss, PluginResult::Continue));

    let mut ctx_external_again = make_ctx("GET", "/api/data");
    ctx_external_again.authenticated_identity = Some("oidc-alice".to_string());
    let mut hit_headers = HashMap::new();
    let (_, body, _) = expect_reject(
        plugin
            .before_proxy(&mut ctx_external_again, &mut hit_headers)
            .await,
    );
    assert_eq!(body, b"alice-data");
}

// === Query string caching ===

#[tokio::test]
async fn test_different_raw_queries_different_cache() {
    let plugin = default_plugin();

    // Cache response for ?page=1
    let mut ctx1 = make_ctx_with_query("GET", "/api/items", &[("page", "1")]);
    ctx1.matched_proxy = Some(std::sync::Arc::new(create_test_proxy()));
    let mut h = HashMap::new();
    plugin.before_proxy(&mut ctx1, &mut h).await;
    let mut rh = HashMap::new();
    plugin.after_proxy(&mut ctx1, 200, &mut rh).await;
    plugin
        .on_final_response_body(&mut ctx1, 200, &rh, b"page-1-data")
        .await;

    // ?page=2 should be a MISS
    let mut ctx2 = make_ctx_with_query("GET", "/api/items", &[("page", "2")]);
    ctx2.matched_proxy = Some(std::sync::Arc::new(create_test_proxy()));
    let mut h2 = HashMap::new();
    let result = plugin.before_proxy(&mut ctx2, &mut h2).await;
    assert!(matches!(result, PluginResult::Continue));

    // ?page=1 should be a HIT
    let mut ctx3 = make_ctx_with_query("GET", "/api/items", &[("page", "1")]);
    ctx3.matched_proxy = Some(std::sync::Arc::new(create_test_proxy()));
    let mut h3 = HashMap::new();
    let (_, body, _) = expect_reject(plugin.before_proxy(&mut ctx3, &mut h3).await);
    assert_eq!(body, b"page-1-data");
}

// === Query-insensitive caching ===

#[tokio::test]
async fn test_query_excluded_from_cache_key() {
    let plugin = plugin_with_config(json!({
        "cache_key_include_query": false
    }));

    // Cache with ?page=1
    let mut ctx1 = make_ctx_with_query("GET", "/api/items", &[("page", "1")]);
    ctx1.matched_proxy = Some(std::sync::Arc::new(create_test_proxy()));
    let mut h = HashMap::new();
    plugin.before_proxy(&mut ctx1, &mut h).await;
    let mut rh = HashMap::new();
    plugin.after_proxy(&mut ctx1, 200, &mut rh).await;
    plugin
        .on_final_response_body(&mut ctx1, 200, &rh, b"same-data")
        .await;

    // ?page=2 should be a HIT (query excluded from key)
    let mut ctx2 = make_ctx_with_query("GET", "/api/items", &[("page", "2")]);
    ctx2.matched_proxy = Some(std::sync::Arc::new(create_test_proxy()));
    let mut h2 = HashMap::new();
    let result = plugin.before_proxy(&mut ctx2, &mut h2).await;
    assert!(is_reject(&result));
}

// === HEAD method cacheable ===

#[tokio::test]
async fn test_head_method_cacheable() {
    let plugin = default_plugin();

    cache_response(&plugin, "HEAD", "/api/data", 200, &HashMap::new(), b"").await;

    let mut ctx = make_ctx("HEAD", "/api/data");
    let mut headers = HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(is_reject(&result));
}

// === respect_cache_control disabled ===

#[tokio::test]
async fn test_respect_cache_control_disabled() {
    let plugin = plugin_with_config(json!({
        "respect_cache_control": false,
        "ttl_seconds": 3600
    }));

    // Even with no-store, response should be cached when respect_cache_control=false
    let mut resp_headers = HashMap::new();
    resp_headers.insert("cache-control".to_string(), "no-store".to_string());

    cache_response(
        &plugin,
        "GET",
        "/api/data",
        200,
        &resp_headers,
        b"should be cached",
    )
    .await;

    let mut ctx = make_ctx("GET", "/api/data");
    let mut headers = HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(is_reject(&result));
}

// === Cache-Control: no-cache response not cached ===

#[tokio::test]
async fn test_cache_control_no_cache_response() {
    let plugin = default_plugin();

    let mut resp_headers = HashMap::new();
    resp_headers.insert("cache-control".to_string(), "no-cache".to_string());

    cache_response(
        &plugin,
        "GET",
        "/api/volatile",
        200,
        &resp_headers,
        b"volatile data",
    )
    .await;

    // Should not be cached (no-cache means always revalidate)
    let mut ctx = make_ctx("GET", "/api/volatile");
    let mut headers = HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
}

// === 301 and 404 cacheable by default ===

#[tokio::test]
async fn test_301_cacheable() {
    let plugin = default_plugin();

    cache_response(&plugin, "GET", "/old-path", 301, &HashMap::new(), b"").await;

    let mut ctx = make_ctx("GET", "/old-path");
    let mut headers = HashMap::new();
    let (status_code, _, _) = expect_reject(plugin.before_proxy(&mut ctx, &mut headers).await);
    assert_eq!(status_code, 301);
}

#[tokio::test]
async fn test_404_cacheable() {
    let plugin = default_plugin();

    cache_response(
        &plugin,
        "GET",
        "/not-found",
        404,
        &HashMap::new(),
        b"not found",
    )
    .await;

    let mut ctx = make_ctx("GET", "/not-found");
    let mut headers = HashMap::new();
    let (status_code, _, _) = expect_reject(plugin.before_proxy(&mut ctx, &mut headers).await);
    assert_eq!(status_code, 404);
}

// === Invalidation disabled ===

#[tokio::test]
async fn test_invalidation_disabled() {
    let plugin = plugin_with_config(json!({
        "invalidate_on_unsafe_methods": false
    }));

    cache_response(&plugin, "GET", "/api/items", 200, &HashMap::new(), b"items").await;

    // POST should NOT invalidate when disabled
    let mut ctx = make_ctx("POST", "/api/items");
    let mut headers = HashMap::new();
    plugin.before_proxy(&mut ctx, &mut headers).await;

    // GET should still be a HIT
    let mut ctx = make_ctx("GET", "/api/items");
    let mut headers = HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(is_reject(&result));
}

// === Max total size ===

#[tokio::test]
async fn test_max_total_size_exceeded() {
    let plugin = plugin_with_config(json!({
        "max_total_size_bytes": 300,
        "max_entry_size_bytes": 1048576
    }));

    // Cache a response that takes up most of the total size
    // Each entry is ~200 bytes body + ~64 bytes overhead = ~264 bytes
    cache_response(&plugin, "GET", "/api/a", 200, &HashMap::new(), &[b'x'; 200]).await;

    // This should fail to cache (would exceed 300-byte total size)
    cache_response(&plugin, "GET", "/api/b", 200, &HashMap::new(), &[b'y'; 200]).await;

    // First should be cached
    let mut ctx = make_ctx("GET", "/api/a");
    let mut headers = HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(is_reject(&result));

    // Second should NOT be cached (total size exceeded)
    let mut ctx = make_ctx("GET", "/api/b");
    let mut headers = HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
    assert!(assert_size_accounting_exact(&plugin) <= 300);
}

#[tokio::test]
async fn test_replacement_admission_uses_size_delta() {
    let plugin = plugin_with_config(json!({
        "max_total_size_bytes": 450,
        "max_entry_size_bytes": 1048576
    }));

    cache_response(
        &plugin,
        "GET",
        "/api/replacement-delta",
        200,
        &HashMap::new(),
        &[b'a'; 200],
    )
    .await;
    assert!(assert_size_accounting_exact(&plugin) <= 450);

    replace_cached_response(
        &plugin,
        "GET",
        "/api/replacement-delta",
        200,
        &HashMap::new(),
        &[b'b'; 300],
    )
    .await;

    let mut ctx = make_ctx("GET", "/api/replacement-delta");
    let mut headers = HashMap::new();
    let (_, body, _) = expect_reject(plugin.before_proxy(&mut ctx, &mut headers).await);
    assert_eq!(
        body,
        vec![b'b'; 300],
        "replacement should be admitted when only the positive size delta fits"
    );
    assert!(assert_size_accounting_exact(&plugin) <= 450);
}

#[tokio::test]
async fn test_large_to_small_replacement_releases_capacity() {
    let plugin = plugin_with_config(json!({
        "max_total_size_bytes": 430,
        "max_entry_size_bytes": 1048576
    }));

    cache_response(
        &plugin,
        "GET",
        "/api/replacement-shrink",
        200,
        &HashMap::new(),
        &[b'a'; 300],
    )
    .await;
    assert!(assert_size_accounting_exact(&plugin) <= 430);

    replace_cached_response(
        &plugin,
        "GET",
        "/api/replacement-shrink",
        200,
        &HashMap::new(),
        &[b'b'; 20],
    )
    .await;

    let mut ctx = make_ctx("GET", "/api/replacement-shrink");
    let mut headers = HashMap::new();
    let (_, body, _) = expect_reject(plugin.before_proxy(&mut ctx, &mut headers).await);
    assert_eq!(
        body,
        vec![b'b'; 20],
        "smaller replacement should be admitted even when old+new would exceed the cap"
    );
    assert!(assert_size_accounting_exact(&plugin) <= 430);
}

#[tokio::test]
async fn test_rejected_replacement_preserves_old_entry_and_accounting() {
    let plugin = plugin_with_config(json!({
        "max_total_size_bytes": 450,
        "max_entry_size_bytes": 1048576
    }));

    cache_response(
        &plugin,
        "GET",
        "/api/replacement-reject",
        200,
        &HashMap::new(),
        &[b'a'; 200],
    )
    .await;
    let before = assert_size_accounting_exact(&plugin);

    replace_cached_response(
        &plugin,
        "GET",
        "/api/replacement-reject",
        200,
        &HashMap::new(),
        &[b'b'; 1024],
    )
    .await;

    let mut ctx = make_ctx("GET", "/api/replacement-reject");
    let mut headers = HashMap::new();
    let (_, body, _) = expect_reject(plugin.before_proxy(&mut ctx, &mut headers).await);
    assert_eq!(
        body,
        vec![b'a'; 200],
        "oversize replacement must leave the prior cached entry intact"
    );
    assert_eq!(assert_size_accounting_exact(&plugin), before);
}

#[tokio::test]
async fn test_total_size_limit_uses_saturating_add() {
    // Verify that the total size check doesn't overflow when current_total is
    // near usize::MAX. The fix uses saturating_add to prevent wrapping around
    // to a small number that would bypass the size limit check.
    //
    // We can't directly set the internal total_size counter, but we verify
    // that the cache respects max_total_size_bytes by checking that entries
    // that would exceed the limit are rejected. This validates the comparison
    // logic path that now uses saturating_add.
    let plugin = plugin_with_config(json!({
        "ttl_seconds": 60,
        "max_total_size_bytes": 1, // Extremely small limit
    }));

    // Cache a response that will exceed the 1-byte limit
    cache_response(
        &plugin,
        "GET",
        "/api/overflow",
        200,
        &HashMap::new(),
        b"this body is much larger than 1 byte",
    )
    .await;

    // Should NOT be cached (entry_size > max_total_size_bytes)
    let mut ctx = make_ctx("GET", "/api/overflow");
    let mut headers = HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(
        matches!(result, PluginResult::Continue),
        "Entry exceeding max_total_size_bytes should not be cached"
    );
    assert_eq!(
        ctx.metadata
            .get(&staging_key(&plugin, "cache_status"))
            .unwrap(),
        "MISS"
    );
}

// === Set-Cookie safety ===

#[tokio::test]
async fn test_set_cookie_response_not_cached() {
    let plugin = default_plugin();

    // Cache a response that contains Set-Cookie
    let mut response_headers = HashMap::new();
    response_headers.insert("content-type".to_string(), "application/json".to_string());
    response_headers.insert(
        "set-cookie".to_string(),
        "session=abc123; Path=/; HttpOnly".to_string(),
    );

    cache_response(
        &plugin,
        "GET",
        "/api/login",
        200,
        &response_headers,
        b"user-specific-data",
    )
    .await;

    // Second request should be a MISS — Set-Cookie responses must not be cached
    let mut ctx = make_ctx("GET", "/api/login");
    let mut headers = HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(
        matches!(result, PluginResult::Continue),
        "Response with Set-Cookie header must not be cached"
    );
    let status = ctx
        .metadata
        .get(&staging_key(&plugin, "cache_status"))
        .unwrap()
        .as_str();
    assert!(
        status == "MISS" || status == "PREDICTED-BYPASS",
        "expected MISS or PREDICTED-BYPASS, got {status}"
    );
}

#[tokio::test]
async fn test_response_without_set_cookie_still_cached() {
    let plugin = default_plugin();

    let mut response_headers = HashMap::new();
    response_headers.insert("content-type".to_string(), "application/json".to_string());

    cache_response(
        &plugin,
        "GET",
        "/api/public",
        200,
        &response_headers,
        b"public-data",
    )
    .await;

    // Second request should be a HIT — no Set-Cookie, normal caching
    let mut ctx = make_ctx("GET", "/api/public");
    let mut headers = HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(
        is_reject(&result),
        "Response without Set-Cookie should be cached normally"
    );
}

// === Auto-Vary on Authorization (RFC 7234 §3.2 cross-user leak fix) ===

#[tokio::test]
async fn test_authorization_auto_vary_isolates_users() {
    // Two users hit the same `public, max-age=...` resource with different
    // bearer tokens. Without the auto-Vary fix, User B would receive User A's
    // cached payload. With the fix, the cache is keyed by the Authorization
    // value so each user gets their own entry.
    let plugin = default_plugin();

    // User A: cache `user-a-data` under `Authorization: Bearer A`.
    let mut ctx_a = make_ctx("GET", "/api/me/data");
    ctx_a
        .headers
        .insert("authorization".to_string(), "Bearer A".to_string());
    let mut headers_a = HashMap::new();
    headers_a.insert("authorization".to_string(), "Bearer A".to_string());
    plugin.before_proxy(&mut ctx_a, &mut headers_a).await;

    let mut response_headers_a = HashMap::new();
    response_headers_a.insert(
        "cache-control".to_string(),
        "public, max-age=300".to_string(),
    );
    plugin
        .after_proxy(&mut ctx_a, 200, &mut response_headers_a)
        .await;
    plugin
        .on_final_response_body(&mut ctx_a, 200, &response_headers_a, b"user-a-data")
        .await;

    // User B presents a DIFFERENT bearer token on the same path. Without the
    // fix this would return User A's cached body (cross-user leak); with the
    // fix it must be a cache MISS because the auto-Vary on `authorization`
    // makes the cache key user-specific.
    let mut ctx_b = make_ctx("GET", "/api/me/data");
    ctx_b
        .headers
        .insert("authorization".to_string(), "Bearer B".to_string());
    let mut headers_b = HashMap::new();
    headers_b.insert("authorization".to_string(), "Bearer B".to_string());
    let result_b = plugin.before_proxy(&mut ctx_b, &mut headers_b).await;
    assert!(
        matches!(result_b, PluginResult::Continue),
        "User B with different bearer token must NOT receive User A's cached response"
    );

    // User A re-issuing the same request with the same token must still HIT.
    let mut ctx_a2 = make_ctx("GET", "/api/me/data");
    ctx_a2
        .headers
        .insert("authorization".to_string(), "Bearer A".to_string());
    let mut headers_a2 = HashMap::new();
    headers_a2.insert("authorization".to_string(), "Bearer A".to_string());
    let (_, body, response_headers) =
        expect_reject(plugin.before_proxy(&mut ctx_a2, &mut headers_a2).await);
    assert_eq!(
        body, b"user-a-data",
        "User A with the same bearer token must still receive their cached response"
    );
    // Cached response surfaces auto-merged `Vary: authorization`.
    let vary = response_headers
        .get("vary")
        .expect("Vary header should be present on cached authorized response");
    assert!(
        vary.split(',')
            .map(str::trim)
            .any(|h| h.eq_ignore_ascii_case("authorization")),
        "expected `Vary` to include `authorization`, got `{}`",
        vary
    );
}

#[tokio::test]
async fn test_no_authorization_no_auto_vary() {
    // When the request has no Authorization header, the plugin must NOT
    // auto-add `authorization` to the cached response's Vary list — the
    // existing behavior (cache hit on identical anonymous request) is
    // preserved.
    let plugin = default_plugin();

    cache_response(
        &plugin,
        "GET",
        "/api/anon",
        200,
        &HashMap::new(),
        b"anon-data",
    )
    .await;

    let mut ctx = make_ctx("GET", "/api/anon");
    let mut headers = HashMap::new();
    let (_, body, response_headers) =
        expect_reject(plugin.before_proxy(&mut ctx, &mut headers).await);
    assert_eq!(body, b"anon-data");
    // No Vary header should have been auto-added (vary_headers list was empty
    // and the request had no Authorization, so the auto-merge branch did not
    // fire).
    let vary_lower = response_headers.get("vary").map(|v| v.to_ascii_lowercase());
    if let Some(vary) = vary_lower {
        assert!(
            !vary.contains("authorization"),
            "Vary must NOT include `authorization` when request had no Authorization header, got `{}`",
            vary
        );
    }
}

// === Host included in base cache key (multi-host proxy isolation) ===

#[tokio::test]
async fn test_different_host_headers_different_cache_keys() {
    // A multi-host proxy (`hosts: ["a.example.com", "b.example.com"]`) shares
    // the same `proxy_id`. Without including Host in the cache key, the two
    // hosts collide and a response cached under host A is served to clients
    // addressing host B.
    let plugin = default_plugin();

    // Cache a response from host A.
    let mut ctx_a = make_ctx("GET", "/api/data");
    ctx_a
        .headers
        .insert("host".to_string(), "a.example.com".to_string());
    let mut headers_a = HashMap::new();
    headers_a.insert("host".to_string(), "a.example.com".to_string());
    plugin.before_proxy(&mut ctx_a, &mut headers_a).await;
    let mut response_headers_a = HashMap::new();
    plugin
        .after_proxy(&mut ctx_a, 200, &mut response_headers_a)
        .await;
    plugin
        .on_final_response_body(&mut ctx_a, 200, &response_headers_a, b"a-data")
        .await;

    // A request to host B on the same path must MISS — different host =
    // different cache key, no cross-host pollution.
    let mut ctx_b = make_ctx("GET", "/api/data");
    ctx_b
        .headers
        .insert("host".to_string(), "b.example.com".to_string());
    let mut headers_b = HashMap::new();
    headers_b.insert("host".to_string(), "b.example.com".to_string());
    let result_b = plugin.before_proxy(&mut ctx_b, &mut headers_b).await;
    assert!(
        matches!(result_b, PluginResult::Continue),
        "Different Host header must NOT hit cache stored under another host"
    );

    // Re-issuing the original host request must still HIT.
    let mut ctx_a2 = make_ctx("GET", "/api/data");
    ctx_a2
        .headers
        .insert("host".to_string(), "a.example.com".to_string());
    let mut headers_a2 = HashMap::new();
    headers_a2.insert("host".to_string(), "a.example.com".to_string());
    let (_, body, _) = expect_reject(plugin.before_proxy(&mut ctx_a2, &mut headers_a2).await);
    assert_eq!(body, b"a-data");
}

#[tokio::test]
async fn test_host_header_case_insensitive_in_cache_key() {
    // Per RFC 9110 §4.2.3 the host component is case-insensitive. The base
    // key normalizes ASCII case so `A.Example.COM` and `a.example.com`
    // collapse to the same cache entry.
    let plugin = default_plugin();

    let mut ctx_upper = make_ctx("GET", "/api/data");
    ctx_upper
        .headers
        .insert("host".to_string(), "A.Example.COM".to_string());
    let mut headers_upper = HashMap::new();
    headers_upper.insert("host".to_string(), "A.Example.COM".to_string());
    plugin
        .before_proxy(&mut ctx_upper, &mut headers_upper)
        .await;
    let mut resp = HashMap::new();
    plugin.after_proxy(&mut ctx_upper, 200, &mut resp).await;
    plugin
        .on_final_response_body(&mut ctx_upper, 200, &resp, b"host-data")
        .await;

    let mut ctx_lower = make_ctx("GET", "/api/data");
    ctx_lower
        .headers
        .insert("host".to_string(), "a.example.com".to_string());
    let mut headers_lower = HashMap::new();
    headers_lower.insert("host".to_string(), "a.example.com".to_string());
    let (_, body, _) = expect_reject(
        plugin
            .before_proxy(&mut ctx_lower, &mut headers_lower)
            .await,
    );
    assert_eq!(body, b"host-data");
}

// === SSE bypass ===

#[tokio::test]
async fn test_sse_request_skips_response_buffering() {
    // When the client requests SSE via `Accept: text/event-stream`, the
    // response body MUST NOT be buffered — buffering an unbounded event
    // stream collects frames forever and 502s once the
    // FERRUM_MAX_RESPONSE_BODY_SIZE_BYTES ceiling is hit.
    let plugin = default_plugin();
    assert!(plugin.requires_response_body_buffering());

    let mut ctx = make_ctx("GET", "/events");
    ctx.headers
        .insert("accept".to_string(), "text/event-stream".to_string());

    assert!(!plugin.should_buffer_response_body(&ctx));
}

#[tokio::test]
async fn test_sse_request_bypasses_preexisting_cached_response() {
    let plugin = default_plugin();
    let mut resp_headers = HashMap::new();
    resp_headers.insert("content-type".to_string(), "application/json".to_string());

    cache_response(
        &plugin,
        "GET",
        "/events",
        200,
        &resp_headers,
        b"{\"cached\":true}",
    )
    .await;

    let mut cached_ctx = make_ctx("GET", "/events");
    let mut cached_headers = HashMap::new();
    assert!(is_reject(
        &plugin
            .before_proxy(&mut cached_ctx, &mut cached_headers)
            .await
    ));

    let mut sse_ctx = make_ctx("GET", "/events");
    let mut sse_headers = HashMap::new();
    sse_headers.insert("accept".to_string(), "text/event-stream".to_string());

    let result = plugin.before_proxy(&mut sse_ctx, &mut sse_headers).await;
    assert!(matches!(result, PluginResult::Continue));
    assert_eq!(
        sse_ctx
            .metadata
            .get(&staging_key(&plugin, "cache_status"))
            .unwrap(),
        "BYPASS"
    );
    assert!(
        !sse_ctx
            .metadata
            .contains_key(&staging_key(&plugin, "cache_base_key"))
    );

    let mut bypass_headers = HashMap::new();
    plugin
        .after_proxy(&mut sse_ctx, 200, &mut bypass_headers)
        .await;
    assert_eq!(bypass_headers.get("x-cache-status").unwrap(), "BYPASS");
}

#[tokio::test]
async fn test_non_sse_request_still_buffers() {
    // Plain JSON requests must still take the buffered/cacheable path.
    let plugin = default_plugin();

    let mut ctx = make_ctx("GET", "/api/data");
    ctx.headers
        .insert("accept".to_string(), "application/json".to_string());

    assert!(plugin.should_buffer_response_body(&ctx));
}

#[tokio::test]
async fn test_sse_in_accept_list_skips_buffering() {
    // EventSource clients send `Accept: text/event-stream` but other clients
    // may include it as one of several alternatives. Any presence of SSE in
    // the Accept list signals streaming intent.
    let plugin = default_plugin();

    let mut ctx = make_ctx("GET", "/events");
    ctx.headers.insert(
        "accept".to_string(),
        "text/html, text/event-stream;q=0.9, */*".to_string(),
    );

    assert!(!plugin.should_buffer_response_body(&ctx));
}

/// Finding #61: conditional-request HTTP-date parsing must accept all three
/// RFC 9110 §5.6.7 formats, not just RFC 2822 / IMF-fixdate. Before the fix the
/// obsolete RFC 850 and asctime forms returned `None`, which made
/// `If-Modified-Since` revalidation silently serve a full 200 from cache.
#[test]
fn test_parse_http_date_accepts_all_rfc9110_formats() {
    use ferrum_edge::_test_support::response_caching_parse_http_date as parse;

    // All three forms encode the same instant: 1994-11-06 08:49:37 UTC.
    let expected = chrono::DateTime::parse_from_rfc3339("1994-11-06T08:49:37Z")
        .unwrap()
        .with_timezone(&Utc);

    // IMF-fixdate (the dominant, already-supported form).
    assert_eq!(
        parse("Sun, 06 Nov 1994 08:49:37 GMT"),
        Some(expected),
        "IMF-fixdate must parse"
    );
    // RFC 850 (obsolete): full weekday, 2-digit dashed year.
    assert_eq!(
        parse("Sunday, 06-Nov-94 08:49:37 GMT"),
        Some(expected),
        "RFC 850 date must parse"
    );
    // asctime (obsolete): no commas, space-padded day, trailing year.
    assert_eq!(
        parse("Sun Nov  6 08:49:37 1994"),
        Some(expected),
        "asctime date must parse"
    );

    // Genuinely malformed input still yields None.
    assert_eq!(parse("not a date"), None);
    assert_eq!(parse(""), None);
}

/// Finding #62: cache-size subtraction must be underflow-safe. A drift larger
/// than the current total previously wrapped a `usize` to ~`usize::MAX`, which
/// permanently wedged the size cap (every later store was rejected). The
/// saturating subtraction floors at 0 instead.
#[test]
fn test_sub_total_size_saturates_instead_of_wrapping() {
    use ferrum_edge::_test_support::response_caching_sub_total_size as sub;
    use std::sync::atomic::{AtomicUsize, Ordering};

    let total = AtomicUsize::new(100);

    // Subtracting more than the current total must floor at 0, not wrap.
    sub(&total, 250);
    assert_eq!(
        total.load(Ordering::Relaxed),
        0,
        "underflow must saturate at 0, not wrap to usize::MAX"
    );

    // Subtracting from 0 stays at 0.
    sub(&total, 10);
    assert_eq!(total.load(Ordering::Relaxed), 0);

    // Normal subtraction still works.
    total.store(100, Ordering::Relaxed);
    sub(&total, 40);
    assert_eq!(total.load(Ordering::Relaxed), 60);
}

/// Finding #62: under many concurrent stores plus interleaved invalidations
/// the size accountant must never exceed the configured `max_total_size_bytes`
/// and must match the actual retained entry sizes.
#[tokio::test]
async fn test_concurrent_stores_keep_size_bounded_and_non_wrapping() {
    let plugin = Arc::new(
        ResponseCaching::new(&json!({
            "ttl_seconds": 60,
            // Small cap so concurrent stores actively race the ceiling check.
            "max_total_size_bytes": 4096,
            "max_entries": 64
        }))
        .expect("config should be valid"),
    );

    let mut response_headers = HashMap::new();
    response_headers.insert("content-type".to_string(), "application/json".to_string());

    let mut tasks = Vec::new();
    for n in 0..64u32 {
        let plugin = Arc::clone(&plugin);
        let response_headers = response_headers.clone();
        tasks.push(tokio::spawn(async move {
            // A bounded set of paths so stores, replacements, and unsafe-method
            // invalidations all collide on the same keys.
            let path = format!("/api/item-{}", n % 16);
            let body = vec![b'x'; 512];
            cache_response(&plugin, "GET", &path, 200, &response_headers, &body).await;

            // Interleave an invalidation via an unsafe method on the same path.
            let mut inv_ctx = make_ctx("POST", &path);
            let mut inv_headers = HashMap::new();
            let _ = plugin.before_proxy(&mut inv_ctx, &mut inv_headers).await;
        }));
    }
    for task in tasks {
        task.await.expect("store task panicked");
    }

    // The byte cap is an exact upper bound, not a per-worker or approximate
    // target, and the tracked total must match the actual retained entries.
    let total = response_caching_current_total_size_for_test(&plugin);
    let (tracked, actual) = response_caching_size_accounting_snapshot_for_test(&plugin);
    assert_eq!(
        tracked, actual,
        "tracked total must match actual retained entry sizes"
    );
    assert!(
        total <= 4096,
        "total_size exceeded configured max_total_size_bytes: {total}"
    );
}

// === Multi-instance request-staging isolation (#2605) ===

fn public_response_headers() -> HashMap<String, String> {
    let mut headers = HashMap::new();
    headers.insert(
        "cache-control".to_string(),
        "public, max-age=60".to_string(),
    );
    headers
}

async fn run_two_instance_store_isolation(a_first: bool) {
    let query_instance = plugin_with_config(json!({
        "ttl_seconds": 60,
        "cache_key_include_query": true,
        "cache_key_include_consumer": false,
        "vary_by_headers": [],
        "cacheable_methods": ["GET", "HEAD"],
        "cacheable_status_codes": [200],
        "add_cache_status_header": true
    }));
    let consumer_vary_instance = plugin_with_config(json!({
        "ttl_seconds": 60,
        "cache_key_include_query": false,
        "cache_key_include_consumer": true,
        "vary_by_headers": ["x-tenant"],
        "cacheable_methods": ["GET", "HEAD", "POST"],
        "cacheable_status_codes": [200, 404],
        "add_cache_status_header": true
    }));

    assert_ne!(
        response_caching_instance_id_for_test(&query_instance),
        response_caching_instance_id_for_test(&consumer_vary_instance),
        "each response_caching constructor must mint a distinct staging namespace"
    );

    let (first, second) = if a_first {
        (&query_instance, &consumer_vary_instance)
    } else {
        (&consumer_vary_instance, &query_instance)
    };

    let mut ctx = make_ctx_with_raw_query("GET", "/catalog", "sku=1&color=red");
    ctx.identified_consumer = Some(Arc::new(make_consumer("c-1", "alice")));
    ctx.headers
        .insert("x-tenant".to_string(), "acme".to_string());
    let mut headers = ctx.headers.clone();

    assert!(matches!(
        first.before_proxy(&mut ctx, &mut headers).await,
        PluginResult::Continue
    ));
    assert!(matches!(
        second.before_proxy(&mut ctx, &mut headers).await,
        PluginResult::Continue
    ));

    assert_status(first, &ctx, "MISS");
    assert_status(second, &ctx, "MISS");

    let first_base = ctx
        .metadata
        .get(&staging_key(first, "cache_base_key"))
        .cloned()
        .expect("first instance staged base key");
    let second_base = ctx
        .metadata
        .get(&staging_key(second, "cache_base_key"))
        .cloned()
        .expect("second instance staged base key");
    assert_ne!(
        first_base, second_base,
        "distinct query/consumer/Vary policies must stage independent base keys"
    );
    assert_ne!(
        staging_key(first, "cache_status"),
        staging_key(second, "cache_status")
    );
    assert!(
        ctx.metadata.contains_key(&staging_key(
            &consumer_vary_instance,
            "cache_request_headers_snapshot"
        )),
        "Vary-aware instance must stash its own header snapshot"
    );

    let response_headers = public_response_headers();
    first
        .on_final_response_body(&mut ctx, 200, &response_headers, b"first-body")
        .await;
    second
        .on_final_response_body(&mut ctx, 200, &response_headers, b"second-body")
        .await;

    // Replay against each instance independently: each must HIT from the
    // entry it stored under its own staging snapshot / key policy.
    let mut replay = make_ctx_with_raw_query("GET", "/catalog", "sku=1&color=red");
    replay.identified_consumer = Some(Arc::new(make_consumer("c-1", "alice")));
    replay
        .headers
        .insert("x-tenant".to_string(), "acme".to_string());
    let mut replay_headers = replay.headers.clone();
    let first_hit = first.before_proxy(&mut replay, &mut replay_headers).await;
    match first_hit {
        PluginResult::RejectBinary {
            status_code, body, ..
        } => {
            assert_eq!(status_code, 200);
            assert_eq!(&body[..], b"first-body");
        }
        other => panic!("first instance should HIT its own entry, got {other:?}"),
    }
    assert_status(first, &replay, "HIT");

    let mut replay2 = make_ctx_with_raw_query("GET", "/catalog", "sku=1&color=red");
    replay2.identified_consumer = Some(Arc::new(make_consumer("c-1", "alice")));
    replay2
        .headers
        .insert("x-tenant".to_string(), "acme".to_string());
    let mut replay2_headers = replay2.headers.clone();
    let second_hit = second
        .before_proxy(&mut replay2, &mut replay2_headers)
        .await;
    match second_hit {
        PluginResult::RejectBinary {
            status_code, body, ..
        } => {
            assert_eq!(status_code, 200);
            assert_eq!(&body[..], b"second-body");
        }
        other => panic!("second instance should HIT its own entry, got {other:?}"),
    }
    assert_status(second, &replay2, "HIT");
}

#[tokio::test]
async fn multiple_instances_isolate_staging_in_both_priority_orders() {
    run_two_instance_store_isolation(true).await;
    run_two_instance_store_isolation(false).await;
}

#[tokio::test]
async fn later_sibling_without_lookup_state_cannot_overwrite_hit_header() {
    let hit_instance = plugin_with_config(json!({
        "ttl_seconds": 60,
        "add_cache_status_header": true
    }));
    let unvisited_sibling = plugin_with_config(json!({
        "ttl_seconds": 60,
        "add_cache_status_header": true
    }));

    let mut store_ctx = make_ctx("GET", "/header-owner");
    let mut store_headers = HashMap::new();
    assert!(matches!(
        hit_instance
            .before_proxy(&mut store_ctx, &mut store_headers)
            .await,
        PluginResult::Continue
    ));
    let response_headers = public_response_headers();
    hit_instance
        .on_final_response_body(&mut store_ctx, 200, &response_headers, b"cached")
        .await;

    let mut hit_ctx = make_ctx("GET", "/header-owner");
    let mut hit_headers = HashMap::new();
    let PluginResult::RejectBinary { mut headers, .. } = hit_instance
        .before_proxy(&mut hit_ctx, &mut hit_headers)
        .await
    else {
        panic!("first instance must serve the cached response");
    };
    assert_eq!(
        headers.get("x-cache-status").map(String::as_str),
        Some("HIT")
    );
    assert!(ferrum_edge::_test_support::response_cache_hit_for_test(
        &hit_ctx
    ));

    assert!(matches!(
        unvisited_sibling
            .after_proxy(&mut hit_ctx, 200, &mut headers)
            .await,
        PluginResult::Continue
    ));
    assert_eq!(
        headers.get("x-cache-status").map(String::as_str),
        Some("HIT"),
        "an unvisited sibling must not synthesize MISS over the cache owner"
    );
    assert!(
        !hit_ctx
            .metadata
            .contains_key(&staging_key(&unvisited_sibling, "cache_status")),
        "the later sibling must remain without instance-private lookup state"
    );
}

#[tokio::test]
async fn global_hit_signal_is_monotonic_across_sibling_statuses() {
    let hit_instance = plugin_with_config(json!({"ttl_seconds": 60}));
    let miss_instance = plugin_with_config(json!({"ttl_seconds": 60}));

    let mut store_ctx = make_ctx("GET", "/global-hit");
    let mut headers = HashMap::new();
    assert!(matches!(
        hit_instance
            .before_proxy(&mut store_ctx, &mut headers)
            .await,
        PluginResult::Continue
    ));
    hit_instance
        .on_final_response_body(&mut store_ctx, 200, &public_response_headers(), b"cached")
        .await;

    let mut ctx = make_ctx("GET", "/global-hit");
    let mut headers = HashMap::new();
    assert!(matches!(
        hit_instance.before_proxy(&mut ctx, &mut headers).await,
        PluginResult::RejectBinary { .. }
    ));
    assert!(ferrum_edge::_test_support::response_cache_hit_for_test(
        &ctx
    ));

    let mut sibling_headers = HashMap::new();
    assert!(matches!(
        miss_instance
            .before_proxy(&mut ctx, &mut sibling_headers)
            .await,
        PluginResult::Continue
    ));
    assert_status(&miss_instance, &ctx, "MISS");
    assert!(
        ferrum_edge::_test_support::response_cache_hit_for_test(&ctx),
        "a sibling MISS must not clear the request-global HIT signal"
    );
}

#[tokio::test]
async fn multiple_instances_method_and_sse_bypass_clear_only_own_staging() {
    let cacheable = plugin_with_config(json!({
        "ttl_seconds": 60,
        "cacheable_methods": ["GET"],
        "cacheable_status_codes": [200]
    }));
    let method_only_head = plugin_with_config(json!({
        "ttl_seconds": 60,
        "cacheable_methods": ["HEAD"],
        "invalidate_on_unsafe_methods": false
    }));

    // Order A then B: cacheable stages, then method-bypass sibling.
    let mut ctx = make_ctx("GET", "/mixed-method");
    let mut headers = HashMap::new();
    assert!(matches!(
        cacheable.before_proxy(&mut ctx, &mut headers).await,
        PluginResult::Continue
    ));
    assert_status(&cacheable, &ctx, "MISS");
    assert!(
        ctx.metadata
            .contains_key(&staging_key(&cacheable, "cache_base_key"))
    );

    assert!(matches!(
        method_only_head.before_proxy(&mut ctx, &mut headers).await,
        PluginResult::Continue
    ));
    assert_status(&method_only_head, &ctx, "BYPASS");
    assert!(
        !ctx.metadata
            .contains_key(&staging_key(&method_only_head, "cache_base_key"))
    );
    assert_status(&cacheable, &ctx, "MISS");
    assert!(
        ctx.metadata
            .contains_key(&staging_key(&cacheable, "cache_base_key"))
    );

    // Reverse order: method bypass first, then cacheable stages.
    let mut ctx = make_ctx("GET", "/mixed-method-rev");
    let mut headers = HashMap::new();
    assert!(matches!(
        method_only_head.before_proxy(&mut ctx, &mut headers).await,
        PluginResult::Continue
    ));
    assert_status(&method_only_head, &ctx, "BYPASS");
    assert!(matches!(
        cacheable.before_proxy(&mut ctx, &mut headers).await,
        PluginResult::Continue
    ));
    assert_status(&cacheable, &ctx, "MISS");
    assert!(
        ctx.metadata
            .contains_key(&staging_key(&cacheable, "cache_base_key"))
    );
    assert_status(&method_only_head, &ctx, "BYPASS");

    // SSE bypass after a staged miss must not wipe the sibling's staging.
    let sse_peer = plugin_with_config(json!({
        "ttl_seconds": 60,
        "cacheable_methods": ["GET", "POST"]
    }));
    let mut ctx = make_ctx("GET", "/mixed-sse");
    let mut headers = HashMap::new();
    assert!(matches!(
        cacheable.before_proxy(&mut ctx, &mut headers).await,
        PluginResult::Continue
    ));
    let staged_base = ctx
        .metadata
        .get(&staging_key(&cacheable, "cache_base_key"))
        .cloned();
    headers.insert("accept".to_string(), "text/event-stream".to_string());
    assert!(matches!(
        sse_peer.before_proxy(&mut ctx, &mut headers).await,
        PluginResult::Continue
    ));
    assert_status(&sse_peer, &ctx, "BYPASS");
    assert_eq!(
        ctx.metadata
            .get(&staging_key(&cacheable, "cache_base_key"))
            .cloned(),
        staged_base
    );
    assert_status(&cacheable, &ctx, "MISS");

    // Reverse: SSE bypass first, then cacheable stages independently.
    let mut ctx = make_ctx("GET", "/mixed-sse-rev");
    let mut headers = HashMap::new();
    headers.insert("accept".to_string(), "text/event-stream".to_string());
    assert!(matches!(
        sse_peer.before_proxy(&mut ctx, &mut headers).await,
        PluginResult::Continue
    ));
    assert_status(&sse_peer, &ctx, "BYPASS");
    headers.remove("accept");
    assert!(matches!(
        cacheable.before_proxy(&mut ctx, &mut headers).await,
        PluginResult::Continue
    ));
    assert_status(&cacheable, &ctx, "MISS");
    assert_status(&sse_peer, &ctx, "BYPASS");
}

#[tokio::test]
async fn status_policy_divergence_does_not_cross_contaminate_stores() {
    for a_first in [true, false] {
        let only_200 = plugin_with_config(json!({
            "ttl_seconds": 60,
            "cacheable_status_codes": [200]
        }));
        let allows_404 = plugin_with_config(json!({
            "ttl_seconds": 60,
            "cacheable_status_codes": [200, 404]
        }));

        let (first, second) = if a_first {
            (&only_200, &allows_404)
        } else {
            (&allows_404, &only_200)
        };
        let mut ctx = make_ctx("GET", "/status-policy");
        let mut headers = HashMap::new();
        assert!(matches!(
            first.before_proxy(&mut ctx, &mut headers).await,
            PluginResult::Continue
        ));
        assert!(matches!(
            second.before_proxy(&mut ctx, &mut headers).await,
            PluginResult::Continue
        ));

        let response_headers = public_response_headers();
        first
            .on_final_response_body(&mut ctx, 404, &response_headers, b"missing")
            .await;
        second
            .on_final_response_body(&mut ctx, 404, &response_headers, b"missing")
            .await;

        let mut replay = make_ctx("GET", "/status-policy");
        let mut replay_headers = HashMap::new();
        let only_200_result = only_200
            .before_proxy(&mut replay, &mut replay_headers)
            .await;
        assert!(
            matches!(only_200_result, PluginResult::Continue),
            "200-only instance must not store 404"
        );
        assert_status(&only_200, &replay, "PREDICTED-BYPASS");

        let mut replay = make_ctx("GET", "/status-policy");
        let mut replay_headers = HashMap::new();
        let allows_404_result = allows_404
            .before_proxy(&mut replay, &mut replay_headers)
            .await;
        match allows_404_result {
            PluginResult::RejectBinary {
                status_code, body, ..
            } => {
                assert_eq!(status_code, 404);
                assert_eq!(&body[..], b"missing");
            }
            other => panic!("404-capable instance should HIT, got {other:?}"),
        }
        assert_status(&allows_404, &replay, "HIT");
    }
}

#[tokio::test]
async fn reload_generations_do_not_share_staging_namespaces() {
    let generation_one = plugin_with_config(json!({
        "ttl_seconds": 60,
        "vary_by_headers": ["x-tenant"],
        "cache_key_include_query": true
    }));
    let mut ctx = make_ctx_with_raw_query("GET", "/reload", "v=1");
    ctx.headers
        .insert("x-tenant".to_string(), "before".to_string());
    let mut headers = ctx.headers.clone();
    assert!(matches!(
        generation_one.before_proxy(&mut ctx, &mut headers).await,
        PluginResult::Continue
    ));
    let gen1_base_key = staging_key(&generation_one, "cache_base_key");
    let gen1_status_key = staging_key(&generation_one, "cache_status");
    let gen1_snapshot_key = staging_key(&generation_one, "cache_request_headers_snapshot");
    assert!(ctx.metadata.contains_key(&gen1_base_key));
    assert_eq!(
        ctx.metadata.get(&gen1_status_key).map(String::as_str),
        Some("MISS")
    );
    assert!(ctx.metadata.contains_key(&gen1_snapshot_key));

    // A reload constructs a fresh instance with a new runtime id. It must not
    // read or clear the retired generation's namespaced staging.
    let generation_two = plugin_with_config(json!({
        "ttl_seconds": 120,
        "vary_by_headers": ["x-tenant"],
        "cache_key_include_query": false,
        "cacheable_status_codes": [200, 404]
    }));
    assert_ne!(
        response_caching_instance_id_for_test(&generation_one),
        response_caching_instance_id_for_test(&generation_two)
    );

    let mut gen2_headers = headers.clone();
    gen2_headers.insert("accept".to_string(), "text/event-stream".to_string());
    assert!(matches!(
        generation_two
            .before_proxy(&mut ctx, &mut gen2_headers)
            .await,
        PluginResult::Continue
    ));
    assert_status(&generation_two, &ctx, "BYPASS");
    assert!(
        !ctx.metadata
            .contains_key(&staging_key(&generation_two, "cache_base_key")),
        "SSE bypass must clear only the current generation's lookup staging"
    );
    assert!(
        ctx.metadata.contains_key(&gen1_base_key),
        "reload generation must not clear retired instance staging"
    );
    assert_eq!(
        ctx.metadata.get(&gen1_status_key).map(String::as_str),
        Some("MISS")
    );
    assert!(ctx.metadata.contains_key(&gen1_snapshot_key));

    generation_one
        .on_final_response_body(&mut ctx, 200, &public_response_headers(), b"gen1")
        .await;

    let mut replay = make_ctx_with_raw_query("GET", "/reload", "v=1");
    replay
        .headers
        .insert("x-tenant".to_string(), "before".to_string());
    let mut replay_headers = replay.headers.clone();
    match generation_one
        .before_proxy(&mut replay, &mut replay_headers)
        .await
    {
        PluginResult::RejectBinary {
            status_code, body, ..
        } => {
            assert_eq!(status_code, 200);
            assert_eq!(&body[..], b"gen1");
        }
        other => panic!("retired generation should still HIT its own cache, got {other:?}"),
    }

    let mut replay = make_ctx_with_raw_query("GET", "/reload", "v=1");
    replay
        .headers
        .insert("x-tenant".to_string(), "before".to_string());
    let mut replay_headers = replay.headers.clone();
    assert!(
        matches!(
            generation_two
                .before_proxy(&mut replay, &mut replay_headers)
                .await,
            PluginResult::Continue
        ),
        "replacement generation must not inherit the retired generation's entries"
    );
    assert_status(&generation_two, &replay, "MISS");
}
