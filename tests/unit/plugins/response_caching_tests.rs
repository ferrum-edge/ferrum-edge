//! Tests for response_caching plugin

// These tests intentionally serialize complete async cache lifecycles against
// process-global RTDS publications. The guard is test-only and no task in the
// guarded lifecycle reacquires it.
#![allow(clippy::await_holding_lock)]

use super::plugin_utils::create_test_proxy;
use chrono::Utc;
use ferrum_edge::_test_support::{
    advance_response_caching_clock_for_test, clone_log_metadata,
    refine_stream_response_for_content_type_for_test, response_caching_cache_keys_for_test,
    response_caching_current_total_size_for_test, response_caching_instance_id_for_test,
    response_caching_shard_amount_for_test, response_caching_size_accounting_snapshot_for_test,
    response_caching_staging_metadata_key_for_test, response_caching_vary_index_snapshot_for_test,
    retry_response_decision_context_for_test, run_after_proxy_hooks_for_test,
    run_after_proxy_hooks_reject_for_test, set_replay_credential_headers_for_test,
    set_replay_request_body_empty_proven_for_test,
    set_response_presentation_policy_digest_for_test, stamp_original_response_metadata_for_test,
};
use ferrum_edge::config::types::Consumer;
use ferrum_edge::plugins::response_caching::{RESPONSE_CACHING_CONFIG_KEYS, ResponseCaching};
use ferrum_edge::plugins::response_size_limiting::ResponseSizeLimiting;
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
    set_replay_request_body_empty_proven_for_test(&mut ctx, true);
    set_response_presentation_policy_digest_for_test(&mut ctx, Some([0x51; 32]));
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
    cache_response_with_host(plugin, method, path, None, status, response_headers, body).await;
}

async fn cache_response_with_host(
    plugin: &ResponseCaching,
    method: &str,
    path: &str,
    host: Option<&str>,
    status: u16,
    response_headers: &HashMap<String, String>,
    body: &[u8],
) {
    let mut ctx = make_ctx(method, path);
    let mut headers = HashMap::new();
    if let Some(host) = host {
        ctx.headers.insert("host".to_string(), host.to_string());
        headers.insert("host".to_string(), host.to_string());
    }

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

/// Drive an unsafe-method request through lookup bypass and the response-side
/// invalidation gate (RFC 9111 §4.4).
async fn unsafe_method_cycle(
    plugin: &ResponseCaching,
    method: &str,
    path: &str,
    host: Option<&str>,
    response_status: u16,
) {
    let mut ctx = make_ctx(method, path);
    let mut headers = HashMap::new();
    if let Some(host) = host {
        ctx.headers.insert("host".to_string(), host.to_string());
        headers.insert("host".to_string(), host.to_string());
    }
    assert!(matches!(
        plugin.before_proxy(&mut ctx, &mut headers).await,
        PluginResult::Continue
    ));
    let mut resp_headers = HashMap::new();
    plugin
        .after_proxy(&mut ctx, response_status, &mut resp_headers)
        .await;
}

async fn assert_cache_hit_for_host(plugin: &ResponseCaching, path: &str, host: &str, body: &[u8]) {
    let mut ctx = make_ctx("GET", path);
    ctx.headers.insert("host".to_string(), host.to_string());
    let mut headers = HashMap::new();
    headers.insert("host".to_string(), host.to_string());
    let (_, hit_body, _) = expect_reject(plugin.before_proxy(&mut ctx, &mut headers).await);
    assert_eq!(hit_body, body);
}

async fn assert_cache_miss_for_host(plugin: &ResponseCaching, path: &str, host: &str) {
    let mut ctx = make_ctx("GET", path);
    ctx.headers.insert("host".to_string(), host.to_string());
    let mut headers = HashMap::new();
    headers.insert("host".to_string(), host.to_string());
    assert!(
        matches!(
            plugin.before_proxy(&mut ctx, &mut headers).await,
            PluginResult::Continue
        ),
        "expected MISS for host {host} path {path}"
    );
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

/// Serialize against RTDS runtime-overlay publications.
///
/// `response_caching` stamps every stored entry with the live response-side
/// runtime-overlay gate publication and retires entries whose stamp no longer
/// matches, so an overlay publication in a concurrently running test would
/// legitimately turn a HIT into a MISS. Every test that stores an entry and
/// then asserts a HIT/REVALIDATED replay takes this process-wide lock, which
/// is the same lock every overlay publisher holds.
fn response_cache_replay_policy_guard() -> std::sync::MutexGuard<'static, ()> {
    ferrum_edge::modes::mesh::runtime_overlay_consumers::test_lock()
}

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
        ("anonymous_caller_scope", "anonymous_caller_scop"),
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
async fn base_cache_key_partitions_unannounced_origin_visible_headers() {
    let plugin = default_plugin();
    let mut alpha = make_ctx("GET", "/tenant-data");
    let mut alpha_headers = HashMap::from([("x-tenant-id".to_string(), "alpha".to_string())]);
    assert!(matches!(
        plugin.before_proxy(&mut alpha, &mut alpha_headers).await,
        PluginResult::Continue
    ));

    let mut beta = make_ctx("GET", "/tenant-data");
    let mut beta_headers = HashMap::from([("x-tenant-id".to_string(), "beta".to_string())]);
    assert!(matches!(
        plugin.before_proxy(&mut beta, &mut beta_headers).await,
        PluginResult::Continue
    ));

    assert_ne!(
        alpha.metadata.get(&staging_key(&plugin, "cache_base_key")),
        beta.metadata.get(&staging_key(&plugin, "cache_base_key")),
        "an origin-visible header must partition the cache even without Vary"
    );
}

async fn staged_base_cache_key(
    plugin: &ResponseCaching,
    path: &str,
    extra_headers: &[(&str, &str)],
) -> Option<String> {
    let mut ctx = make_ctx("GET", path);
    let mut headers = HashMap::new();
    for (name, value) in extra_headers {
        headers.insert((*name).to_string(), (*value).to_string());
    }
    let _ = plugin.before_proxy(&mut ctx, &mut headers).await;
    ctx.metadata
        .get(&staging_key(plugin, "cache_base_key"))
        .cloned()
}

#[tokio::test]
async fn base_cache_key_keeps_supported_entry_operation_headers_reachable() {
    let plugin = default_plugin();
    let path = "/entry-ops-reachable";
    let baseline = staged_base_cache_key(&plugin, path, &[])
        .await
        .expect("baseline request must stage a base key");

    let supported = [
        ("if-none-match", r#""etag-1""#),
        ("if-modified-since", "Wed, 21 Oct 2015 07:28:00 GMT"),
        ("cache-control", "no-cache"),
        ("content-length", "0"),
    ];
    for (name, value) in supported {
        let key = staged_base_cache_key(&plugin, path, &[(name, value)])
            .await
            .unwrap_or_else(|| panic!("{name}: {value} must stage a base key"));
        assert_eq!(
            key, baseline,
            "{name}: {value} is a handled entry operation and must stay reachable"
        );
    }

    // Request `Cache-Control: no-store` is still excluded from the key digest
    // (same entry-operation class as no-cache), but RFC 9111 §5.2.1.5 makes the
    // store path unreachable, so staging is cleared rather than retained for a
    // store that can never happen (see
    // `request_no_store_releases_the_response_buffer_and_does_not_store`).
    assert!(
        staged_base_cache_key(&plugin, path, &[("cache-control", "no-store")])
            .await
            .is_none(),
        "cache-control: no-store must clear lookup staging rather than retain a store key"
    );
}

#[tokio::test]
async fn base_cache_key_binds_unsupported_precondition_range_and_pragma_dimensions() {
    let plugin = default_plugin();
    let path = "/unsupported-preconditions";
    let baseline = staged_base_cache_key(&plugin, path, &[])
        .await
        .expect("baseline request must stage a base key");

    let unsupported = [
        ("if-match", r#""etag-1""#),
        ("if-unmodified-since", "Wed, 21 Oct 2015 07:28:00 GMT"),
        ("if-range", r#""etag-1""#),
        ("range", "bytes=0-3"),
        ("pragma", "no-cache"),
    ];
    for (name, value) in unsupported {
        let key = staged_base_cache_key(&plugin, path, &[(name, value)])
            .await
            .unwrap_or_else(|| panic!("{name}: {value} must stage a base key"));
        assert_ne!(
            key, baseline,
            "{name} is not implemented as a cache operation and must not share a replay key"
        );
    }
}

#[tokio::test]
async fn base_cache_key_cache_control_exclusion_is_value_aware() {
    let plugin = default_plugin();
    let path = "/cache-control-value-aware";
    let baseline = staged_base_cache_key(&plugin, path, &[])
        .await
        .expect("baseline request must stage a base key");

    let recognized_refresh = staged_base_cache_key(&plugin, path, &[("cache-control", "no-cache")])
        .await
        .expect("recognized no-cache refresh must stage a base key");
    assert_eq!(
        recognized_refresh, baseline,
        "recognized no-cache must remain under the original partition for replacement"
    );

    // Bare `no-store` (alone or beside `no-cache`) clears staging: RFC 9111
    // §5.2.1.5 forbids retaining any part of the request or its response, so
    // there is no store-side replacement partition to keep reachable.
    assert!(
        staged_base_cache_key(&plugin, path, &[("cache-control", "no-store")])
            .await
            .is_none(),
        "recognized no-store must clear staging rather than retain a store key"
    );
    assert!(
        staged_base_cache_key(&plugin, path, &[("cache-control", "no-cache, no-store")])
            .await
            .is_none(),
        "a pure no-cache/no-store pair still carries no-store, so staging must clear"
    );

    let unrecognized = [
        ("max-age=0", "request max-age is not a handled refresh"),
        (
            "only-if-cached",
            "only-if-cached is not interpreted by this cache",
        ),
        (
            "foo",
            "arbitrary Cache-Control extensions are backend-visible",
        ),
        ("public", "public on a request is not a handled refresh"),
    ];
    for (value, reason) in unrecognized {
        let key = staged_base_cache_key(&plugin, path, &[("cache-control", value)])
            .await
            .unwrap_or_else(|| panic!("cache-control: {value} must stage a base key"));
        assert_ne!(
            key, baseline,
            "cache-control: {value} must partition ({reason})"
        );
    }

    // Mixed recognized refresh + unimplemented members remain backend-visible
    // context and must not collapse onto the baseline refresh partition.
    let mixed_max_age =
        staged_base_cache_key(&plugin, path, &[("cache-control", "no-cache, max-age=0")])
            .await
            .expect("mixed no-cache refresh must stage a base key");
    assert_ne!(
        mixed_max_age, baseline,
        "mixed no-cache plus max-age=0 must not share the baseline replay key"
    );

    let mixed_extension =
        staged_base_cache_key(&plugin, path, &[("cache-control", "no-cache, x-tenant=a")])
            .await
            .expect("mixed no-cache plus extension must stage a base key");
    assert_ne!(
        mixed_extension, baseline,
        "mixed no-cache plus an arbitrary extension must not share the baseline replay key"
    );

    for value in [
        r#"no-cache="authorization, cookie""#,
        "no-cache=opaque",
        r#"no-cache="authorization", x-tenant=a"#,
        r#"no-cache="authorization"junk"#,
        r#"no-cache="authorization"#,
    ] {
        let key = staged_base_cache_key(&plugin, path, &[("cache-control", value)])
            .await
            .unwrap_or_else(|| panic!("cache-control: {value} must stage a base key"));
        assert_ne!(
            key, baseline,
            "argument-bearing, mixed, or malformed cache-control must fail closed into its own partition"
        );
    }

    // Argument-bearing `no-store=…` is not a pure honored refresh for keying,
    // but the store-path parser still treats any `no-store` member as forbidding
    // retention — staging clears rather than partitioning a dead store key.
    assert!(
        staged_base_cache_key(&plugin, path, &[("cache-control", "no-store=opaque")])
            .await
            .is_none(),
        "argument-bearing no-store still forbids retention, so staging must clear"
    );
}

#[tokio::test]
async fn base_cache_key_binds_cache_control_when_respect_no_cache_disabled() {
    let plugin = plugin_with_config(json!({ "respect_no_cache": false }));
    let path = "/cache-control-respect-disabled";
    let baseline = staged_base_cache_key(&plugin, path, &[])
        .await
        .expect("baseline request must stage a base key");

    for value in ["no-cache", "no-store", r#"no-cache="authorization""#] {
        let key = staged_base_cache_key(&plugin, path, &[("cache-control", value)])
            .await
            .unwrap_or_else(|| panic!("cache-control: {value} must stage a base key"));
        assert_ne!(
            key, baseline,
            "respect_no_cache=false leaves cache-control: {value} backend-visible and bound"
        );
    }
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
    let _policy_guard = response_cache_replay_policy_guard();
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
    let _policy_guard = response_cache_replay_policy_guard();
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
    let _policy_guard = response_cache_replay_policy_guard();
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
    // Seed the entry under the same origin-visible Accept-Encoding partition
    // as the refresh below. A different request-header view is deliberately a
    // different base key and must not be invalidated by this response.
    let mut store_ctx = make_ctx("GET", path);
    store_ctx
        .headers
        .insert("accept-encoding".to_string(), "gzip".to_string());
    let mut store_headers = store_ctx.headers.clone();
    assert!(matches!(
        plugin
            .before_proxy(&mut store_ctx, &mut store_headers)
            .await,
        PluginResult::Continue
    ));
    plugin
        .after_proxy(&mut store_ctx, 200, &mut resp_headers)
        .await;
    plugin
        .on_final_response_body(&mut store_ctx, 200, &resp_headers, b"cached")
        .await;
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
    let _policy_guard = response_cache_replay_policy_guard();
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

    // Successful POST to the same path should invalidate after the response
    unsafe_method_cycle(&plugin, "POST", "/api/items", None, 200).await;

    // GET should now be a MISS
    let mut ctx = make_ctx("GET", "/api/items");
    let mut headers = HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
}

/// A route-dispatch rewrite (`mesh_route_dispatch`, a `request_transformer`
/// route override, `ai_stream_router`) publishes `route_override_path` during
/// `before_proxy`; proxy core folds it into `RequestContext::path` only *after*
/// the phase returns, and it stays there for the rest of the request.
///
/// The base key and the staged unsafe-method invalidation target are both the
/// *client-facing* path observed at lookup. The storage-side invalidation index
/// must use that same value: indexing under the then-current (rewritten) path
/// would leave RFC 9111 §4.4 invalidation matching nothing, so a mutated
/// resource would keep serving its stale cached representation for the rest of
/// its TTL.
#[tokio::test]
async fn test_unsafe_method_invalidates_entry_stored_behind_a_route_rewrite() {
    const CLIENT_PATH: &str = "/api/items";
    const BACKEND_PATH: &str = "/backend/v2/items";

    fn rewritten_ctx(method: &str) -> RequestContext {
        let mut ctx = make_ctx(method, CLIENT_PATH);
        ctx.route_override_path = Some(BACKEND_PATH.to_string());
        ctx
    }

    // Proxy core consumes the override and rebases `ctx.path` onto the backend
    // route only after `before_proxy` has already returned.
    fn apply_route_rewrite(ctx: &mut RequestContext) {
        let rewritten = ctx.route_override_path.take().expect("override staged");
        ctx.path = rewritten;
    }

    let plugin = default_plugin();

    let mut ctx = rewritten_ctx("GET");
    let mut headers = HashMap::new();
    let miss = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(miss, PluginResult::Continue));
    apply_route_rewrite(&mut ctx);
    let mut resp_headers = HashMap::new();
    plugin.after_proxy(&mut ctx, 200, &mut resp_headers).await;
    plugin
        .on_final_response_body(&mut ctx, 200, &resp_headers, b"cached")
        .await;

    // Reachability first, otherwise the invalidation assertion is vacuous.
    let mut ctx = rewritten_ctx("GET");
    let mut headers = HashMap::new();
    let hit = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(is_reject(&hit), "rewritten route must be cacheable");

    // A successful POST on the same client-facing path must evict it.
    let mut ctx = rewritten_ctx("POST");
    let mut headers = HashMap::new();
    let bypass = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(bypass, PluginResult::Continue));
    apply_route_rewrite(&mut ctx);
    let mut resp_headers = HashMap::new();
    plugin.after_proxy(&mut ctx, 200, &mut resp_headers).await;

    let mut ctx = rewritten_ctx("GET");
    let mut headers = HashMap::new();
    let after = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(
        matches!(after, PluginResult::Continue),
        "invalidation must reach an entry stored behind a route rewrite"
    );
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
    let _policy_guard = response_cache_replay_policy_guard();
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
    let _policy_guard = response_cache_replay_policy_guard();
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
async fn test_if_none_match_parses_entity_tag_lists_without_partial_matches() {
    let plugin = default_plugin();
    let cases = [
        ("quoted comma", r#""alpha,beta""#, r#""alpha,beta""#, true),
        (
            "quoted comma in list",
            r#""other", "alpha,beta", W/"last""#,
            r#""alpha,beta""#,
            true,
        ),
        (
            "weak comparison",
            r#"W/"alpha,beta""#,
            r#""alpha,beta""#,
            true,
        ),
        ("wildcard", " \t*\t ", r#""alpha,beta""#, true),
        (
            "optional whitespace",
            " \tW/\"other\"\t,\t \"alpha,beta\" \t",
            r#"W/"alpha,beta""#,
            true,
        ),
        (
            "invalid leading fragment",
            r#"bogus, "alpha,beta""#,
            r#""alpha,beta""#,
            false,
        ),
        (
            "trailing comma",
            r#""alpha,beta", "#,
            r#""alpha,beta""#,
            false,
        ),
        (
            "junk after matching tag",
            r#""alpha,beta"junk"#,
            r#""alpha,beta""#,
            false,
        ),
        (
            "lowercase weak prefix",
            r#"w/"alpha,beta""#,
            r#""alpha,beta""#,
            false,
        ),
        (
            "space inside opaque tag",
            r#""alpha, beta""#,
            r#""alpha, beta""#,
            false,
        ),
        (
            "wildcard list member",
            r#""alpha,beta", *"#,
            r#""alpha,beta""#,
            false,
        ),
    ];

    for (index, (name, if_none_match, etag, should_match)) in cases.into_iter().enumerate() {
        let path = format!("/etag-list-{index}");
        let mut response_headers = HashMap::new();
        response_headers.insert("etag".to_string(), etag.to_string());
        response_headers.insert("cache-control".to_string(), "max-age=60".to_string());
        cache_response(
            &plugin,
            "GET",
            &path,
            200,
            &response_headers,
            b"cached-body",
        )
        .await;

        let mut ctx = make_ctx("GET", &path);
        ctx.headers
            .insert("if-none-match".to_string(), if_none_match.to_string());
        let mut headers = HashMap::new();
        headers.insert("if-none-match".to_string(), if_none_match.to_string());
        let (status_code, body, _) =
            expect_reject(plugin.before_proxy(&mut ctx, &mut headers).await);

        assert_eq!(
            status_code,
            if should_match { 304 } else { 200 },
            "case {name}: If-None-Match={if_none_match:?}, ETag={etag:?}"
        );
        assert_eq!(
            body.is_empty(),
            should_match,
            "case {name}: 304 must be empty and a non-match must replay the cached body"
        );
    }
}

#[tokio::test]
async fn test_authorization_response_not_shared_cached_without_public() {
    let plugin = default_plugin();
    let mut ctx = make_ctx("GET", "/api/private");
    ctx.headers
        .insert("authorization".to_string(), "Bearer token-a".to_string());
    // GHSA-7f28-wh4x-5375: the credential must be in the live `before_proxy`
    // view too — that map, not `ctx.headers`, is what production passes — so
    // this exercises the storage refusal rather than a Vary-key mismatch.
    let mut headers = ctx.headers.clone();
    plugin.before_proxy(&mut ctx, &mut headers).await;

    let mut response_headers = HashMap::new();
    response_headers.insert("cache-control".to_string(), "max-age=60".to_string());
    plugin
        .after_proxy(&mut ctx, 200, &mut response_headers)
        .await;
    plugin
        .on_final_response_body(&mut ctx, 200, &response_headers, b"user-a")
        .await;

    assert!(
        response_caching_cache_keys_for_test(&plugin).is_empty(),
        "the response must not be retained at all, not merely keyed apart"
    );

    let mut second_ctx = make_ctx("GET", "/api/private");
    second_ctx
        .headers
        .insert("authorization".to_string(), "Bearer token-a".to_string());
    let mut second_headers = second_ctx.headers.clone();
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

    // Authenticated principals require RFC 9111 §3.5 shared-cache opt-in.
    // `cache_key_include_consumer` only partitions keys; it cannot authorize
    // storage (see `test_consumer_key_partition_does_not_override_shared_cache_admission`).
    let mut public_response = HashMap::new();
    public_response.insert(
        "cache-control".to_string(),
        "public, max-age=60".to_string(),
    );

    // Cache response for user A
    let mut ctx_a = make_ctx("GET", "/api/data");
    ctx_a.identified_consumer = Some(Arc::new(make_consumer("a", "alice")));
    let mut h = HashMap::new();
    plugin.before_proxy(&mut ctx_a, &mut h).await;
    let mut rh = public_response.clone();
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

    let mut public_response = HashMap::new();
    public_response.insert(
        "cache-control".to_string(),
        "public, max-age=60".to_string(),
    );

    let mut ctx_external = make_ctx("GET", "/api/data");
    ctx_external.authenticated_identity = Some("oidc-alice".to_string());
    let mut headers = HashMap::new();
    plugin.before_proxy(&mut ctx_external, &mut headers).await;
    let mut response_headers = public_response.clone();
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

// === Complete backend-visible query partition ===

#[tokio::test]
async fn legacy_query_toggle_cannot_exclude_backend_visible_query() {
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

    // The legacy toggle still rotates the keyspace, but it cannot authorize
    // cross-query replay when the origin receives and may vary on the query.
    let mut ctx2 = make_ctx_with_query("GET", "/api/items", &[("page", "2")]);
    ctx2.matched_proxy = Some(std::sync::Arc::new(create_test_proxy()));
    let mut h2 = HashMap::new();
    let result = plugin.before_proxy(&mut ctx2, &mut h2).await;
    assert!(
        matches!(result, PluginResult::Continue),
        "a different backend-visible query must miss even when the legacy flag is false"
    );
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

    // Successful POST must NOT invalidate when disabled
    unsafe_method_cycle(&plugin, "POST", "/api/items", None, 200).await;

    // GET should still be a HIT
    let mut ctx = make_ctx("GET", "/api/items");
    let mut headers = HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(is_reject(&result));
}

// === Max total size ===

#[tokio::test]
async fn test_max_total_size_exceeded() {
    let _policy_guard = response_cache_replay_policy_guard();
    let plugin = plugin_with_config(json!({
        "max_total_size_bytes": 500,
        "max_entry_size_bytes": 1048576,
        // Keep generated telemetry out of this accounting fixture.
        "add_cache_status_header": false
    }));

    // Cache a response that takes up most of the total size. Each entry is
    // ~200 bytes body + ~96 bytes struct overhead + the retained
    // invalidation-index scope digest and path, so one fits inside 500 bytes
    // and two do not.
    cache_response(&plugin, "GET", "/api/a", 200, &HashMap::new(), &[b'x'; 200]).await;

    // This should fail to cache (would exceed the 500-byte total size). The cap
    // is a hard cap on retained bytes, not an LRU trigger, so the fresh first
    // entry is never evicted to make room.
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
    assert!(assert_size_accounting_exact(&plugin) <= 500);
}

#[tokio::test]
async fn test_replacement_admission_uses_size_delta() {
    let plugin = plugin_with_config(json!({
        "max_total_size_bytes": 600,
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
    assert!(assert_size_accounting_exact(&plugin) <= 600);

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
    assert!(assert_size_accounting_exact(&plugin) <= 600);
}

#[tokio::test]
async fn test_large_to_small_replacement_releases_capacity() {
    let plugin = plugin_with_config(json!({
        "max_total_size_bytes": 550,
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
    assert!(assert_size_accounting_exact(&plugin) <= 550);

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
    assert!(assert_size_accounting_exact(&plugin) <= 550);
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
async fn test_anonymous_response_keeps_mandatory_sensitive_vary_boundary() {
    // Ferrum's private caller partition is invisible to downstream shared
    // caches. An anonymous response therefore keeps all mandatory sensitive
    // Vary names so a downstream cache cannot replay it to a credentialed or
    // session-bearing request.
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
    let vary = response_headers
        .get("vary")
        .expect("anonymous cached response must retain the sensitive Vary boundary");
    for sensitive in ["authorization", "proxy-authorization", "cookie"] {
        assert!(
            vary.split(',')
                .map(str::trim)
                .any(|name| name.eq_ignore_ascii_case(sensitive)),
            "Vary must include `{sensitive}` even for an anonymous request, got `{vary}`"
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
    let _policy_guard = response_cache_replay_policy_guard();
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

            // Interleave an invalidation via an unsafe method on the same path
            // after a non-error response (RFC 9111 §4.4 gate).
            let mut inv_ctx = make_ctx("POST", &path);
            let mut inv_headers = HashMap::new();
            let _ = plugin.before_proxy(&mut inv_ctx, &mut inv_headers).await;
            let mut inv_resp = HashMap::new();
            let _ = plugin.after_proxy(&mut inv_ctx, 200, &mut inv_resp).await;
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

/// Concurrent cold fills that discover different Vary dimensions must publish
/// one monotonic union. Widening the index must also remove older narrow-key
/// entries whose missing request-header values cannot be reconstructed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_concurrent_stores_atomically_union_vary_dimensions_and_remove_narrow_entries() {
    let plugin = Arc::new(
        ResponseCaching::new(&json!({
            "ttl_seconds": 60,
            "max_total_size_bytes": 1024 * 1024,
            "max_entries": 64
        }))
        .expect("config should be valid"),
    );
    let barrier = Arc::new(tokio::sync::Barrier::new(2));

    let mut tasks = Vec::new();
    for (vary_header, body) in [("x-a", b"body-a"), ("x-b", b"body-b")] {
        let plugin = Arc::clone(&plugin);
        let barrier = Arc::clone(&barrier);
        tasks.push(tokio::spawn(async move {
            let mut ctx = make_ctx("GET", "/vary-race");
            let mut request_headers = ctx.headers.clone();
            assert!(matches!(
                plugin.before_proxy(&mut ctx, &mut request_headers).await,
                PluginResult::Continue
            ));

            let mut response_headers = HashMap::from([
                (
                    "cache-control".to_string(),
                    "public, max-age=60".to_string(),
                ),
                ("vary".to_string(), vary_header.to_string()),
            ]);
            plugin
                .after_proxy(&mut ctx, 200, &mut response_headers)
                .await;

            // Both requests complete lookup before either response is
            // published, matching concurrent cold fills for one base key.
            barrier.wait().await;
            plugin
                .on_final_response_body(&mut ctx, 200, &response_headers, body)
                .await;
        }));
    }
    for task in tasks {
        task.await.expect("store task panicked");
    }

    let vary_index = response_caching_vary_index_snapshot_for_test(&plugin);
    assert_eq!(vary_index.len(), 1, "one base key should be indexed");
    assert_eq!(
        vary_index[0].1,
        vec![
            "authorization".to_string(),
            "cookie".to_string(),
            "proxy-authorization".to_string(),
            "x-a".to_string(),
            "x-b".to_string(),
        ],
        "concurrent stores must publish the full Vary union plus mandatory sensitive dimensions"
    );

    let cache_keys = response_caching_cache_keys_for_test(&plugin);
    assert_eq!(
        cache_keys.len(),
        1,
        "the older narrow-key variant must be deliberately removed when the index widens"
    );
    assert_size_accounting_exact(&plugin);

    let mut ctx = make_ctx("GET", "/vary-race");
    let mut request_headers = ctx.headers.clone();
    assert!(
        is_reject(&plugin.before_proxy(&mut ctx, &mut request_headers).await),
        "the sole retained wide-key entry must remain reachable under the final union"
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
        "cacheable_methods": ["GET", "HEAD"],
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
    let _policy_guard = response_cache_replay_policy_guard();
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
    let _policy_guard = response_cache_replay_policy_guard();
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
    let _policy_guard = response_cache_replay_policy_guard();
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
        "cacheable_methods": ["GET", "HEAD"]
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
    let _policy_guard = response_cache_replay_policy_guard();
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
    let _policy_guard = response_cache_replay_policy_guard();
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

// === Unsafe-method invalidation scope (#2418) ===

/// A safe method that is merely absent from `cacheable_methods` must bypass
/// without evicting: with the default cacheable set, OPTIONS is not cacheable
/// but is still an RFC 9110 safe method.
#[tokio::test]
async fn test_options_does_not_invalidate_cached_get() {
    let _policy_guard = response_cache_replay_policy_guard();
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

    // Sanity: the entry is served from cache.
    let mut ctx = make_ctx("GET", "/api/items");
    let mut headers = HashMap::new();
    assert!(is_reject(
        &plugin.before_proxy(&mut ctx, &mut headers).await
    ));

    let mut ctx = make_ctx("OPTIONS", "/api/items");
    let mut headers = HashMap::new();
    assert!(matches!(
        plugin.before_proxy(&mut ctx, &mut headers).await,
        PluginResult::Continue
    ));
    assert_status(&plugin, &ctx, "BYPASS");

    // The cached GET response must survive the safe-method bypass.
    let mut ctx = make_ctx("GET", "/api/items");
    let mut headers = HashMap::new();
    assert!(
        is_reject(&plugin.before_proxy(&mut ctx, &mut headers).await),
        "OPTIONS must not invalidate cached GET entries"
    );
}

/// HEAD is safe even when an operator deliberately configures a GET-only
/// cacheable set — it must bypass without invalidating the cached GET entry.
#[tokio::test]
async fn test_non_cacheable_head_does_not_invalidate_cached_get() {
    let _policy_guard = response_cache_replay_policy_guard();
    let plugin = plugin_with_config(json!({
        "cacheable_methods": ["GET"]
    }));

    cache_response(&plugin, "GET", "/api/items", 200, &HashMap::new(), b"body").await;

    let mut ctx = make_ctx("HEAD", "/api/items");
    let mut headers = HashMap::new();
    assert!(matches!(
        plugin.before_proxy(&mut ctx, &mut headers).await,
        PluginResult::Continue
    ));
    assert_status(&plugin, &ctx, "BYPASS");

    let mut ctx = make_ctx("GET", "/api/items");
    let mut headers = HashMap::new();
    assert!(
        is_reject(&plugin.before_proxy(&mut ctx, &mut headers).await),
        "non-cacheable HEAD must not invalidate cached GET entries"
    );
}

/// Every standardized unsafe method must still invalidate the cached entry
/// for the same path after a non-error response, preserving the documented
/// POST/PUT/PATCH/DELETE behavior of `invalidate_on_unsafe_methods`.
#[tokio::test]
async fn test_every_unsafe_method_invalidates_cached_get() {
    for method in ["POST", "PUT", "PATCH", "DELETE"] {
        let plugin = default_plugin();
        cache_response(&plugin, "GET", "/api/items", 200, &HashMap::new(), b"body").await;

        unsafe_method_cycle(&plugin, method, "/api/items", None, 200).await;

        let mut ctx = make_ctx("GET", "/api/items");
        let mut headers = HashMap::new();
        assert!(
            matches!(
                plugin.before_proxy(&mut ctx, &mut headers).await,
                PluginResult::Continue
            ),
            "{method} must invalidate the cached GET entry"
        );
    }
}

/// Extension methods have unknown semantics, so they fail closed as unsafe
/// and invalidate matching cached entries after a non-error response.
#[tokio::test]
async fn test_extension_method_conservatively_invalidates_cached_get() {
    let plugin = default_plugin();
    cache_response(&plugin, "GET", "/api/items", 200, &HashMap::new(), b"body").await;

    unsafe_method_cycle(&plugin, "PURGE", "/api/items", None, 200).await;

    let mut ctx = make_ctx("GET", "/api/items");
    let mut headers = HashMap::new();
    assert!(
        matches!(
            plugin.before_proxy(&mut ctx, &mut headers).await,
            PluginResult::Continue
        ),
        "unknown extension methods must conservatively invalidate cached entries"
    );
}

// === Byte-cap admission reclaims expired entries (#2400) ===

/// Expired entries must not trap the byte budget: a store rejected only for
/// aggregate byte pressure reclaims stale entries first and admits the new
/// key when it fits after reclamation — even when the entry count never
/// exceeded `max_entries`.
#[tokio::test]
async fn test_byte_cap_admission_reclaims_expired_entries() {
    let plugin = plugin_with_config(json!({
        "ttl_seconds": 10,
        "max_entries": 1000,
        "max_total_size_bytes": 3000
    }));

    let body = vec![b'x'; 1000];
    // Two distinct ~1KB entries fit inside the 3KB byte budget; a third
    // cannot fit while both are retained.
    cache_response(&plugin, "GET", "/a", 200, &HashMap::new(), &body).await;
    cache_response(&plugin, "GET", "/b", 200, &HashMap::new(), &body).await;
    let filled_total = response_caching_current_total_size_for_test(&plugin);
    assert!(
        filled_total > 1500 && filled_total <= 3000,
        "setup entries must fill most of the byte budget, got {filled_total}"
    );

    // While every retained entry is fresh, the byte cap still rejects a new
    // distinct key — the cap is enforced, not bypassed by the reclaim path.
    cache_response(&plugin, "GET", "/c", 200, &HashMap::new(), &body).await;
    assert_eq!(
        response_caching_current_total_size_for_test(&plugin),
        filled_total,
        "fresh entries must keep the byte cap closed to a third distinct entry"
    );
    let mut ctx = make_ctx("GET", "/c");
    let mut headers = HashMap::new();
    assert!(matches!(
        plugin.before_proxy(&mut ctx, &mut headers).await,
        PluginResult::Continue
    ));

    // Expire every retained entry without re-requesting its key. The entry
    // count stays below `max_entries`, so the count-gated eviction sweep
    // never runs for them.
    advance_response_caching_clock_for_test(&plugin, std::time::Duration::from_secs(20));

    // The next store must reclaim the expired bytes and be admitted.
    cache_response(&plugin, "GET", "/d", 200, &HashMap::new(), &body).await;
    let mut ctx = make_ctx("GET", "/d");
    let mut headers = HashMap::new();
    assert!(
        is_reject(&plugin.before_proxy(&mut ctx, &mut headers).await),
        "new entry must be admitted after expired entries are reclaimed"
    );

    // Expired keys are gone and tracked size matches the retained entries.
    let mut ctx = make_ctx("GET", "/a");
    let mut headers = HashMap::new();
    assert!(matches!(
        plugin.before_proxy(&mut ctx, &mut headers).await,
        PluginResult::Continue
    ));
    assert!(
        response_caching_current_total_size_for_test(&plugin) <= 3000,
        "tracked size must stay within the byte cap after reclaim"
    );
    assert_size_accounting_exact(&plugin);
}

/// Expiration order is independent of insertion order: a short-lived entry can
/// expire behind an older long-lived entry and must still be reclaimable
/// without scanning or evicting the fresh representation.
#[tokio::test]
async fn test_byte_cap_reclaims_later_inserted_short_lived_entry() {
    let plugin = plugin_with_config(json!({
        "ttl_seconds": 60,
        "max_entries": 1000,
        "max_total_size_bytes": 3000
    }));
    let body = vec![b'x'; 1000];
    let long_lived = HashMap::from([(
        "cache-control".to_string(),
        "public, max-age=120".to_string(),
    )]);
    let short_lived =
        HashMap::from([("cache-control".to_string(), "public, max-age=1".to_string())]);

    cache_response(&plugin, "GET", "/long-lived", 200, &long_lived, &body).await;
    cache_response(&plugin, "GET", "/short-lived", 200, &short_lived, &body).await;
    advance_response_caching_clock_for_test(&plugin, std::time::Duration::from_secs(10));

    // A third entry cannot fit until the later-inserted short-lived entry is
    // reclaimed. The older long-lived entry at the FIFO front remains fresh.
    cache_response(&plugin, "GET", "/replacement", 200, &long_lived, &body).await;

    let mut long_ctx = make_ctx("GET", "/long-lived");
    let mut long_headers = HashMap::new();
    assert!(
        is_reject(&plugin.before_proxy(&mut long_ctx, &mut long_headers).await),
        "fresh older entry must not be evicted"
    );

    let mut short_ctx = make_ctx("GET", "/short-lived");
    let mut short_headers = HashMap::new();
    assert!(matches!(
        plugin
            .before_proxy(&mut short_ctx, &mut short_headers)
            .await,
        PluginResult::Continue
    ));

    let mut replacement_ctx = make_ctx("GET", "/replacement");
    let mut replacement_headers = HashMap::new();
    assert!(
        is_reject(
            &plugin
                .before_proxy(&mut replacement_ctx, &mut replacement_headers)
                .await
        ),
        "new entry must be admitted after expiration-ordered reclaim"
    );
    assert!(response_caching_current_total_size_for_test(&plugin) <= 3000);
    assert_size_accounting_exact(&plugin);
}

/// Concurrent stores racing an expiring working set must keep the size
/// accountant exact: byte-cap admission reclaim runs under the same
/// accounting lock as insertion and replacement accounting.
#[tokio::test]
async fn test_concurrent_stores_with_expiry_keep_size_accounting_exact() {
    let plugin = Arc::new(
        ResponseCaching::new(&json!({
            "ttl_seconds": 5,
            "max_total_size_bytes": 8192,
            "max_entries": 1000
        }))
        .expect("config should be valid"),
    );

    // Seed a working set that expires before the concurrent stores run, so
    // byte-cap admission must reclaim it while other stores race.
    let seed_body = vec![b's'; 512];
    for n in 0..8u32 {
        cache_response(
            &plugin,
            "GET",
            &format!("/seed-{n}"),
            200,
            &HashMap::new(),
            &seed_body,
        )
        .await;
    }
    advance_response_caching_clock_for_test(&plugin, std::time::Duration::from_secs(10));

    let mut tasks = Vec::new();
    for n in 0..32u32 {
        let plugin = Arc::clone(&plugin);
        tasks.push(tokio::spawn(async move {
            let path = format!("/api/item-{}", n % 16);
            let body = vec![b'x'; 512];
            cache_response(&plugin, "GET", &path, 200, &HashMap::new(), &body).await;
        }));
    }
    for task in tasks {
        task.await.expect("store task panicked");
    }

    assert_size_accounting_exact(&plugin);
    assert!(
        response_caching_current_total_size_for_test(&plugin) <= 8192,
        "total_size exceeded configured max_total_size_bytes"
    );
}

// === Hot-path map shard sizing (#2429) ===

/// The explicit constructor must route the selected shard count to the
/// plugin's hot-path maps, normalizing non-power-of-two values the same way
/// `FERRUM_POOL_SHARD_AMOUNT` does.
#[test]
fn test_constructor_honors_explicit_pool_shard_amount() {
    let plugin = ResponseCaching::new_with_pool_shard_amount(&json!({}), 96)
        .expect("config should be valid");
    assert_eq!(
        response_caching_shard_amount_for_test(&plugin),
        128,
        "non-power-of-two overrides must round up to the next power of two"
    );

    let plugin = ResponseCaching::new_with_pool_shard_amount(&json!({}), 256)
        .expect("config should be valid");
    assert_eq!(response_caching_shard_amount_for_test(&plugin), 256);
}

/// The convenience constructor used by tests/support tooling must auto-derive
/// the same host-topology shard amount the gateway computes for a zero
/// `FERRUM_POOL_SHARD_AMOUNT`.
#[test]
fn test_default_constructor_auto_derives_shard_amount() {
    let plugin = default_plugin();
    assert_eq!(
        response_caching_shard_amount_for_test(&plugin),
        ferrum_edge::util::sharding::pool_shard_amount(0),
        "the default constructor must auto-derive the host shard amount"
    );
}

// === Advisory coverage: shared-cache admission, qualified Cache-Control
// field lists, and partial/validator-only representations ===
//
// GHSA-7f28-wh4x-5375 — authenticated responses cached without shared-cache opt-in
// GHSA-fpx2-5v4j-wqxq — qualified private/no-cache fields replayed unsafely
// GHSA-v7fj-73gm-h625 — standalone 304 / partial 206 stored as reusable representations

fn advisory_headers(pairs: &[(&str, &str)]) -> HashMap<String, String> {
    pairs
        .iter()
        .map(|(name, value)| (name.to_string(), value.to_string()))
        .collect()
}

/// Drive one production-shaped MISS: `before_proxy` sees the live (possibly
/// transformed) header view, `after_proxy` stamps the status header, and
/// `on_final_response_body` decides whether the representation is retained.
async fn advisory_miss_cycle(
    plugin: &ResponseCaching,
    path: &str,
    request_headers: &HashMap<String, String>,
    status: u16,
    response_headers: &HashMap<String, String>,
    body: &[u8],
) {
    let mut ctx = make_ctx("GET", path);
    ctx.headers = request_headers.clone();
    let mut live_headers = request_headers.clone();
    plugin.before_proxy(&mut ctx, &mut live_headers).await;

    let mut resp_headers = response_headers.clone();
    plugin
        .after_proxy(&mut ctx, status, &mut resp_headers)
        .await;
    plugin
        .on_final_response_body(&mut ctx, status, &resp_headers, body)
        .await;
}

async fn advisory_lookup(
    plugin: &ResponseCaching,
    path: &str,
    request_headers: &HashMap<String, String>,
) -> PluginResult {
    let mut ctx = make_ctx("GET", path);
    ctx.headers = request_headers.clone();
    let mut live_headers = request_headers.clone();
    plugin.before_proxy(&mut ctx, &mut live_headers).await
}

/// GHSA-7f28-wh4x-5375: a gateway that forwards `Authorization` to a backend
/// which validates it itself mints no Ferrum identity, so an identity-only
/// gate treated the request as anonymous and stored the protected response.
/// RFC 9111 §3.5 requires an explicit shared-cache opt-in.
#[tokio::test]
async fn test_backend_authenticated_bearer_not_stored_without_shared_cache_optin() {
    let plugin = default_plugin();
    let request = advisory_headers(&[("authorization", "Bearer backend-validated")]);
    let response = advisory_headers(&[("cache-control", "max-age=300")]);

    advisory_miss_cycle(
        &plugin,
        "/api/backend-auth",
        &request,
        200,
        &response,
        b"protected",
    )
    .await;

    assert!(
        response_caching_cache_keys_for_test(&plugin).is_empty(),
        "a response to an Authorization-bearing request must not be retained without \
         `public`, `must-revalidate`, or `s-maxage`"
    );

    // Backend-side revocation, expiry, and scope changes must not be masked:
    // the same token has to reach the origin again.
    assert!(matches!(
        advisory_lookup(&plugin, "/api/backend-auth", &request).await,
        PluginResult::Continue
    ));
}

/// The three RFC 9111 §3.5 opt-in directives each permit shared storage of a
/// backend-authenticated response.
#[tokio::test]
async fn test_backend_authenticated_bearer_stored_with_explicit_optin() {
    for directive in [
        "public, max-age=300",
        "must-revalidate, max-age=300",
        "s-maxage=300",
    ] {
        let plugin = default_plugin();
        let request = advisory_headers(&[("authorization", "Bearer backend-validated")]);
        let response = advisory_headers(&[("cache-control", directive)]);

        advisory_miss_cycle(&plugin, "/api/opt-in", &request, 200, &response, b"shared").await;

        let (_, body, _) = expect_reject(advisory_lookup(&plugin, "/api/opt-in", &request).await);
        assert_eq!(
            body, b"shared",
            "`{directive}` must permit shared storage of an authorized response"
        );
    }
}

/// A local key-partition option cannot replace the origin's explicit
/// shared-cache permission. Otherwise backend-side revocation remains masked
/// for the entry lifetime even though credentials do not cross cache keys.
#[tokio::test]
async fn test_consumer_key_partition_does_not_override_shared_cache_admission() {
    let plugin = plugin_with_config(json!({ "cache_key_include_consumer": true }));
    let request = advisory_headers(&[("authorization", "Bearer backend-validated")]);
    let response = advisory_headers(&[("cache-control", "max-age=300")]);

    advisory_miss_cycle(
        &plugin,
        "/api/consumer-key-partition",
        &request,
        200,
        &response,
        b"isolated",
    )
    .await;

    assert!(
        response_caching_cache_keys_for_test(&plugin).is_empty(),
        "cache_key_include_consumer only changes key partitioning and must not authorize storage"
    );
    assert!(matches!(
        advisory_lookup(&plugin, "/api/consumer-key-partition", &request).await,
        PluginResult::Continue
    ));
}

/// The gate reads the same live/restored header view the cache key comes from,
/// so a request-side transformer cannot move a credentialed request across the
/// boundary in either direction.
#[tokio::test]
async fn test_transformed_authorization_view_still_requires_optin() {
    for (in_live_view, in_ctx_headers) in [(true, false), (false, true)] {
        let plugin = default_plugin();
        let mut ctx = make_ctx("GET", "/api/transformed-auth");
        if in_ctx_headers {
            ctx.headers
                .insert("authorization".to_string(), "Bearer t".to_string());
        }
        let mut live_headers = HashMap::new();
        if in_live_view {
            live_headers.insert("authorization".to_string(), "Bearer t".to_string());
        }
        plugin.before_proxy(&mut ctx, &mut live_headers).await;

        let response = advisory_headers(&[("cache-control", "max-age=300")]);
        plugin
            .on_final_response_body(&mut ctx, 200, &response, b"protected")
            .await;

        assert!(
            response_caching_cache_keys_for_test(&plugin).is_empty(),
            "a credential visible in either header view must refuse storage \
             (live={in_live_view}, ctx={in_ctx_headers})"
        );
    }
}

/// GHSA-fpx2-5v4j-wqxq: `private="x-account"` names a field a shared cache may
/// not retain. The response for the requesting client keeps it; the entry must
/// not.
#[tokio::test]
async fn test_qualified_private_field_is_not_retained() {
    let plugin = default_plugin();
    let request = HashMap::new();
    let response = advisory_headers(&[
        (
            "cache-control",
            "public, max-age=300, private=\"x-account\"",
        ),
        ("x-account", "tenant-a"),
        ("content-type", "application/json"),
    ]);

    advisory_miss_cycle(
        &plugin,
        "/api/qualified-private",
        &request,
        200,
        &response,
        b"{}",
    )
    .await;

    let hit = advisory_lookup(&plugin, "/api/qualified-private", &request).await;
    let (_, body, replayed) = expect_reject(hit);
    assert_eq!(body, b"{}");
    assert!(
        !replayed.contains_key("x-account"),
        "a qualified `private` field must never be replayed: {replayed:?}"
    );
    assert_eq!(
        replayed.get("content-type").map(String::as_str),
        Some("application/json"),
        "unqualified fields must survive"
    );
    assert_eq!(
        response.get("x-account").map(String::as_str),
        Some("tenant-a"),
        "only the retained copy is narrowed; the origin response is untouched"
    );
}

/// A quoted field-name list holds its own commas, is matched case-insensitively,
/// and may name several fields. A `split(',')` parser sees neither half of
/// `no-cache="a, b"` as a directive and retains both fields.
#[tokio::test]
async fn test_qualified_no_cache_quoted_list_survives_commas_and_case() {
    let plugin = default_plugin();
    let request = HashMap::new();
    let cache_control = "public, MAX-AGE=300, No-Cache=\"X-Secret, x-policy\"";
    let response = advisory_headers(&[
        ("cache-control", cache_control),
        ("x-secret", "s3cret"),
        ("x-policy", "tenant-a"),
        ("x-public", "ok"),
    ]);

    advisory_miss_cycle(
        &plugin,
        "/api/qualified-no-cache",
        &request,
        200,
        &response,
        b"body",
    )
    .await;

    let hit = advisory_lookup(&plugin, "/api/qualified-no-cache", &request).await;
    let (_, body, replayed) = expect_reject(hit);
    assert_eq!(body, b"body");
    for protected in ["x-secret", "x-policy"] {
        assert!(
            !replayed.contains_key(protected),
            "`{protected}` was named by a qualified `no-cache` and must not be replayed: \
             {replayed:?}"
        );
    }
    assert_eq!(replayed.get("x-public").map(String::as_str), Some("ok"));
}

/// Anything that is not a well-formed quoted field-name list fails closed to
/// the bare directive, which refuses the whole response. Duplicate spellings
/// resolve to the bare form in either order.
#[tokio::test]
async fn test_malformed_qualified_directives_refuse_the_whole_response() {
    for directive in [
        // Unterminated quoted string.
        "public, max-age=300, private=\"x-account",
        // Unquoted argument.
        "public, max-age=300, private=x-account",
        // Empty list.
        "public, max-age=300, private=\"\"",
        // Member that is not a valid field name.
        "public, max-age=300, no-cache=\"bad header\"",
        // A valid quoted prefix followed by non-OWS junk is malformed.
        "public, max-age=300, private=\"x-account\"junk",
        // Bare spelling alongside a qualified one, either order.
        "public, max-age=300, private=\"x-account\", private",
        "public, max-age=300, private, private=\"x-account\"",
    ] {
        let plugin = default_plugin();
        let request = HashMap::new();
        let response = advisory_headers(&[("cache-control", directive), ("x-account", "t-a")]);

        advisory_miss_cycle(&plugin, "/api/malformed", &request, 200, &response, b"body").await;

        assert!(
            response_caching_cache_keys_for_test(&plugin).is_empty(),
            "`{directive}` must fail closed to the bare directive and refuse the response"
        );
    }
}

/// Connection- and intermediary-scoped response fields describe this hop, not
/// the representation, and must never be replayed from a shared entry.
#[tokio::test]
async fn test_connection_scoped_and_proxy_auth_fields_are_not_retained() {
    let plugin = default_plugin();
    let request = HashMap::new();
    let response = advisory_headers(&[
        ("cache-control", "public, max-age=300"),
        ("connection", "keep-alive, x-internal-token"),
        ("x-internal-token", "internal"),
        ("keep-alive", "timeout=5"),
        ("proxy-authenticate", "Basic realm=\"edge\""),
        ("transfer-encoding", "chunked"),
        ("upgrade", "websocket"),
        ("content-type", "text/plain"),
    ]);

    advisory_miss_cycle(&plugin, "/api/hop-by-hop", &request, 200, &response, b"ok").await;

    let hit = advisory_lookup(&plugin, "/api/hop-by-hop", &request).await;
    let (_, _, replayed) = expect_reject(hit);
    for stripped in [
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "transfer-encoding",
        "upgrade",
        "x-internal-token",
    ] {
        assert!(
            !replayed.contains_key(stripped),
            "`{stripped}` must not be replayed from cache: {replayed:?}"
        );
    }
    assert_eq!(
        replayed.get("content-type").map(String::as_str),
        Some("text/plain")
    );
}

/// GHSA-v7fj-73gm-h625: statuses whose caching semantics the plugin does not
/// implement cannot be configured as cacheable.
#[test]
fn test_unsupported_cacheable_status_codes_rejected() {
    for status in [100, 101, 199, 206, 304] {
        let err = ResponseCaching::new(&json!({ "cacheable_status_codes": [200, status] }))
            .err()
            .unwrap_or_else(|| panic!("status {status} must not be configurable as cacheable"));
        assert!(err.contains("cacheable_status_codes[1]"), "got: {err}");
    }

    for status in [200, 203, 204, 300, 301, 308, 404, 410, 500] {
        ResponseCaching::new(&json!({ "cacheable_status_codes": [status] }))
            .unwrap_or_else(|error| panic!("status {status} must stay configurable: {error}"));
    }
}

/// A caller-selected byte range describes bytes, not the resource, so it must
/// never become the entry a later unconditional request receives — even when
/// the partial arrives under an allowed status.
#[tokio::test]
async fn test_partial_representation_is_never_stored() {
    let plugin = default_plugin();
    let ranged_request = advisory_headers(&[("range", "bytes=0-3")]);
    let response = advisory_headers(&[
        ("cache-control", "public, max-age=300"),
        ("content-range", "bytes 0-3/1024"),
    ]);

    advisory_miss_cycle(
        &plugin,
        "/api/ranged",
        &ranged_request,
        200,
        &response,
        b"part",
    )
    .await;

    assert!(
        response_caching_cache_keys_for_test(&plugin).is_empty(),
        "a `Content-Range` response must not become a reusable representation"
    );
    assert!(matches!(
        advisory_lookup(&plugin, "/api/ranged", &HashMap::new()).await,
        PluginResult::Continue
    ));
}

/// A `304` is validator metadata for an existing stored representation, never
/// a representation of its own.
#[tokio::test]
async fn test_validator_only_not_modified_is_never_stored() {
    let plugin = plugin_with_config(json!({ "cacheable_status_codes": [200] }));
    let request = HashMap::new();
    let response =
        advisory_headers(&[("cache-control", "public, max-age=300"), ("etag", "\"v1\"")]);

    advisory_miss_cycle(&plugin, "/api/validator", &request, 304, &response, b"").await;

    assert!(
        response_caching_cache_keys_for_test(&plugin).is_empty(),
        "a standalone 304 must not be stored as a reusable representation"
    );
    assert!(matches!(
        advisory_lookup(&plugin, "/api/validator", &request).await,
        PluginResult::Continue
    ));
}

/// Conflicting duplicate `delta-seconds` values are ambiguous; the most
/// restrictive lifetime wins instead of whichever member happened to be last.
#[tokio::test]
async fn test_duplicate_max_age_keeps_the_most_restrictive_lifetime() {
    let plugin = default_plugin();
    let request = HashMap::new();
    let response = advisory_headers(&[("cache-control", "public, max-age=600, max-age=1")]);

    advisory_miss_cycle(&plugin, "/api/dup-max-age", &request, 200, &response, b"ok").await;
    let fresh_hit = advisory_lookup(&plugin, "/api/dup-max-age", &request).await;
    assert!(is_reject(&fresh_hit));

    advance_response_caching_clock_for_test(&plugin, std::time::Duration::from_secs(2));
    assert!(
        matches!(
            advisory_lookup(&plugin, "/api/dup-max-age", &request).await,
            PluginResult::Continue
        ),
        "the shorter duplicate `max-age` must bound freshness"
    );
}

// === Authority-scoped deferred invalidation (GHSA-7836-2m4x-3gwr) ===

/// A successful mutation on authority A must not evict the same path cached
/// under authority B on a shared proxy.
#[tokio::test]
async fn test_unsafe_invalidation_does_not_cross_authority_boundaries() {
    let _policy_guard = response_cache_replay_policy_guard();
    let plugin = default_plugin();

    cache_response_with_host(
        &plugin,
        "GET",
        "/api/items",
        Some("a.example.com"),
        200,
        &HashMap::new(),
        b"tenant-a",
    )
    .await;
    cache_response_with_host(
        &plugin,
        "GET",
        "/api/items",
        Some("b.example.com"),
        200,
        &HashMap::new(),
        b"tenant-b",
    )
    .await;

    unsafe_method_cycle(&plugin, "POST", "/api/items", Some("a.example.com"), 200).await;

    assert_cache_miss_for_host(&plugin, "/api/items", "a.example.com").await;
    assert_cache_hit_for_host(&plugin, "/api/items", "b.example.com", b"tenant-b").await;
}

/// Invalidation must use the same transformed Host partition as cache lookup:
/// a mutation whose outbound Host was rewritten must evict only that partition.
#[tokio::test]
async fn test_unsafe_invalidation_uses_transformed_host_partition() {
    let _policy_guard = response_cache_replay_policy_guard();
    let plugin = default_plugin();

    // Store under the rewritten backend Host (lookup/storage contract).
    let mut store_ctx = make_ctx("GET", "/api/items");
    store_ctx
        .headers
        .insert("host".to_string(), "client.example.com".to_string());
    let mut store_headers = HashMap::new();
    store_headers.insert("host".to_string(), "backend.internal".to_string());
    plugin
        .before_proxy(&mut store_ctx, &mut store_headers)
        .await;
    let mut store_resp = HashMap::new();
    plugin
        .after_proxy(&mut store_ctx, 200, &mut store_resp)
        .await;
    plugin
        .on_final_response_body(&mut store_ctx, 200, &store_resp, b"rewritten-host")
        .await;

    // Unrelated client-facing Host entry must survive.
    cache_response_with_host(
        &plugin,
        "GET",
        "/api/items",
        Some("other.example.com"),
        200,
        &HashMap::new(),
        b"other-host",
    )
    .await;

    // Mutation with the same Host rewrite must invalidate only the rewritten
    // partition.
    let mut post_ctx = make_ctx("POST", "/api/items");
    post_ctx
        .headers
        .insert("host".to_string(), "client.example.com".to_string());
    let mut post_headers = HashMap::new();
    post_headers.insert("host".to_string(), "backend.internal".to_string());
    plugin.before_proxy(&mut post_ctx, &mut post_headers).await;
    let mut post_resp = HashMap::new();
    plugin.after_proxy(&mut post_ctx, 204, &mut post_resp).await;

    // Lookup with the rewritten Host must MISS.
    let mut miss_ctx = make_ctx("GET", "/api/items");
    miss_ctx
        .headers
        .insert("host".to_string(), "client.example.com".to_string());
    let mut miss_headers = HashMap::new();
    miss_headers.insert("host".to_string(), "backend.internal".to_string());
    assert!(matches!(
        plugin.before_proxy(&mut miss_ctx, &mut miss_headers).await,
        PluginResult::Continue
    ));

    assert_cache_hit_for_host(&plugin, "/api/items", "other.example.com", b"other-host").await;
}

/// Deferred invalidation must retain the client-facing path used by cache
/// lookup even when proxy routing rewrites `ctx.path` for the backend.
#[tokio::test]
async fn test_unsafe_invalidation_uses_original_path_after_route_rewrite() {
    let _policy_guard = response_cache_replay_policy_guard();
    let plugin = default_plugin();

    cache_response_with_host(
        &plugin,
        "GET",
        "/v1/items",
        Some("a.example.com"),
        200,
        &HashMap::new(),
        b"cached-v1",
    )
    .await;

    let mut post_ctx = make_ctx("POST", "/v1/items");
    post_ctx
        .headers
        .insert("host".to_string(), "a.example.com".to_string());
    let mut post_headers = post_ctx.headers.clone();
    plugin.before_proxy(&mut post_ctx, &mut post_headers).await;

    // Proxy core applies a route override after before_proxy hooks.
    post_ctx.path = "/v2/items".to_string();
    let mut response_headers = HashMap::new();
    plugin
        .after_proxy(&mut post_ctx, 204, &mut response_headers)
        .await;

    assert_cache_miss_for_host(&plugin, "/v1/items", "a.example.com").await;
}

/// A failed mutation must not evict cache entries (RFC 9111 §4.4).
#[tokio::test]
async fn test_failed_unsafe_mutation_does_not_invalidate() {
    let _policy_guard = response_cache_replay_policy_guard();
    let plugin = default_plugin();

    cache_response_with_host(
        &plugin,
        "GET",
        "/api/items",
        Some("a.example.com"),
        200,
        &HashMap::new(),
        b"still-fresh",
    )
    .await;

    for status in [400u16, 401, 403, 404, 409, 500, 502, 503] {
        unsafe_method_cycle(&plugin, "POST", "/api/items", Some("a.example.com"), status).await;
        assert_cache_hit_for_host(&plugin, "/api/items", "a.example.com", b"still-fresh").await;
    }
}

/// Successful unsafe mutations (2xx/3xx) do invalidate the matched authority.
#[tokio::test]
async fn test_successful_unsafe_mutation_invalidates_after_non_error_response() {
    let _policy_guard = response_cache_replay_policy_guard();
    let plugin = default_plugin();

    for status in [200u16, 201, 204, 301, 302, 303, 307, 399] {
        cache_response_with_host(
            &plugin,
            "GET",
            "/api/items",
            Some("a.example.com"),
            200,
            &HashMap::new(),
            b"cached",
        )
        .await;

        // before_proxy alone must not evict.
        let mut ctx = make_ctx("DELETE", "/api/items");
        ctx.headers
            .insert("host".to_string(), "a.example.com".to_string());
        let mut headers = HashMap::new();
        headers.insert("host".to_string(), "a.example.com".to_string());
        plugin.before_proxy(&mut ctx, &mut headers).await;
        assert_cache_hit_for_host(&plugin, "/api/items", "a.example.com", b"cached").await;

        let mut resp_headers = HashMap::new();
        plugin
            .after_proxy(&mut ctx, status, &mut resp_headers)
            .await;
        assert_cache_miss_for_host(&plugin, "/api/items", "a.example.com").await;
    }
}

/// Unknown/custom methods fail closed as unsafe and invalidate after success.
#[tokio::test]
async fn test_unknown_method_fail_closed_invalidates_after_success() {
    let _policy_guard = response_cache_replay_policy_guard();
    let plugin = default_plugin();

    cache_response(&plugin, "GET", "/api/items", 200, &HashMap::new(), b"body").await;

    // Error response for unknown method: no eviction.
    unsafe_method_cycle(&plugin, "CUSTOM", "/api/items", None, 405).await;
    let mut ctx = make_ctx("GET", "/api/items");
    let mut headers = HashMap::new();
    assert!(is_reject(
        &plugin.before_proxy(&mut ctx, &mut headers).await
    ));

    // Non-error response: evict.
    unsafe_method_cycle(&plugin, "CUSTOM", "/api/items", None, 200).await;
    let mut ctx = make_ctx("GET", "/api/items");
    let mut headers = HashMap::new();
    assert!(matches!(
        plugin.before_proxy(&mut ctx, &mut headers).await,
        PluginResult::Continue
    ));
}

/// Path-descendant invalidation remains authority-scoped.
#[tokio::test]
async fn test_path_descendant_invalidation_stays_authority_scoped() {
    let _policy_guard = response_cache_replay_policy_guard();
    let plugin = default_plugin();

    cache_response_with_host(
        &plugin,
        "GET",
        "/api/items/42",
        Some("a.example.com"),
        200,
        &HashMap::new(),
        b"a-child",
    )
    .await;
    cache_response_with_host(
        &plugin,
        "GET",
        "/api/items/42",
        Some("b.example.com"),
        200,
        &HashMap::new(),
        b"b-child",
    )
    .await;
    cache_response_with_host(
        &plugin,
        "GET",
        "/api/other",
        Some("a.example.com"),
        200,
        &HashMap::new(),
        b"a-other",
    )
    .await;

    unsafe_method_cycle(&plugin, "DELETE", "/api/items", Some("a.example.com"), 204).await;

    assert_cache_miss_for_host(&plugin, "/api/items/42", "a.example.com").await;
    assert_cache_hit_for_host(&plugin, "/api/items/42", "b.example.com", b"b-child").await;
    assert_cache_hit_for_host(&plugin, "/api/other", "a.example.com", b"a-other").await;
}

/// Concurrent successful invalidations on distinct authorities must not
/// cross-evict each other's partitions.
#[tokio::test]
async fn test_concurrent_authority_scoped_invalidation() {
    let _policy_guard = response_cache_replay_policy_guard();
    let plugin = std::sync::Arc::new(default_plugin());

    cache_response_with_host(
        &plugin,
        "GET",
        "/api/items",
        Some("a.example.com"),
        200,
        &HashMap::new(),
        b"tenant-a",
    )
    .await;
    cache_response_with_host(
        &plugin,
        "GET",
        "/api/items",
        Some("b.example.com"),
        200,
        &HashMap::new(),
        b"tenant-b",
    )
    .await;
    cache_response_with_host(
        &plugin,
        "GET",
        "/api/items",
        Some("c.example.com"),
        200,
        &HashMap::new(),
        b"tenant-c",
    )
    .await;

    let plugin_a = plugin.clone();
    let plugin_b = plugin.clone();
    let ((), ()) = tokio::join!(
        async move {
            unsafe_method_cycle(&plugin_a, "POST", "/api/items", Some("a.example.com"), 200).await;
        },
        async move {
            unsafe_method_cycle(&plugin_b, "PUT", "/api/items", Some("b.example.com"), 201).await;
        },
    );

    assert_cache_miss_for_host(&plugin, "/api/items", "a.example.com").await;
    assert_cache_miss_for_host(&plugin, "/api/items", "b.example.com").await;
    assert_cache_hit_for_host(&plugin, "/api/items", "c.example.com", b"tenant-c").await;
}

/// A body-bearing method can no longer be made cacheable: a shared cache
/// selects a representation by method + target + Vary, and lookup runs before
/// the exact backend-visible request body exists (GHSA-w27g-65rf-h7xm).
#[tokio::test]
async fn test_body_bearing_cacheable_method_is_refused_at_admission() {
    for method in ["POST", "PUT", "PATCH", "DELETE", "QUERY"] {
        let error = match ResponseCaching::new(&json!({ "cacheable_methods": ["GET", method] })) {
            Ok(_) => panic!("body-bearing cacheable method must be refused"),
            Err(error) => error,
        };
        assert!(
            error.contains("bodyless retrieval method"),
            "unexpected admission error for {method}: {error}"
        );
    }
    assert!(
        ResponseCaching::new(&json!({ "cacheable_methods": ["GET", "HEAD"] })).is_ok(),
        "bodyless retrieval methods must remain admissible"
    );
}

/// Direct plugin calls and any transport path that has not observed the
/// complete upload must fail closed. In particular, absence of body framing
/// headers is not proof for an H2/H3 GET whose DATA frames may arrive later.
#[tokio::test]
async fn test_cache_lookup_requires_transport_owned_empty_body_proof() {
    let plugin = default_plugin();
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/api/items".to_string(),
    );
    ctx.matched_proxy = Some(Arc::new(create_test_proxy()));
    let mut headers = HashMap::new();

    assert!(matches!(
        plugin.before_proxy(&mut ctx, &mut headers).await,
        PluginResult::Continue
    ));
    assert_status(&plugin, &ctx, "BYPASS");
    assert!(
        !ctx.metadata
            .contains_key(&staging_key(&plugin, "cache_base_key")),
        "an unproven upload must not stage a lookup or storage key"
    );
}

/// Even for an admissible method, a request that declares a body bypasses both
/// lookup and storage: the pre-transform bytes are not the ones sent upstream.
#[tokio::test]
async fn test_request_declaring_a_body_bypasses_cache() {
    let _policy_guard = response_cache_replay_policy_guard();
    let plugin = default_plugin();

    cache_response_with_host(
        &plugin,
        "GET",
        "/api/items",
        Some("a.example.com"),
        200,
        &HashMap::new(),
        b"cached-get",
    )
    .await;

    for (name, value) in [
        ("content-length", "7"),
        ("content-length", ""),
        ("content-length", "+0"),
        ("content-length", "not-a-length"),
        ("content-length", "0, 0"),
        ("transfer-encoding", "chunked"),
    ] {
        let mut ctx = make_ctx("GET", "/api/items");
        ctx.headers
            .insert("host".to_string(), "a.example.com".to_string());
        let mut headers = HashMap::new();
        headers.insert("host".to_string(), "a.example.com".to_string());
        headers.insert(name.to_string(), value.to_string());
        assert!(
            matches!(
                plugin.before_proxy(&mut ctx, &mut headers).await,
                PluginResult::Continue
            ),
            "unsafe body framing must not replay ({name}={value:?})"
        );
        assert_eq!(
            ctx.metadata
                .get(&staging_key(&plugin, "cache_status"))
                .map(String::as_str),
            Some("BYPASS"),
            "unsafe body framing must bypass ({name}={value:?})"
        );
        assert!(
            !ctx.metadata
                .contains_key(&staging_key(&plugin, "cache_base_key")),
            "a bypassed request must not stage a key ({name}={value:?})"
        );
    }

    // A zero-length declaration is not a body and still uses the cache.
    let mut ctx = make_ctx("GET", "/api/items");
    ctx.headers
        .insert("host".to_string(), "a.example.com".to_string());
    let mut headers = HashMap::new();
    headers.insert("host".to_string(), "a.example.com".to_string());
    headers.insert("content-length".to_string(), "0".to_string());
    let (_, body, _) = expect_reject(plugin.before_proxy(&mut ctx, &mut headers).await);
    assert_eq!(body, b"cached-get");
}

/// An unsafe method is never cacheable now, but it must still stage and apply
/// RFC 9111 §4.4 invalidation after a non-error origin response.
#[tokio::test]
async fn test_unsafe_method_bypass_invalidates_after_success() {
    let _policy_guard = response_cache_replay_policy_guard();
    let plugin = plugin_with_config(json!({
        "cacheable_methods": ["GET", "HEAD"],
        "invalidate_on_unsafe_methods": true
    }));

    cache_response_with_host(
        &plugin,
        "GET",
        "/api/items",
        Some("a.example.com"),
        200,
        &HashMap::new(),
        b"cached-get",
    )
    .await;

    let mut post_ctx = make_ctx("POST", "/api/items");
    post_ctx
        .headers
        .insert("host".to_string(), "a.example.com".to_string());
    let mut post_headers = HashMap::new();
    post_headers.insert("host".to_string(), "a.example.com".to_string());
    assert!(matches!(
        plugin.before_proxy(&mut post_ctx, &mut post_headers).await,
        PluginResult::Continue
    ));
    assert_eq!(
        post_ctx
            .metadata
            .get(&staging_key(&plugin, "cache_status"))
            .map(String::as_str),
        Some("BYPASS"),
        "a body-bearing method must bypass storage"
    );
    assert!(
        post_ctx
            .metadata
            .contains_key(&staging_key(&plugin, "cache_pending_invalidate_host")),
        "an unsafe method must still stage pending invalidation"
    );

    // before_proxy alone must not evict.
    assert_cache_hit_for_host(&plugin, "/api/items", "a.example.com", b"cached-get").await;

    let mut resp_headers = HashMap::new();
    plugin
        .after_proxy(&mut post_ctx, 201, &mut resp_headers)
        .await;
    assert_cache_miss_for_host(&plugin, "/api/items", "a.example.com").await;
}

/// An unsafe bypass that receives an error origin status must not invalidate
/// peer GET/HEAD variants.
#[tokio::test]
async fn test_unsafe_method_error_does_not_invalidate() {
    let _policy_guard = response_cache_replay_policy_guard();
    let plugin = plugin_with_config(json!({
        "cacheable_methods": ["GET", "HEAD"],
        "invalidate_on_unsafe_methods": true
    }));

    cache_response_with_host(
        &plugin,
        "GET",
        "/api/items",
        Some("a.example.com"),
        200,
        &HashMap::new(),
        b"still-fresh",
    )
    .await;

    for status in [400u16, 403, 404, 500, 502] {
        let mut post_ctx = make_ctx("POST", "/api/items");
        post_ctx
            .headers
            .insert("host".to_string(), "a.example.com".to_string());
        let mut post_headers = HashMap::new();
        post_headers.insert("host".to_string(), "a.example.com".to_string());
        assert!(matches!(
            plugin.before_proxy(&mut post_ctx, &mut post_headers).await,
            PluginResult::Continue
        ));
        let mut resp_headers = HashMap::new();
        plugin
            .after_proxy(&mut post_ctx, status, &mut resp_headers)
            .await;
        assert_cache_hit_for_host(&plugin, "/api/items", "a.example.com", b"still-fresh").await;
    }
}

/// An earlier `after_proxy` rejection of a genuine non-error origin response
/// must not suppress unsafe-method invalidation. Proxy core records private
/// origin status and notifies plugins before the after_proxy loop.
#[tokio::test]
async fn test_earlier_after_proxy_reject_still_invalidates_on_origin_success() {
    let _policy_guard = response_cache_replay_policy_guard();
    let cache = Arc::new(default_plugin());
    let size_limit = Arc::new(
        ResponseSizeLimiting::new(&json!({ "max_bytes": 8 })).expect("size limiter config"),
    );

    cache_response_with_host(
        &cache,
        "GET",
        "/api/items",
        Some("a.example.com"),
        200,
        &HashMap::new(),
        b"stale",
    )
    .await;

    let mut ctx = make_ctx("DELETE", "/api/items");
    ctx.headers
        .insert("host".to_string(), "a.example.com".to_string());
    let mut req_headers = HashMap::new();
    req_headers.insert("host".to_string(), "a.example.com".to_string());
    assert!(matches!(
        cache.before_proxy(&mut ctx, &mut req_headers).await,
        PluginResult::Continue
    ));
    assert!(
        ctx.metadata
            .contains_key(&staging_key(&cache, "cache_pending_invalidate_host"))
    );

    // Priority order: size limiting (3490) runs before caching (3500) and
    // rejects the oversized Content-Length, so caching's after_proxy never
    // sees the genuine 200. observe_origin_http_response_status must still
    // apply the staged invalidation.
    let plugins: Vec<Arc<dyn Plugin>> = vec![size_limit, cache.clone()];
    let mut resp_headers = HashMap::new();
    resp_headers.insert("content-length".to_string(), "64".to_string());
    resp_headers.insert("content-type".to_string(), "text/plain".to_string());
    let reject = run_after_proxy_hooks_reject_for_test(&plugins, &mut ctx, 200, &mut resp_headers)
        .await
        .expect("size limiter must reject oversized origin response");
    assert_eq!(reject.0, 502);

    assert_cache_miss_for_host(&cache, "/api/items", "a.example.com").await;
    assert!(
        !ctx.metadata
            .contains_key(&staging_key(&cache, "cache_pending_invalidate_host")),
        "pending invalidation must be consumed exactly once"
    );
}

/// An earlier after_proxy rejection of an origin *error* must still leave the
/// cache intact — only non-error origin status invalidates.
#[tokio::test]
async fn test_earlier_after_proxy_reject_of_origin_error_does_not_invalidate() {
    let _policy_guard = response_cache_replay_policy_guard();
    let cache = Arc::new(default_plugin());
    let size_limit = Arc::new(
        ResponseSizeLimiting::new(&json!({ "max_bytes": 8 })).expect("size limiter config"),
    );

    cache_response_with_host(
        &cache,
        "GET",
        "/api/items",
        Some("a.example.com"),
        200,
        &HashMap::new(),
        b"fresh",
    )
    .await;

    let mut ctx = make_ctx("POST", "/api/items");
    ctx.headers
        .insert("host".to_string(), "a.example.com".to_string());
    let mut req_headers = HashMap::new();
    req_headers.insert("host".to_string(), "a.example.com".to_string());
    assert!(matches!(
        cache.before_proxy(&mut ctx, &mut req_headers).await,
        PluginResult::Continue
    ));

    let plugins: Vec<Arc<dyn Plugin>> = vec![size_limit, cache.clone()];
    let mut resp_headers = HashMap::new();
    resp_headers.insert("content-length".to_string(), "64".to_string());
    let reject = run_after_proxy_hooks_reject_for_test(&plugins, &mut ctx, 500, &mut resp_headers)
        .await
        .expect("size limiter must reject oversized origin error body");
    assert_eq!(reject.0, 502);

    assert_cache_hit_for_host(&cache, "/api/items", "a.example.com", b"fresh").await;
}

/// Public metadata cannot forge origin success: without private provenance and
/// without a genuine after_proxy status argument that is non-error, staged
/// invalidation must not fire from spoofed metadata alone.
#[tokio::test]
async fn test_forged_public_backend_status_metadata_cannot_force_invalidation() {
    let _policy_guard = response_cache_replay_policy_guard();
    let plugin = default_plugin();

    cache_response(
        &plugin,
        "GET",
        "/api/items",
        200,
        &HashMap::new(),
        b"protected",
    )
    .await;

    let mut ctx = make_ctx("POST", "/api/items");
    let mut headers = HashMap::new();
    assert!(matches!(
        plugin.before_proxy(&mut ctx, &mut headers).await,
        PluginResult::Continue
    ));
    // Spoof the AI rate-limiter public metadata key — invalidation must ignore it.
    ctx.metadata
        .insert("ai_ratelimit_backend_status".to_string(), "200".to_string());

    let mut resp_headers = HashMap::new();
    plugin.after_proxy(&mut ctx, 500, &mut resp_headers).await;

    let mut get_ctx = make_ctx("GET", "/api/items");
    let mut get_headers = HashMap::new();
    assert!(
        is_reject(&plugin.before_proxy(&mut get_ctx, &mut get_headers).await),
        "forged public metadata must not invalidate on an error after_proxy status"
    );
}

/// Sibling response_caching instances must not consume or overwrite each
/// other's pending invalidation staging.
#[tokio::test]
async fn test_sibling_instances_do_not_consume_each_others_pending_invalidation() {
    let _policy_guard = response_cache_replay_policy_guard();
    let instance_a = plugin_with_config(json!({
        "invalidate_on_unsafe_methods": true,
        "cache_key_include_query": true
    }));
    let instance_b = plugin_with_config(json!({
        "invalidate_on_unsafe_methods": true,
        "cache_key_include_query": false
    }));
    assert_ne!(
        response_caching_instance_id_for_test(&instance_a),
        response_caching_instance_id_for_test(&instance_b)
    );

    cache_response(
        &instance_a,
        "GET",
        "/api/items",
        200,
        &HashMap::new(),
        b"a-body",
    )
    .await;
    cache_response(
        &instance_b,
        "GET",
        "/api/items",
        200,
        &HashMap::new(),
        b"b-body",
    )
    .await;

    let mut ctx = make_ctx("DELETE", "/api/items");
    let mut headers = HashMap::new();
    assert!(matches!(
        instance_a.before_proxy(&mut ctx, &mut headers).await,
        PluginResult::Continue
    ));
    assert!(matches!(
        instance_b.before_proxy(&mut ctx, &mut headers).await,
        PluginResult::Continue
    ));

    let key_a = staging_key(&instance_a, "cache_pending_invalidate_host");
    let key_b = staging_key(&instance_b, "cache_pending_invalidate_host");
    assert_ne!(key_a, key_b);
    assert!(ctx.metadata.contains_key(&key_a));
    assert!(ctx.metadata.contains_key(&key_b));

    // Instance A observes origin success and consumes only its own staging.
    instance_a.observe_origin_http_response_status(&mut ctx, 204);
    assert!(!ctx.metadata.contains_key(&key_a));
    assert!(
        ctx.metadata.contains_key(&key_b),
        "sibling pending invalidation must survive the other instance's observe"
    );

    let mut miss_a = make_ctx("GET", "/api/items");
    let mut miss_headers = HashMap::new();
    assert!(matches!(
        instance_a
            .before_proxy(&mut miss_a, &mut miss_headers)
            .await,
        PluginResult::Continue
    ));

    // Instance B has not observed success yet — its entry remains.
    let mut hit_b = make_ctx("GET", "/api/items");
    let mut hit_headers = HashMap::new();
    assert!(is_reject(
        &instance_b.before_proxy(&mut hit_b, &mut hit_headers).await
    ));

    instance_b.observe_origin_http_response_status(&mut ctx, 204);
    assert!(!ctx.metadata.contains_key(&key_b));
    let mut miss_b = make_ctx("GET", "/api/items");
    let mut miss_b_headers = HashMap::new();
    assert!(matches!(
        instance_b
            .before_proxy(&mut miss_b, &mut miss_b_headers)
            .await,
        PluginResult::Continue
    ));
}

/// Full lifecycle: observe via `run_after_proxy_hooks` then a later after_proxy
/// pass must not double-apply (staging already consumed).
#[tokio::test]
async fn test_observe_then_after_proxy_does_not_double_invalidate() {
    let _policy_guard = response_cache_replay_policy_guard();
    let cache = Arc::new(default_plugin());

    cache_response(&cache, "GET", "/api/items", 200, &HashMap::new(), b"once").await;

    let mut ctx = make_ctx("POST", "/api/items");
    let mut headers = HashMap::new();
    assert!(matches!(
        cache.before_proxy(&mut ctx, &mut headers).await,
        PluginResult::Continue
    ));

    let plugins: Vec<Arc<dyn Plugin>> = vec![cache.clone()];
    let mut resp_headers = HashMap::new();
    assert!(
        !run_after_proxy_hooks_for_test(&plugins, &mut ctx, 200, &mut resp_headers).await,
        "caching after_proxy must Continue"
    );
    assert!(
        !ctx.metadata
            .contains_key(&staging_key(&cache, "cache_pending_invalidate_host"))
    );

    // Re-store and prove a second after_proxy without fresh staging is a no-op.
    cache_response(&cache, "GET", "/api/items", 200, &HashMap::new(), b"again").await;
    let mut resp_headers = HashMap::new();
    cache.after_proxy(&mut ctx, 200, &mut resp_headers).await;
    let mut hit_ctx = make_ctx("GET", "/api/items");
    let mut hit_headers = HashMap::new();
    let (_, body, _) = expect_reject(cache.before_proxy(&mut hit_ctx, &mut hit_headers).await);
    assert_eq!(body, b"again");
}

// ---------------------------------------------------------------------------
// Replay-partition contract (GHSA-w27g-65rf-h7xm, GHSA-v4g3-2r4f-f6pc,
// GHSA-37gg-v9m4-8445)
//
// Each test proves a HIT cannot cross one omitted boundary: it seeds an entry
// under one partition and asserts the peer request MISSes.
// ---------------------------------------------------------------------------

/// Seed one cacheable GET through the full lifecycle using an explicitly built
/// context, then return that context's staged base key.
async fn seed_public_entry(plugin: &ResponseCaching, ctx: &mut RequestContext, body: &[u8]) {
    set_replay_request_body_empty_proven_for_test(ctx, true);
    set_response_presentation_policy_digest_for_test(ctx, Some([0x51; 32]));
    let mut headers = ctx.headers.clone();
    assert!(matches!(
        plugin.before_proxy(ctx, &mut headers).await,
        PluginResult::Continue
    ));
    let mut response_headers = HashMap::new();
    response_headers.insert(
        "cache-control".to_string(),
        "public, max-age=60".to_string(),
    );
    plugin
        .on_final_response_body(ctx, 200, &response_headers, body)
        .await;
}

async fn lookup_is_hit(plugin: &ResponseCaching, ctx: &mut RequestContext) -> bool {
    set_replay_request_body_empty_proven_for_test(ctx, true);
    set_response_presentation_policy_digest_for_test(ctx, Some([0x51; 32]));
    let mut headers = ctx.headers.clone();
    is_reject(&plugin.before_proxy(ctx, &mut headers).await)
}

#[tokio::test]
async fn replay_partition_isolates_same_subject_different_credential_scope() {
    let _policy_guard = response_cache_replay_policy_guard();
    let plugin = plugin_with_config(json!({ "ttl_seconds": 60 }));

    // One display subject, two credentials. The old partition keyed only the
    // subject, so the second caller replayed the first caller's response.
    let mut narrow = make_ctx("GET", "/api/reports");
    narrow.authenticated_identity = Some("alice@example.com".to_string());
    narrow.headers.insert(
        "authorization".to_string(),
        "Bearer scope-read-only".to_string(),
    );
    seed_public_entry(&plugin, &mut narrow, b"read-only-view").await;

    let mut broad = make_ctx("GET", "/api/reports");
    broad.authenticated_identity = Some("alice@example.com".to_string());
    broad.headers.insert(
        "authorization".to_string(),
        "Bearer scope-read-write-admin".to_string(),
    );
    assert!(
        !lookup_is_hit(&plugin, &mut broad).await,
        "a different credential for the same subject must not replay"
    );
}

#[tokio::test]
async fn replay_partition_isolates_anonymous_callers_by_canonical_address() {
    let _policy_guard = response_cache_replay_policy_guard();
    let plugin = plugin_with_config(json!({ "ttl_seconds": 60 }));

    let mut first = RequestContext::new(
        "203.0.113.7".to_string(),
        "GET".to_string(),
        "/public".to_string(),
    );
    first.matched_proxy = Some(Arc::new(create_test_proxy()));
    seed_public_entry(&plugin, &mut first, b"geo-a").await;

    let mut second = RequestContext::new(
        "198.51.100.9".to_string(),
        "GET".to_string(),
        "/public".to_string(),
    );
    second.matched_proxy = Some(Arc::new(create_test_proxy()));
    assert!(
        !lookup_is_hit(&plugin, &mut second).await,
        "anonymous callers at different canonical addresses must not share an entry"
    );

    // The same address still hits.
    let mut same = RequestContext::new(
        "203.0.113.7".to_string(),
        "GET".to_string(),
        "/public".to_string(),
    );
    same.matched_proxy = Some(Arc::new(create_test_proxy()));
    assert!(
        lookup_is_hit(&plugin, &mut same).await,
        "the same canonical address must still hit"
    );
}

#[tokio::test]
async fn anonymous_caller_scope_shared_is_an_explicit_operator_opt_out() {
    let _policy_guard = response_cache_replay_policy_guard();
    let plugin = plugin_with_config(json!({
        "ttl_seconds": 60,
        "anonymous_caller_scope": "shared"
    }));

    let mut first = RequestContext::new(
        "203.0.113.7".to_string(),
        "GET".to_string(),
        "/public".to_string(),
    );
    first.matched_proxy = Some(Arc::new(create_test_proxy()));
    seed_public_entry(&plugin, &mut first, b"shared-body").await;

    let mut second = RequestContext::new(
        "198.51.100.9".to_string(),
        "GET".to_string(),
        "/public".to_string(),
    );
    second.matched_proxy = Some(Arc::new(create_test_proxy()));
    assert!(
        lookup_is_hit(&plugin, &mut second).await,
        "the explicit shared attestation must let anonymous callers share"
    );

    assert!(
        ResponseCaching::new(&json!({ "anonymous_caller_scope": "everyone" })).is_err(),
        "an unknown anonymous_caller_scope must fail closed"
    );
}

/// Build a context whose *pristine inbound* credential differs from the *live*
/// backend-visible one, exactly as `ai_stream_router` leaves it: the client's
/// token is stripped and the selected provider's key is injected.
///
/// `response_caching` runs at priority 3500, after `ai_stream_router` at 2984,
/// so the live view it is handed no longer distinguishes the two clients.
fn ctx_with_rewritten_credential(
    client_token: &str,
    provider_key: &str,
    client_ip: &str,
) -> RequestContext {
    let mut ctx = RequestContext::new(
        client_ip.to_string(),
        "GET".to_string(),
        "/v1/models".to_string(),
    );
    ctx.matched_proxy = Some(Arc::new(create_test_proxy()));

    let mut raw = http::HeaderMap::new();
    raw.insert(
        http::header::AUTHORIZATION,
        http::HeaderValue::from_str(client_token).expect("client token"),
    );
    ctx.set_raw_headers(raw);

    // The live, backend-visible view an earlier router already rewrote. Both
    // callers present the *same* bytes here — only the retained wire view can
    // still tell them apart.
    ctx.headers
        .insert("authorization".to_string(), provider_key.to_string());
    ctx
}

/// GHSA-w27g-65rf-h7xm: two client tokens that an earlier route-dispatch plugin
/// replaced with one provider credential must not collapse onto one partition.
/// Binding only the live `before_proxy` header view did exactly that.
#[tokio::test]
async fn replay_partition_survives_an_earlier_credential_rewrite() {
    let _policy_guard = response_cache_replay_policy_guard();
    let plugin = plugin_with_config(json!({ "ttl_seconds": 60 }));

    let mut narrow = ctx_with_rewritten_credential(
        "Bearer client-token-read-only",
        "Bearer sk-provider-shared",
        "203.0.113.7",
    );
    seed_public_entry(&plugin, &mut narrow, b"read-only-view").await;

    // Same rewritten live credential, same address, same target — only the
    // original inbound token differs.
    let mut broad = ctx_with_rewritten_credential(
        "Bearer client-token-read-write-admin",
        "Bearer sk-provider-shared",
        "203.0.113.7",
    );
    assert!(
        !lookup_is_hit(&plugin, &mut broad).await,
        "an earlier router rewrite must not erase the original caller distinction"
    );

    // The identical original caller still hits, so the binding is a partition
    // and not a blanket cache disable.
    let mut same = ctx_with_rewritten_credential(
        "Bearer client-token-read-only",
        "Bearer sk-provider-shared",
        "203.0.113.7",
    );
    assert!(
        lookup_is_hit(&plugin, &mut same).await,
        "the same original caller must still hit"
    );
}

fn ctx_with_stripped_custom_credential(token: &str) -> RequestContext {
    let mut ctx = RequestContext::new(
        "203.0.113.7".to_string(),
        "GET".to_string(),
        "/custom-auth".to_string(),
    );
    ctx.matched_proxy = Some(Arc::new(create_test_proxy()));
    ctx.authenticated_identity = Some("alice@example.com".to_string());
    set_replay_credential_headers_for_test(&mut ctx, vec!["x-tenant-jwt".to_string()]);
    let mut raw = http::HeaderMap::new();
    raw.insert(
        "x-tenant-jwt",
        http::HeaderValue::from_str(token).expect("custom credential"),
    );
    ctx.set_raw_headers(raw);
    ctx
}

/// A configured credential header is part of the authorization context even
/// when it is not one of the conservative built-in names and auth stripped it
/// from the live backend view.
#[tokio::test]
async fn replay_partition_binds_stripped_custom_credential_headers() {
    let _policy_guard = response_cache_replay_policy_guard();
    let plugin = plugin_with_config(json!({ "ttl_seconds": 60 }));

    let mut narrow = ctx_with_stripped_custom_credential("scope-read-only");
    seed_public_entry(&plugin, &mut narrow, b"read-only-view").await;

    let mut broad = ctx_with_stripped_custom_credential("scope-read-write-admin");
    assert!(
        !lookup_is_hit(&plugin, &mut broad).await,
        "custom credential locations must not collapse onto one resolved subject"
    );

    let mut same = ctx_with_stripped_custom_credential("scope-read-only");
    assert!(lookup_is_hit(&plugin, &mut same).await);
}

fn ctx_with_query_credential(token: &str) -> RequestContext {
    let mut ctx = RequestContext::new(
        "203.0.113.7".to_string(),
        "GET".to_string(),
        "/query-auth".to_string(),
    );
    ctx.matched_proxy = Some(Arc::new(create_test_proxy()));
    ctx.authenticated_identity = Some("alice@example.com".to_string());
    ctx.set_raw_query_string(format!("access_token={token}"));
    ctx.materialize_query_params();
    let auth = ferrum_edge::plugins::jwt_auth::JwtAuth::new(
        &json!({ "token_lookup": "query:access_token" }),
    )
    .expect("query JWT config");
    auth.mark_query_credentials_for_redaction(&mut ctx);
    ctx
}

/// Query exclusion is an origin-cache policy, not permission to erase an
/// authentication credential from the mandatory caller partition.
#[tokio::test]
async fn replay_partition_binds_query_credentials_when_cache_key_excludes_query() {
    let _policy_guard = response_cache_replay_policy_guard();
    let plugin = plugin_with_config(json!({
        "ttl_seconds": 60,
        "cache_key_include_query": false
    }));

    let mut narrow = ctx_with_query_credential("scope-read-only");
    seed_public_entry(&plugin, &mut narrow, b"read-only-view").await;

    let mut broad = ctx_with_query_credential("scope-read-write-admin");
    assert!(
        !lookup_is_hit(&plugin, &mut broad).await,
        "excluding ordinary query state must not exclude a query credential"
    );

    let mut same = ctx_with_query_credential("scope-read-only");
    assert!(lookup_is_hit(&plugin, &mut same).await);
}

/// The backend receives Ferrum's regenerated forwarding identity for
/// authenticated callers too, so it may vary policy or content by address
/// independently of the credential.
#[tokio::test]
async fn replay_partition_isolates_authenticated_callers_by_canonical_address() {
    let _policy_guard = response_cache_replay_policy_guard();
    let plugin = plugin_with_config(json!({ "ttl_seconds": 60 }));

    let mut first = RequestContext::new(
        "203.0.113.7".to_string(),
        "GET".to_string(),
        "/api/reports".to_string(),
    );
    first.matched_proxy = Some(Arc::new(create_test_proxy()));
    first.authenticated_identity = Some("alice@example.com".to_string());
    first.headers.insert(
        "authorization".to_string(),
        "Bearer scope-read-only".to_string(),
    );
    seed_public_entry(&plugin, &mut first, b"office-view").await;

    let mut elsewhere = RequestContext::new(
        "198.51.100.9".to_string(),
        "GET".to_string(),
        "/api/reports".to_string(),
    );
    elsewhere.matched_proxy = Some(Arc::new(create_test_proxy()));
    elsewhere.authenticated_identity = Some("alice@example.com".to_string());
    elsewhere.headers.insert(
        "authorization".to_string(),
        "Bearer scope-read-only".to_string(),
    );
    assert!(
        !lookup_is_hit(&plugin, &mut elsewhere).await,
        "one authenticated caller at two canonical addresses must not share an entry"
    );
}

/// `anonymous_caller_scope: shared` is an attestation about *anonymous* callers.
/// It must not relax the authenticated caller's address binding.
#[tokio::test]
async fn shared_anonymous_scope_does_not_relax_authenticated_callers() {
    let _policy_guard = response_cache_replay_policy_guard();
    let plugin = plugin_with_config(json!({
        "ttl_seconds": 60,
        "anonymous_caller_scope": "shared"
    }));

    let mut first = RequestContext::new(
        "203.0.113.7".to_string(),
        "GET".to_string(),
        "/api/reports".to_string(),
    );
    first.matched_proxy = Some(Arc::new(create_test_proxy()));
    first.authenticated_identity = Some("alice@example.com".to_string());
    first.headers.insert(
        "authorization".to_string(),
        "Bearer scope-read-only".to_string(),
    );
    seed_public_entry(&plugin, &mut first, b"office-view").await;

    let mut elsewhere = RequestContext::new(
        "198.51.100.9".to_string(),
        "GET".to_string(),
        "/api/reports".to_string(),
    );
    elsewhere.matched_proxy = Some(Arc::new(create_test_proxy()));
    elsewhere.authenticated_identity = Some("alice@example.com".to_string());
    elsewhere.headers.insert(
        "authorization".to_string(),
        "Bearer scope-read-only".to_string(),
    );
    assert!(
        !lookup_is_hit(&plugin, &mut elsewhere).await,
        "the shared attestation covers anonymous callers only"
    );
}

#[tokio::test]
async fn replay_partition_isolates_effective_route_destination() {
    let _policy_guard = response_cache_replay_policy_guard();
    let plugin = plugin_with_config(json!({ "ttl_seconds": 60 }));

    let mut tenant_a = make_ctx("GET", "/api/data");
    tenant_a.route_override_upstream_id = Some("tenant-a".to_string());
    seed_public_entry(&plugin, &mut tenant_a, b"tenant-a-body").await;

    let mut tenant_b = make_ctx("GET", "/api/data");
    tenant_b.route_override_upstream_id = Some("tenant-b".to_string());
    assert!(
        !lookup_is_hit(&plugin, &mut tenant_b).await,
        "a header-selected upstream must not replay another backend's response"
    );

    let mut rewritten = make_ctx("GET", "/api/data");
    rewritten.route_override_upstream_id = Some("tenant-a".to_string());
    rewritten.route_override_path = Some("/internal/data".to_string());
    assert!(
        !lookup_is_hit(&plugin, &mut rewritten).await,
        "a post-routing path rewrite must not replay the unrewritten destination"
    );
}

#[tokio::test]
async fn vary_tuple_framing_defeats_delimiter_collisions() {
    let _policy_guard = response_cache_replay_policy_guard();
    let plugin = plugin_with_config(json!({
        "ttl_seconds": 60,
        "vary_by_headers": ["x-a", "x-b"]
    }));

    // The advisory's exact collision pair. Under `name=value|name=value` both
    // serialized to `x-a=foo|x-b=bar|x-b=baz`.
    let mut first = make_ctx("GET", "/vary");
    first.headers.insert("x-a".to_string(), "foo".to_string());
    first
        .headers
        .insert("x-b".to_string(), "bar|x-b=baz".to_string());
    seed_public_entry(&plugin, &mut first, b"first-tuple").await;

    let mut second = make_ctx("GET", "/vary");
    second
        .headers
        .insert("x-a".to_string(), "foo|x-b=bar".to_string());
    second.headers.insert("x-b".to_string(), "baz".to_string());
    assert!(
        !lookup_is_hit(&plugin, &mut second).await,
        "delimiter-bearing Vary values must not collide onto one cache key"
    );
}

#[tokio::test]
async fn vary_framing_distinguishes_absent_empty_and_newline_values() {
    let _policy_guard = response_cache_replay_policy_guard();
    let plugin = plugin_with_config(json!({
        "ttl_seconds": 60,
        "vary_by_headers": ["x-a", "x-b"]
    }));

    let mut absent = make_ctx("GET", "/vary2");
    absent.headers.insert("x-a".to_string(), "v".to_string());
    seed_public_entry(&plugin, &mut absent, b"absent-b").await;

    let mut empty = make_ctx("GET", "/vary2");
    empty.headers.insert("x-a".to_string(), "v".to_string());
    empty.headers.insert("x-b".to_string(), String::new());
    assert!(
        !lookup_is_hit(&plugin, &mut empty).await,
        "an absent Vary header must not share a key with an empty one"
    );

    let mut newline = make_ctx("GET", "/vary2");
    newline.headers.insert("x-a".to_string(), "v".to_string());
    newline
        .headers
        .insert("x-b".to_string(), "\nx-a=v".to_string());
    assert!(
        !lookup_is_hit(&plugin, &mut newline).await,
        "a newline-bearing Vary value must not forge a field boundary"
    );
}

#[tokio::test]
async fn replay_partition_isolates_query_and_path_delimiters() {
    let _policy_guard = response_cache_replay_policy_guard();
    let plugin = plugin_with_config(json!({ "ttl_seconds": 60 }));

    let mut colon = make_ctx_with_raw_query("GET", "/items:1", "a=b");
    seed_public_entry(&plugin, &mut colon, b"colon-body").await;

    // The same bytes redistributed across the path/query boundary must be a
    // different partition.
    let mut shifted = make_ctx_with_raw_query("GET", "/items", ":1:a=b");
    assert!(
        !lookup_is_hit(&plugin, &mut shifted).await,
        "path/query boundary must be unambiguous"
    );
}

/// An origin-visible request header the backend never nominates in `Vary` is
/// already bound by the conservative base partition. `vary_by_headers` remains
/// an additional operator-declared `Vary` dimension, including its explicit
/// absent-versus-present behavior, and must continue to agree at lookup/store.
#[tokio::test]
async fn replay_partition_binds_vary_by_headers_the_backend_never_nominates() {
    let _policy_guard = response_cache_replay_policy_guard();
    let plugin = plugin_with_config(json!({
        "ttl_seconds": 60,
        "vary_by_headers": ["x-tenant-policy"]
    }));

    let mut tenant_a = make_ctx("GET", "/reports");
    tenant_a
        .headers
        .insert("x-tenant-policy".to_string(), "read-only".to_string());
    seed_public_entry(&plugin, &mut tenant_a, b"tenant-a-view").await;

    let mut tenant_b = make_ctx("GET", "/reports");
    tenant_b
        .headers
        .insert("x-tenant-policy".to_string(), "admin".to_string());
    assert!(
        !lookup_is_hit(&plugin, &mut tenant_b).await,
        "a configured Vary dimension must partition replay without backend Vary"
    );

    let mut absent = make_ctx("GET", "/reports");
    assert!(
        !lookup_is_hit(&plugin, &mut absent).await,
        "an absent dimension is distinct from a present one"
    );

    let mut same = make_ctx("GET", "/reports");
    same.headers
        .insert("x-tenant-policy".to_string(), "read-only".to_string());
    assert!(lookup_is_hit(&plugin, &mut same).await);
}

#[tokio::test]
async fn replay_partition_binds_effective_transformed_query() {
    let _policy_guard = response_cache_replay_policy_guard();
    let plugin = plugin_with_config(json!({
        "ttl_seconds": 60,
        "cache_key_include_query": false
    }));

    let mut tenant_a = make_ctx_with_raw_query("GET", "/reports", "tenant=wire");
    tenant_a.publish_transformed_query(
        "tenant=a".to_string(),
        HashMap::from([("tenant".to_string(), "a".to_string())]),
    );
    seed_public_entry(&plugin, &mut tenant_a, b"tenant-a-view").await;

    let mut tenant_b = make_ctx_with_raw_query("GET", "/reports", "tenant=wire");
    tenant_b.publish_transformed_query(
        "tenant=b".to_string(),
        HashMap::from([("tenant".to_string(), "b".to_string())]),
    );
    assert!(
        !lookup_is_hit(&plugin, &mut tenant_b).await,
        "the backend-effective transformed query must partition replay"
    );
}

#[tokio::test]
async fn saturated_cache_evicts_in_bounded_batches_with_exact_accounting() {
    let _policy_guard = response_cache_replay_policy_guard();
    let max_entries = 32;
    let plugin = plugin_with_config(json!({
        "ttl_seconds": 300,
        "max_entries": max_entries,
    }));

    // Far more unique targets than the cap: the FIFO must hold the cache at the
    // cap with exact byte accounting and no stranded vary_index mappings.
    for i in 0..(max_entries * 8) {
        let mut ctx = make_ctx("GET", &format!("/unique/{i}"));
        seed_public_entry(&plugin, &mut ctx, b"body").await;
    }

    assert_eq!(
        response_caching_cache_keys_for_test(&plugin).len(),
        max_entries,
        "cache must stay pinned at max_entries"
    );
    assert_size_accounting_exact(&plugin);
    assert!(
        response_caching_vary_index_snapshot_for_test(&plugin).len()
            <= response_caching_cache_keys_for_test(&plugin).len(),
        "vary_index must never exceed the live base-key count"
    );
    assert!(response_caching_current_total_size_for_test(&plugin) > 0);
}

#[tokio::test]
async fn invalidation_index_removes_only_the_mutated_subtree() {
    let _policy_guard = response_cache_replay_policy_guard();
    let plugin = plugin_with_config(json!({ "ttl_seconds": 300 }));

    for path in ["/api/items", "/api/items/1", "/api/itemsX", "/api/other"] {
        cache_response_with_host(
            &plugin,
            "GET",
            path,
            Some("a.example.com"),
            200,
            &HashMap::new(),
            b"seed",
        )
        .await;
    }
    // Another authority must be untouched by the sweep.
    cache_response_with_host(
        &plugin,
        "GET",
        "/api/items",
        Some("b.example.com"),
        200,
        &HashMap::new(),
        b"other-authority",
    )
    .await;

    unsafe_method_cycle(&plugin, "DELETE", "/api/items", Some("a.example.com"), 204).await;

    assert_cache_miss_for_host(&plugin, "/api/items", "a.example.com").await;
    assert_cache_miss_for_host(&plugin, "/api/items/1", "a.example.com").await;
    assert_cache_hit_for_host(&plugin, "/api/itemsX", "a.example.com", b"seed").await;
    assert_cache_hit_for_host(&plugin, "/api/other", "a.example.com", b"seed").await;
    assert_cache_hit_for_host(&plugin, "/api/items", "b.example.com", b"other-authority").await;
    assert_size_accounting_exact(&plugin);
}

#[tokio::test]
async fn predictor_stays_bounded_without_sorting_at_capacity() {
    let _policy_guard = response_cache_replay_policy_guard();
    // `max_entries / 10`, floored at 100, sizes the predictor.
    let plugin = plugin_with_config(json!({ "ttl_seconds": 300, "max_entries": 200 }));

    // A stream of unique uncacheable targets: every response carries Set-Cookie,
    // which marks the exact variant uncacheable.
    let mut response_headers = HashMap::new();
    response_headers.insert("set-cookie".to_string(), "s=1".to_string());
    for i in 0..2000 {
        let mut ctx = make_ctx("GET", &format!("/uncacheable/{i}"));
        let mut headers = ctx.headers.clone();
        plugin.before_proxy(&mut ctx, &mut headers).await;
        plugin
            .on_final_response_body(&mut ctx, 200, &response_headers, b"body")
            .await;
    }

    // Nothing was stored, accounting stayed exact, and the run completed
    // without a per-admission full sort.
    assert!(response_caching_cache_keys_for_test(&plugin).is_empty());
    assert_size_accounting_exact(&plugin);
}

#[tokio::test]
async fn concurrent_writers_keep_exact_entry_and_byte_accounting() {
    let _policy_guard = response_cache_replay_policy_guard();
    let max_entries = 64;
    let plugin = Arc::new(plugin_with_config(json!({
        "ttl_seconds": 300,
        "max_entries": max_entries,
    })));

    let mut tasks = Vec::new();
    for worker in 0..8 {
        let plugin = Arc::clone(&plugin);
        tasks.push(tokio::spawn(async move {
            for i in 0..64 {
                let mut ctx = make_ctx("GET", &format!("/w{worker}/{i}"));
                let mut headers = ctx.headers.clone();
                plugin.before_proxy(&mut ctx, &mut headers).await;
                let mut response_headers = HashMap::new();
                response_headers.insert(
                    "cache-control".to_string(),
                    "public, max-age=300".to_string(),
                );
                plugin
                    .on_final_response_body(&mut ctx, 200, &response_headers, b"concurrent")
                    .await;
            }
        }));
    }
    for task in tasks {
        task.await.expect("writer task");
    }

    let keys = response_caching_cache_keys_for_test(&plugin);
    assert!(
        keys.len() <= max_entries,
        "concurrent writers must respect max_entries; got {}",
        keys.len()
    );
    assert_size_accounting_exact(&plugin);
}

// ---------------------------------------------------------------------------
// GHSA-pwcm-6rh8-f2gh — response buffering must be released as soon as the
// store path is provably unreachable, instead of collecting a body that
// `on_final_response_body` will discard unread.
// ---------------------------------------------------------------------------

fn response_headers_from(pairs: &[(&str, &str)]) -> HashMap<String, String> {
    pairs
        .iter()
        .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
        .collect()
}

/// A request-side fact `before_proxy` established must reach the buffering vote.
#[tokio::test]
async fn uncacheable_method_releases_the_response_buffer() {
    let plugin = default_plugin();
    let mut ctx = make_ctx("POST", "/api/orders");
    let mut headers = HashMap::new();

    assert!(
        plugin.should_buffer_response_body(&ctx),
        "before before_proxy the vote must stay conservative"
    );

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
    assert_status(&plugin, &ctx, "BYPASS");
    assert!(
        !plugin.should_buffer_response_body(&ctx),
        "an uncacheable method has no store path, so the body must stream"
    );
}

#[tokio::test]
async fn request_no_store_releases_the_response_buffer_and_does_not_store() {
    let plugin = default_plugin();
    let mut ctx = make_ctx("GET", "/api/no-store");
    let mut headers = HashMap::new();
    headers.insert("cache-control".to_string(), "no-store".to_string());

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
    assert_status(&plugin, &ctx, "BYPASS");
    assert!(!plugin.should_buffer_response_body(&ctx));

    // RFC 9111 §5.2.1.5: nothing from a `no-store` request may be retained.
    let response_headers = public_response_headers();
    plugin
        .on_final_response_body(&mut ctx, 200, &response_headers, b"secret")
        .await;
    assert!(
        response_caching_cache_keys_for_test(&plugin).is_empty(),
        "a no-store request must not produce a stored representation"
    );
}

#[tokio::test]
async fn request_with_a_body_releases_the_response_buffer() {
    let plugin = default_plugin();
    let mut ctx = make_ctx("GET", "/api/with-body");
    set_replay_request_body_empty_proven_for_test(&mut ctx, false);
    let mut headers = HashMap::new();

    plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_status(&plugin, &ctx, "BYPASS");
    assert!(!plugin.should_buffer_response_body(&ctx));
}

#[tokio::test]
async fn predicted_uncacheable_variant_releases_and_re_learns() {
    let plugin = default_plugin();

    // Teach the predictor: 500 is not in the default cacheable status set
    // (`[200, 301, 404]`), so the store path marks this variant uncacheable.
    let mut ctx = make_ctx("GET", "/api/always-500");
    let mut headers = HashMap::new();
    plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_status(&plugin, &ctx, "MISS");
    plugin
        .on_final_response_body(&mut ctx, 500, &public_response_headers(), b"boom")
        .await;

    // Next request rides the prediction: no lookup, no store, no buffer.
    let mut ctx = make_ctx("GET", "/api/always-500");
    let mut headers = HashMap::new();
    plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_status(&plugin, &ctx, "PREDICTED-BYPASS");
    assert!(
        !plugin.should_buffer_response_body(&ctx),
        "a variant already known to be uncacheable must not be buffered again"
    );

    // The mark is retired in the same step, so the variant is re-learned on the
    // following request rather than being starved of a store attempt forever.
    let mut ctx = make_ctx("GET", "/api/always-500");
    let mut headers = HashMap::new();
    plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_status(&plugin, &ctx, "MISS");
    assert!(plugin.should_buffer_response_body(&ctx));
}

#[tokio::test]
async fn origin_selected_sse_is_released_after_headers() {
    let plugin = default_plugin();
    let mut ctx = make_ctx("GET", "/api/events");
    let mut headers = HashMap::new();
    // No `Accept: text/event-stream` — the request side cannot predict this.
    plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_status(&plugin, &ctx, "MISS");
    assert!(plugin.should_buffer_response_body(&ctx));

    let response_headers = response_headers_from(&[
        ("content-type", "text/event-stream"),
        ("cache-control", "public, max-age=60"),
    ]);
    assert!(
        !plugin.should_buffer_response_body_for_content_type(
            &ctx,
            Some("text/event-stream"),
            200,
            &response_headers,
        ),
        "an origin-selected event stream must not be collected until termination"
    );
}

#[tokio::test]
async fn uncacheable_status_range_and_set_cookie_are_released_after_headers() {
    let plugin = default_plugin();
    let mut ctx = make_ctx("GET", "/api/resource");
    let mut headers = HashMap::new();
    plugin.before_proxy(&mut ctx, &mut headers).await;

    let plain = response_headers_from(&[("content-type", "application/octet-stream")]);
    assert!(
        !plugin.should_buffer_response_body_for_content_type(
            &ctx,
            Some("application/octet-stream"),
            500,
            &plain,
        ),
        "a status outside cacheable_status_codes has no store path"
    );

    let ranged = response_headers_from(&[
        ("content-type", "video/mp4"),
        ("content-range", "bytes 0-1023/999999999"),
    ]);
    assert!(
        !plugin.should_buffer_response_body_for_content_type(&ctx, Some("video/mp4"), 206, &ranged),
        "a partial representation is never stored as a reusable entry"
    );

    let cookied = response_headers_from(&[
        ("content-type", "application/json"),
        ("set-cookie", "session=abc"),
    ]);
    assert!(
        !plugin.should_buffer_response_body_for_content_type(
            &ctx,
            Some("application/json"),
            200,
            &cookied,
        ),
        "a per-client Set-Cookie response is never stored"
    );
}

/// A response whose store-side refusal ALSO evicts is released too, because the
/// eviction is header-only and now runs in the final response-header phase.
/// Releasing it and skipping the eviction would be the bug; releasing it and
/// performing the eviction is the fix.
#[tokio::test]
async fn invalidating_response_directives_release_and_still_evict() {
    let _policy_guard = response_cache_replay_policy_guard();

    for directive in ["no-store", "private", "no-cache", "max-age=0"] {
        let plugin = Arc::new(default_plugin());
        cache_response(
            &plugin,
            "GET",
            "/api/resource",
            200,
            &HashMap::new(),
            b"old",
        )
        .await;
        assert_eq!(
            response_caching_cache_keys_for_test(&plugin).len(),
            1,
            "seeded entry for `{directive}`"
        );

        let mut ctx = refresh_ctx(&plugin, "/api/resource").await;

        let response_headers = response_headers_from(&[
            ("content-type", "application/json"),
            ("cache-control", directive),
        ]);
        assert!(
            !plugin.should_buffer_response_body_for_content_type(
                &ctx,
                Some("application/json"),
                200,
                &response_headers,
            ),
            "`{directive}` is decidable from headers, so the body must stream"
        );

        // Streaming path: the body hook never runs, only the header phase does.
        assert!(!run_final_response_header_phase(&plugin, &mut ctx, 200, &response_headers).await);
        assert!(
            response_caching_cache_keys_for_test(&plugin).is_empty(),
            "`{directive}` must still evict the entry it supersedes, streamed or not"
        );
    }
}

/// An ordinary cacheable response is unaffected by every narrowing above.
#[tokio::test]
async fn ordinary_cacheable_response_still_buffers_and_stores() {
    let plugin = default_plugin();
    let mut ctx = make_ctx("GET", "/api/widgets");
    let mut headers = HashMap::new();
    plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_status(&plugin, &ctx, "MISS");
    assert!(plugin.should_buffer_response_body(&ctx));

    let response_headers = response_headers_from(&[
        ("content-type", "application/json"),
        ("cache-control", "public, max-age=60"),
    ]);
    assert!(plugin.should_buffer_response_body_for_content_type(
        &ctx,
        Some("application/json"),
        200,
        &response_headers,
    ));
    plugin
        .on_final_response_body(&mut ctx, 200, &response_headers, b"{\"ok\":true}")
        .await;
    assert_eq!(response_caching_cache_keys_for_test(&plugin).len(), 1);
}

// ---------------------------------------------------------------------------
// GHSA-pwcm-6rh8-f2gh (r2) — every header-decidable refusal releases the body,
// and the final response-header phase owns the effects those refusals imply.
//
// The shape of each test is deliberately the same: assert the release, then
// assert the CACHE STATE that proves the release did not drop a required
// effect. A release assertion on its own would be exactly the regression this
// suite exists to prevent.
// ---------------------------------------------------------------------------

/// The one lifecycle helper these tests share: run the response through the real
/// `after_proxy` boundary, which is where the final response-header phase lives.
/// Returns `true` when a hook rejected.
async fn run_final_response_header_phase(
    plugin: &Arc<ResponseCaching>,
    ctx: &mut RequestContext,
    response_status: u16,
    response_headers: &HashMap<String, String>,
) -> bool {
    let plugins: Vec<Arc<dyn Plugin>> = vec![plugin.clone()];
    let mut response_headers = response_headers.clone();
    run_after_proxy_hooks_for_test(&plugins, ctx, response_status, &mut response_headers).await
}

/// A refresh request for a target that already has an entry.
///
/// A plain repeat GET would be served from the cache and clear this instance's
/// lookup staging, so it could never drive a *superseding* response. A client
/// `Cache-Control: no-cache` refuses the stored representation while KEEPING the
/// staging, which is the established way these tests reach the store path for an
/// already-cached target (see `test_bypassed_zero_freshness_response_invalidates_existing_entry`).
async fn refresh_ctx(plugin: &ResponseCaching, path: &str) -> RequestContext {
    let mut ctx = make_ctx("GET", path);
    ctx.headers
        .insert("cache-control".to_string(), "no-cache".to_string());
    let mut headers = HashMap::new();
    headers.insert("cache-control".to_string(), "no-cache".to_string());
    assert!(matches!(
        plugin.before_proxy(&mut ctx, &mut headers).await,
        PluginResult::Continue
    ));
    assert_status(plugin, &ctx, "BYPASS");
    ctx
}

/// `Set-Cookie` beside an invalidating directive: released, AND the entry it
/// supersedes is gone. The earlier revision kept this buffered precisely because
/// the eviction had nowhere else to run.
///
/// The last case pins the store path's ORDER rather than its outcome set:
/// `Set-Cookie` is refused at step 5, BEFORE the unusable-`Vary` eviction at
/// step 8, so a `Vary: *` response that also carries `Set-Cookie` evicts nothing
/// — the store path never reaches that branch. Releasing it must not invent an
/// eviction any more than it may skip one.
#[tokio::test]
async fn set_cookie_with_an_invalidating_directive_releases_and_evicts() {
    let _policy_guard = response_cache_replay_policy_guard();

    let cases: Vec<(Vec<(&str, &str)>, bool)> = vec![
        (vec![("cache-control", "no-store")], true),
        (vec![("cache-control", "private")], true),
        (vec![("cache-control", "no-cache")], true),
        (vec![("cache-control", "max-age=0")], true),
        (
            vec![("cache-control", "public, max-age=60"), ("vary", "*")],
            false,
        ),
    ];

    for (extra, must_evict) in cases {
        let plugin = Arc::new(default_plugin());
        cache_response(
            &plugin,
            "GET",
            "/api/resource",
            200,
            &HashMap::new(),
            b"old",
        )
        .await;
        assert_eq!(response_caching_cache_keys_for_test(&plugin).len(), 1);

        let mut ctx = refresh_ctx(&plugin, "/api/resource").await;

        let mut pairs = vec![
            ("content-type", "application/json"),
            ("set-cookie", "session=abc"),
        ];
        pairs.extend(extra.iter().copied());
        let response_headers = response_headers_from(&pairs);

        assert!(
            !plugin.should_buffer_response_body_for_content_type(
                &ctx,
                Some("application/json"),
                200,
                &response_headers,
            ),
            "{pairs:?} is decidable from headers alone"
        );
        assert!(!run_final_response_header_phase(&plugin, &mut ctx, 200, &response_headers).await);
        let remaining = response_caching_cache_keys_for_test(&plugin).len();
        if must_evict {
            assert_eq!(
                remaining, 0,
                "{pairs:?} must still evict what it supersedes"
            );
        } else {
            assert_eq!(
                remaining, 1,
                "{pairs:?} is refused at Set-Cookie, before the Vary eviction the \
                 store path would only reach later"
            );
        }
    }
}

/// The direct advisory reproduction, one case per header condition the advisory
/// names: an origin-selected event stream must stream — never be collected until
/// the stream ends — no matter which non-store header rides with it. Each case
/// also proves the cache state that release could otherwise have dropped.
#[tokio::test]
async fn origin_selected_sse_streams_under_every_non_store_header_condition() {
    let _policy_guard = response_cache_replay_policy_guard();

    // (label, extra response headers, whether this case must also evict)
    type SseHeaderCase<'a> = (&'a str, Vec<(&'a str, &'a str)>, bool);
    let cases: Vec<SseHeaderCase<'_>> = vec![
        (
            "plain cacheable",
            vec![("cache-control", "public, max-age=60")],
            false,
        ),
        ("no-store", vec![("cache-control", "no-store")], true),
        (
            "private",
            vec![("cache-control", "private, max-age=60")],
            true,
        ),
        ("no-cache", vec![("cache-control", "no-cache")], true),
        ("max-age=0", vec![("cache-control", "max-age=0")], true),
        (
            "Vary: *",
            vec![("cache-control", "public, max-age=60"), ("vary", "*")],
            true,
        ),
        (
            "Set-Cookie",
            vec![
                ("cache-control", "public, max-age=60"),
                ("set-cookie", "session=abc"),
            ],
            false,
        ),
    ];

    for (label, extra, must_evict) in cases {
        let plugin = Arc::new(default_plugin());
        cache_response(&plugin, "GET", "/api/events", 200, &HashMap::new(), b"old").await;
        assert_eq!(response_caching_cache_keys_for_test(&plugin).len(), 1);

        // No `Accept: text/event-stream` — the request side cannot predict this.
        let mut ctx = refresh_ctx(&plugin, "/api/events").await;

        let mut pairs = vec![("content-type", "text/event-stream")];
        pairs.extend(extra.iter().copied());
        let response_headers = response_headers_from(&pairs);

        assert!(
            !plugin.should_buffer_response_body_for_content_type(
                &ctx,
                Some("text/event-stream"),
                200,
                &response_headers,
            ),
            "origin-selected SSE + {label} must stream, not be collected to the retained ceiling"
        );

        assert!(!run_final_response_header_phase(&plugin, &mut ctx, 200, &response_headers).await);
        if must_evict {
            assert!(
                response_caching_cache_keys_for_test(&plugin).is_empty(),
                "SSE + {label} still supersedes the stored entry and must evict it"
            );
        } else {
            assert_eq!(
                response_caching_cache_keys_for_test(&plugin).len(),
                1,
                "SSE + {label} evicts nothing, so the unrelated stored entry survives"
            );
        }
    }
}

/// A proxy that also runs a content-type-rewriting plugin must not silently
/// reinstate the vulnerable behavior. The shared refinement refuses an ordinary
/// buffer -> stream downgrade when any later hook may relabel `Content-Type`;
/// this instance's release survives that guard because the store path it closed
/// does not read `Content-Type` — and because relabelling an unbounded stream
/// does not bound it.
#[tokio::test]
async fn the_release_survives_a_possible_content_type_rewrite() {
    let plugin = default_plugin();
    let mut ctx = make_ctx("GET", "/api/events");
    let mut headers = HashMap::new();
    plugin.before_proxy(&mut ctx, &mut headers).await;

    for extra in [
        vec![("cache-control", "public, max-age=60")],
        vec![("cache-control", "no-store")],
        vec![("cache-control", "private, max-age=60")],
        vec![("cache-control", "no-cache")],
        vec![("cache-control", "max-age=0")],
        vec![("cache-control", "public, max-age=60"), ("vary", "*")],
        vec![
            ("cache-control", "public, max-age=60"),
            ("set-cookie", "session=abc"),
        ],
    ] {
        let mut pairs = vec![("content-type", "text/event-stream")];
        pairs.extend(extra.iter().copied());
        let response_headers = response_headers_from(&pairs);
        assert!(
            plugin.should_release_response_body_before_content_type_rewrite(
                &ctx,
                200,
                &response_headers,
            ),
            "SSE + {extra:?} must release even when a later hook may relabel Content-Type"
        );
    }

    // A genuinely storable non-streaming response is NOT released here: a
    // relabel cannot change that it is storable, and its body is still needed.
    let storable = response_headers_from(&[
        ("content-type", "application/json"),
        ("cache-control", "public, max-age=60"),
    ]);
    assert!(!plugin.should_release_response_body_before_content_type_rewrite(&ctx, 200, &storable));
}

/// An event stream is never STORED either, even when an unrelated plugin keeps
/// the body buffered for its own reasons and the buffered final-body hook does
/// run with a complete body in hand.
#[tokio::test]
async fn an_event_stream_another_plugin_buffered_is_still_not_stored() {
    let _policy_guard = response_cache_replay_policy_guard();
    let plugin = Arc::new(default_plugin());

    let mut ctx = make_ctx("GET", "/api/events");
    let mut headers = HashMap::new();
    plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_status(&plugin, &ctx, "MISS");

    let response_headers = response_headers_from(&[
        ("content-type", "text/event-stream"),
        ("cache-control", "public, max-age=60"),
    ]);
    assert!(!run_final_response_header_phase(&plugin, &mut ctx, 200, &response_headers).await);

    // Some other buffering plugin collected the stream anyway; the cache must
    // still refuse it rather than retaining a representation nothing can reuse.
    plugin
        .on_final_response_body(&mut ctx, 200, &response_headers, b"data: one\n\n")
        .await;
    assert!(
        response_caching_cache_keys_for_test(&plugin).is_empty(),
        "a collected event stream must not become a cache entry"
    );
}

/// The two header-only refusals that are NOT `Cache-Control` shaped: an
/// authorized request with no shared-cache opt-in, and a response already stale
/// on arrival. Both release, and both teach the predictor exactly as the store
/// path did.
#[tokio::test]
async fn authorization_and_stale_age_refusals_release_and_still_predict() {
    let _policy_guard = response_cache_replay_policy_guard();

    // RFC 9111 §3.5: `Authorization` with no `public` / `must-revalidate` /
    // `s-maxage` on the response.
    let plugin = Arc::new(default_plugin());
    let mut ctx = make_ctx("GET", "/api/private");
    ctx.headers
        .insert("authorization".to_string(), "Bearer abc".to_string());
    let mut headers = HashMap::new();
    headers.insert("authorization".to_string(), "Bearer abc".to_string());
    plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_status(&plugin, &ctx, "MISS");

    let response_headers = response_headers_from(&[
        ("content-type", "text/event-stream"),
        ("cache-control", "max-age=60"),
    ]);
    assert!(
        !plugin.should_buffer_response_body_for_content_type(
            &ctx,
            Some("text/event-stream"),
            200,
            &response_headers,
        ),
        "an authorized request the origin never opted into sharing has no store path"
    );
    assert!(!run_final_response_header_phase(&plugin, &mut ctx, 200, &response_headers).await);
    assert!(response_caching_cache_keys_for_test(&plugin).is_empty());

    // The predictor learned the variant, so the very next request bypasses.
    let mut next = make_ctx("GET", "/api/private");
    next.headers
        .insert("authorization".to_string(), "Bearer abc".to_string());
    let mut next_headers = HashMap::new();
    next_headers.insert("authorization".to_string(), "Bearer abc".to_string());
    plugin.before_proxy(&mut next, &mut next_headers).await;
    assert_status(&plugin, &next, "PREDICTED-BYPASS");

    // A response whose corrected age already exceeds its freshness lifetime.
    let stale_plugin = Arc::new(default_plugin());
    let mut stale_ctx = make_ctx("GET", "/api/stale");
    let mut stale_headers = HashMap::new();
    stale_plugin
        .before_proxy(&mut stale_ctx, &mut stale_headers)
        .await;
    let stale_response = response_headers_from(&[
        ("content-type", "application/json"),
        ("cache-control", "max-age=10"),
        ("age", "999"),
    ]);
    assert!(
        !stale_plugin.should_buffer_response_body_for_content_type(
            &stale_ctx,
            Some("application/json"),
            200,
            &stale_response,
        ),
        "a representation already stale on arrival is never stored"
    );
    assert!(
        !run_final_response_header_phase(&stale_plugin, &mut stale_ctx, 200, &stale_response).await
    );
    assert!(response_caching_cache_keys_for_test(&stale_plugin).is_empty());
}

/// A status refused BEFORE the invalidating branches is released even when an
/// invalidating directive is present, because the store path provably returns
/// before reaching them. This is the asymmetry the ordering encodes.
#[tokio::test]
async fn a_pre_invalidation_refusal_releases_even_with_an_invalidating_directive() {
    let plugin = default_plugin();
    let mut ctx = make_ctx("GET", "/api/resource");
    let mut headers = HashMap::new();
    plugin.before_proxy(&mut ctx, &mut headers).await;

    let response_headers = response_headers_from(&[
        ("content-type", "application/json"),
        ("cache-control", "no-store"),
    ]);
    assert!(
        !plugin.should_buffer_response_body_for_content_type(
            &ctx,
            Some("application/json"),
            500,
            &response_headers,
        ),
        "an uncacheable status short-circuits the store path before any eviction"
    );

    let ranged = response_headers_from(&[
        ("content-type", "application/json"),
        ("content-range", "bytes 0-9/100"),
        ("cache-control", "no-store"),
    ]);
    assert!(
        !plugin.should_buffer_response_body_for_content_type(
            &ctx,
            Some("application/json"),
            200,
            &ranged,
        ),
        "a Content-Range answer short-circuits the store path before any eviction"
    );
}

/// A configured `ttl_seconds: 0` makes EVERY response take the zero-freshness
/// branch. That branch is header-only, so a zero-TTL instance releases every
/// response — it must never be a licence to buffer an event stream forever —
/// while its zero-freshness eviction still runs.
#[tokio::test]
async fn a_zero_ttl_instance_releases_every_response_and_still_evicts() {
    let _policy_guard = response_cache_replay_policy_guard();

    // Seed through a normally-configured instance, then supersede through the
    // zero-TTL one: they share nothing, so each half is asserted on its own.
    let plugin = Arc::new(plugin_with_config(json!({"ttl_seconds": 0})));
    let mut ctx = make_ctx("GET", "/api/events");
    let mut headers = HashMap::new();
    plugin.before_proxy(&mut ctx, &mut headers).await;

    for content_type in ["text/event-stream", "application/json"] {
        let response_headers = response_headers_from(&[("content-type", content_type)]);
        assert!(
            !plugin.should_buffer_response_body_for_content_type(
                &ctx,
                Some(content_type),
                200,
                &response_headers,
            ),
            "with ttl_seconds = 0 nothing is ever storable, so `{content_type}` must stream"
        );
    }

    // The zero-freshness branch is what ran, on the streaming path, and it
    // stored nothing.
    let response_headers = response_headers_from(&[("content-type", "text/event-stream")]);
    assert!(!run_final_response_header_phase(&plugin, &mut ctx, 200, &response_headers).await);
    assert_eq!(
        ctx.metadata
            .get(&staging_key(&plugin, "cache_final_header_decision"))
            .map(String::as_str),
        Some("invalidate-zero-freshness"),
        "the eviction the release skipped in the body hook must have run here"
    );
    assert!(
        response_caching_cache_keys_for_test(&plugin).is_empty(),
        "a zero-TTL instance stores nothing and leaves nothing behind"
    );
}

/// Finding 4: with `response_caching` as the ONLY buffering plugin, retries
/// must still be able to reach the header-time release. Before this, the
/// instance overrode neither retry hook, so the shared gate was false and an
/// origin-selected event stream stayed fully buffered under retries.
#[tokio::test]
async fn response_caching_alone_enables_retry_time_release() {
    let plugin: Arc<ResponseCaching> = Arc::new(default_plugin());
    let mut ctx = make_ctx("GET", "/api/events");
    let mut headers = HashMap::new();
    plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_status(&plugin, &ctx, "MISS");

    // The SAME instance the gate is evaluated over, so the release marker this
    // request carries is the one the vote reads.
    let plugins: Vec<Arc<dyn Plugin>> = vec![plugin.clone()];
    assert!(
        plugin.may_release_response_body_under_retries(&ctx),
        "the instance must opt into the retry release path while it is buffering"
    );
    assert!(
        ferrum_edge::_test_support::plugins_may_release_response_body_under_retries_for_test(
            &plugins, &ctx
        ),
        "response_caching alone must open the retry release gate"
    );

    // Every header-decidable representation is released under retries, event
    // streams included, and specifically INCLUDING the ones that also imply an
    // eviction — that eviction belongs to the header phase, which only ever runs
    // for the response retry selection actually kept.
    for extra in [
        vec![("cache-control", "public, max-age=60")],
        vec![("cache-control", "no-store")],
        vec![("cache-control", "private, max-age=60")],
        vec![("cache-control", "no-cache")],
        vec![("cache-control", "max-age=0")],
        vec![("cache-control", "public, max-age=60"), ("vary", "*")],
        vec![
            ("cache-control", "public, max-age=60"),
            ("set-cookie", "session=abc"),
        ],
    ] {
        let mut pairs = vec![("content-type", "text/event-stream")];
        pairs.extend(extra.iter().copied());
        let sse = response_headers_from(&pairs);
        assert!(
            plugin.should_release_response_body_under_retries(&ctx, 200, &sse),
            "an event stream must be releasable under retries with {extra:?}"
        );
    }

    let uncacheable_status = response_headers_from(&[("content-type", "application/json")]);
    assert!(plugin.should_release_response_body_under_retries(&ctx, 500, &uncacheable_status));

    // Only a genuinely storable, non-streaming representation still needs its
    // body, because only there can the body change the answer.
    let storable = response_headers_from(&[
        ("content-type", "application/json"),
        ("cache-control", "public, max-age=60"),
    ]);
    assert!(!plugin.should_release_response_body_under_retries(&ctx, 200, &storable));
}

/// A retry attempt the proxy later discards must not mutate cache state. The
/// retry-time vote and the buffering refinement are pure predicates; only the
/// final response-header phase — which runs once, from the end of the
/// `after_proxy` chain — takes an effect.
#[tokio::test]
async fn a_discarded_retry_attempt_never_mutates_cache_state() {
    let _policy_guard = response_cache_replay_policy_guard();
    let plugin = Arc::new(default_plugin());
    cache_response(
        &plugin,
        "GET",
        "/api/resource",
        200,
        &HashMap::new(),
        b"old",
    )
    .await;
    assert_eq!(response_caching_cache_keys_for_test(&plugin).len(), 1);

    let mut ctx = refresh_ctx(&plugin, "/api/resource").await;

    // Three attempts the proxy discards, each carrying an invalidating response.
    let discarded = response_headers_from(&[
        ("content-type", "application/json"),
        ("cache-control", "no-store"),
    ]);
    for _ in 0..3 {
        assert!(plugin.should_release_response_body_under_retries(&ctx, 200, &discarded));
        assert!(!plugin.should_buffer_response_body_for_content_type(
            &ctx,
            Some("application/json"),
            200,
            &discarded,
        ));
    }
    assert_eq!(
        response_caching_cache_keys_for_test(&plugin).len(),
        1,
        "a discarded attempt must not evict anything"
    );

    // The attempt the proxy actually selects is the only one that applies
    // header effects — and it does apply them.
    assert!(!run_final_response_header_phase(&plugin, &mut ctx, 200, &discarded).await);
    assert!(
        response_caching_cache_keys_for_test(&plugin).is_empty(),
        "the selected final response must still evict what it supersedes"
    );
}

/// Header effects follow the FINAL header view, not the raw backend one. The
/// backend sends no cache directive at all; a later `after_proxy` hook stamps
/// `Cache-Control: no-store`, and the eviction still happens — which is only
/// possible because the phase runs at the END of the `after_proxy` chain rather
/// than at this plugin's own position in it.
#[tokio::test]
async fn the_header_phase_reads_the_final_transformed_headers() {
    let _policy_guard = response_cache_replay_policy_guard();
    let plugin = Arc::new(default_plugin());
    cache_response(
        &plugin,
        "GET",
        "/api/resource",
        200,
        &HashMap::new(),
        b"old",
    )
    .await;

    let mut ctx = refresh_ctx(&plugin, "/api/resource").await;

    // `response_transformer` runs at priority 4000, after `response_caching`
    // at 3500, so its `after_proxy` rule is exactly a "later hook" here.
    let transformer = ferrum_edge::plugins::response_transformer::ResponseTransformer::new(&json!({
        "rules": [
            {"operation": "add", "target": "header", "key": "cache-control", "value": "no-store"}
        ]
    }))
    .expect("response_transformer config");
    let plugins: Vec<Arc<dyn Plugin>> = vec![plugin.clone(), Arc::new(transformer)];

    // The backend said nothing about caching; the final view says `no-store`.
    let mut response_headers = response_headers_from(&[("content-type", "application/json")]);
    assert!(!run_after_proxy_hooks_for_test(&plugins, &mut ctx, 200, &mut response_headers).await);
    assert_eq!(
        response_headers.get("cache-control").map(String::as_str),
        Some("no-store"),
        "the later hook's rule is what the header phase must have seen"
    );
    assert!(
        response_caching_cache_keys_for_test(&plugin).is_empty(),
        "the eviction follows the final header view, not the raw backend one"
    );
}

/// Two instances on one proxy classify the same response independently, and
/// neither reads the other's staged decision.
#[tokio::test]
async fn multi_instance_final_header_decisions_stay_isolated() {
    let _policy_guard = response_cache_replay_policy_guard();
    let strict = Arc::new(plugin_with_config(json!({"ttl_seconds": 0})));
    let ordinary = Arc::new(default_plugin());

    let mut ctx = make_ctx("GET", "/api/widgets");
    let mut headers = HashMap::new();
    strict.before_proxy(&mut ctx, &mut headers).await;
    ordinary.before_proxy(&mut ctx, &mut headers).await;

    // No `max-age`, so each instance's configured `ttl_seconds` is the freshness
    // lifetime — which is exactly what makes the two disagree.
    let response_headers = response_headers_from(&[("content-type", "application/json")]);

    // The zero-TTL instance releases; the ordinary one still needs the body.
    assert!(!strict.should_buffer_response_body_for_content_type(
        &ctx,
        Some("application/json"),
        200,
        &response_headers,
    ));
    assert!(ordinary.should_buffer_response_body_for_content_type(
        &ctx,
        Some("application/json"),
        200,
        &response_headers,
    ));

    let plugins: Vec<Arc<dyn Plugin>> = vec![strict.clone(), ordinary.clone()];
    let mut final_headers = response_headers.clone();
    assert!(!run_after_proxy_hooks_for_test(&plugins, &mut ctx, 200, &mut final_headers).await);

    // Each instance staged its own decision under its own namespaced key.
    assert_eq!(
        ctx.metadata
            .get(&staging_key(&strict, "cache_final_header_decision"))
            .map(String::as_str),
        Some("invalidate-zero-freshness")
    );
    assert_eq!(
        ctx.metadata
            .get(&staging_key(&ordinary, "cache_final_header_decision"))
            .map(String::as_str),
        Some("body-decides")
    );

    // And the buffered body hook honors each of them: only the ordinary
    // instance stores.
    strict
        .on_final_response_body(&mut ctx, 200, &final_headers, b"{\"ok\":true}")
        .await;
    ordinary
        .on_final_response_body(&mut ctx, 200, &final_headers, b"{\"ok\":true}")
        .await;
    assert!(response_caching_cache_keys_for_test(&strict).is_empty());
    assert_eq!(response_caching_cache_keys_for_test(&ordinary).len(), 1);
}

/// An instance that is not buffering this request neither opens the retry gate
/// nor votes to release — the vote belongs to the plugins that are the reason
/// for buffering.
#[tokio::test]
async fn a_released_instance_does_not_open_the_retry_gate() {
    let plugin: Arc<ResponseCaching> = Arc::new(default_plugin());
    let mut ctx = make_ctx("POST", "/api/orders");
    let mut headers = HashMap::new();
    plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(!plugin.should_buffer_response_body(&ctx));

    assert!(!plugin.may_release_response_body_under_retries(&ctx));
    let sse = response_headers_from(&[("content-type", "text/event-stream")]);
    assert!(!plugin.should_release_response_body_under_retries(&ctx, 200, &sse));

    let plugins: Vec<Arc<dyn Plugin>> = vec![plugin.clone()];
    assert!(
        !ferrum_edge::_test_support::plugins_may_release_response_body_under_retries_for_test(
            &plugins, &ctx
        )
    );
}

// ---------------------------------------------------------------------------
// GHSA-pwcm-6rh8-f2gh — the retry-time refinement applies the content-type
// relabel guard PER PLUGIN and projects the later chain's header effects, so a
// supported `retries + response_caching + response_transformer` proxy no longer
// buffers a backend-selected event stream for the life of the connection.
// ---------------------------------------------------------------------------

/// The retry-time refinement, driven exactly as every dispatch path drives it.
fn retry_refinement_streams(
    plugins: &[Arc<dyn Plugin>],
    ctx: &RequestContext,
    response_status: u16,
    response_headers: &HashMap<String, String>,
) -> bool {
    let proxy = create_test_proxy();
    let retry_ctx = retry_response_decision_context_for_test(ctx);
    refine_stream_response_for_content_type_for_test(
        &proxy,
        plugins,
        &retry_ctx,
        response_status,
        response_headers,
    )
}

/// A header-only `response_transformer` that may rewrite `Content-Type`. It runs
/// at priority 4000, after `response_caching` at 3500, so it is exactly a
/// "later hook" for the refinement.
fn later_content_type_rewriter() -> Arc<dyn Plugin> {
    let transformer =
        ferrum_edge::plugins::response_transformer::ResponseTransformer::new(&json!({
            "rules": [{
                "operation": "update",
                "target": "header",
                "key": "Content-Type",
                "value": "application/json"
            }]
        }))
        .expect("response_transformer config");
    Arc::new(transformer)
}

fn later_header_transformer(key: &str, value: &str) -> Arc<dyn Plugin> {
    let transformer =
        ferrum_edge::plugins::response_transformer::ResponseTransformer::new(&json!({
            "rules": [{
                "operation": "update",
                "target": "header",
                "key": key,
                "value": value
            }]
        }))
        .expect("response_transformer config");
    Arc::new(transformer)
}

/// The root residual: with retries configured, a later `Content-Type`-rewriting
/// transformer used to make the whole retry branch return "keep buffering" from
/// one global early return, so a backend-selected event stream was collected for
/// the entire life of the connection against the retained-response budget. The
/// guard is now per plugin, and this instance proves its release independent of
/// the final label — relabelling an unbounded stream does not bound it.
#[tokio::test]
async fn a_retried_event_stream_streams_past_a_later_content_type_rewriter() {
    let _policy_guard = response_cache_replay_policy_guard();
    let plugin: Arc<ResponseCaching> = Arc::new(default_plugin());
    let mut ctx = make_ctx("GET", "/api/events");
    let mut headers = HashMap::new();
    plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_status(&plugin, &ctx, "MISS");

    let sse = response_headers_from(&[
        ("content-type", "text/event-stream"),
        ("cache-control", "public, max-age=60"),
    ]);

    let alone: Vec<Arc<dyn Plugin>> = vec![plugin.clone()];
    assert!(
        retry_refinement_streams(&alone, &ctx, 200, &sse),
        "the cache alone already released this under retries"
    );

    let with_rewriter: Vec<Arc<dyn Plugin>> = vec![plugin.clone(), later_content_type_rewriter()];
    assert!(
        retry_refinement_streams(&with_rewriter, &ctx, 200, &sse),
        "adding a Content-Type-rewriting transformer must not reinstate full buffering \
         of a backend-selected event stream under retries"
    );

    // And the stream is still never STORED, including on the relabelled final
    // headers a buffering plugin elsewhere might have collected. The backend
    // representation is what decides that, so the pristine stamp every dispatch
    // path records is what the header phase reads.
    let mut final_headers = sse.clone();
    stamp_original_response_metadata_for_test(&mut ctx, 200, &final_headers);
    let rejected =
        run_after_proxy_hooks_for_test(&with_rewriter, &mut ctx, 200, &mut final_headers).await;
    assert!(!rejected);
    assert_eq!(
        final_headers.get("content-type").map(String::as_str),
        Some("application/json"),
        "the later hook did relabel the response the header phase classified"
    );
    assert_eq!(
        ctx.metadata
            .get(&staging_key(&plugin, "cache_final_header_decision"))
            .map(String::as_str),
        Some("event-stream-not-stored"),
        "a relabel must not turn the event-stream refusal off"
    );
    plugin
        .on_final_response_body(&mut ctx, 200, &final_headers, b"data: one\n\n")
        .await;
    assert!(
        response_caching_cache_keys_for_test(&plugin).is_empty(),
        "a relabelled event stream is still not a representation a later request can reuse"
    );
}

/// The retry-time decision now sees the LATER chain's header rules, so a
/// response the backend labelled cacheable but a later built-in hook makes
/// unstorable is released rather than collected and discarded unread.
#[tokio::test]
async fn a_retried_response_a_later_hook_makes_unstorable_is_released() {
    let plugin: Arc<ResponseCaching> = Arc::new(default_plugin());
    let mut ctx = make_ctx("GET", "/api/widgets");
    let mut headers = HashMap::new();
    plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_status(&plugin, &ctx, "MISS");

    // The backend response is storable by every header rule, so on the backend
    // view alone only the completed body can decide — it stays buffered.
    let storable = response_headers_from(&[
        ("content-type", "application/json"),
        ("cache-control", "public, max-age=60"),
    ]);
    let alone: Vec<Arc<dyn Plugin>> = vec![plugin.clone()];
    assert!(
        !retry_refinement_streams(&alone, &ctx, 200, &storable),
        "a genuinely storable representation still needs its body"
    );

    for (key, value) in [
        ("cache-control", "no-store"),
        ("cache-control", "private, max-age=60"),
        ("cache-control", "no-cache"),
        ("cache-control", "max-age=0"),
        ("vary", "*"),
    ] {
        let plugins: Vec<Arc<dyn Plugin>> =
            vec![plugin.clone(), later_header_transformer(key, value)];
        assert!(
            retry_refinement_streams(&plugins, &ctx, 200, &storable),
            "a later `{key}: {value}` rule closes the store path, so the body must stream"
        );
    }
}

/// A chain-level route response-header rule is part of the same projection: it
/// is applied by `response_transformer`'s simulation, from the cloned context,
/// so the live request keeps its one-shot override for the real hook.
#[tokio::test]
async fn a_route_level_response_header_rule_participates_in_the_retry_projection() {
    use ferrum_edge::plugins::utils::route_header_transform::{
        RouteHeaderTransformOp, RouteHeaderTransformRule,
    };

    let _policy_guard = response_cache_replay_policy_guard();
    let plugin: Arc<ResponseCaching> = Arc::new(default_plugin());
    cache_response(
        &plugin,
        "GET",
        "/api/resource",
        200,
        &HashMap::new(),
        b"old",
    )
    .await;
    assert_eq!(response_caching_cache_keys_for_test(&plugin).len(), 1);

    let mut ctx = refresh_ctx(&plugin, "/api/resource").await;
    let route_rules = vec![RouteHeaderTransformRule {
        operation: RouteHeaderTransformOp::Update,
        key: "cache-control".to_string(),
        value: Some("no-store".to_string()),
    }];
    ctx.route_override_response_transform = Some(Arc::new(route_rules));

    let transformer =
        ferrum_edge::plugins::response_transformer::ResponseTransformer::new(&json!({
            "apply_route_overrides": true
        }))
        .expect("route override response_transformer config");
    let plugins: Vec<Arc<dyn Plugin>> = vec![plugin.clone(), Arc::new(transformer)];

    let storable = response_headers_from(&[
        ("content-type", "application/json"),
        ("cache-control", "public, max-age=60"),
    ]);
    assert!(
        retry_refinement_streams(&plugins, &ctx, 200, &storable),
        "the route-level rule is part of the final header view the projection must reach"
    );
    assert!(
        ctx.route_override_response_transform.is_some(),
        "the projection runs on a cloned context, so the live one-shot override survives"
    );

    // The real chain then applies it, and the eviction happens exactly once,
    // from the final response-header phase — not from any projection above.
    let mut final_headers = storable.clone();
    assert!(!run_after_proxy_hooks_for_test(&plugins, &mut ctx, 200, &mut final_headers).await);
    assert_eq!(
        final_headers.get("cache-control").map(String::as_str),
        Some("no-store"),
        "the route-level rule is what the real chain applied"
    );
    assert!(
        response_caching_cache_keys_for_test(&plugin).is_empty(),
        "the selected final response evicts what it supersedes"
    );
}

/// The per-plugin guard must not widen anyone else's boundary: a plugin whose
/// body need IS decided by `Content-Type` keeps buffering when a later hook may
/// relabel the response.
#[tokio::test]
async fn a_content_type_dependent_plugin_still_buffers_behind_a_later_rewrite() {
    let plugin: Arc<ResponseCaching> = Arc::new(default_plugin());
    let mut ctx = make_ctx("GET", "/download");
    let mut headers = HashMap::new();
    plugin.before_proxy(&mut ctx, &mut headers).await;

    let body_validator = ferrum_edge::plugins::body_validator::BodyValidator::new(&json!({
        "response_required_fields": ["id"]
    }))
    .expect("body_validator config");
    let validator: Arc<dyn Plugin> = Arc::new(body_validator);
    // `no-store` closes the cache's store path, so the cache is not what decides
    // this case — the validator is.
    let png =
        response_headers_from(&[("content-type", "image/png"), ("cache-control", "no-store")]);

    // Without a relabelling hook both instances release this representation.
    let without_rewrite: Vec<Arc<dyn Plugin>> = vec![plugin.clone(), validator.clone()];
    assert!(retry_refinement_streams(&without_rewrite, &ctx, 200, &png));

    // With one, the validator's release was taken on a label the client never
    // sees, so it must keep the buffered path — and the whole downgrade fails.
    let with_rewrite: Vec<Arc<dyn Plugin>> =
        vec![plugin.clone(), validator, later_content_type_rewriter()];
    assert!(
        !retry_refinement_streams(&with_rewrite, &ctx, 200, &png),
        "a content-type-dependent body plugin must not release behind a later relabel"
    );
}

/// Every active buffering plugin still has to agree. `response_caching` releasing
/// a response can never stream a body another plugin genuinely needs.
#[tokio::test]
async fn retry_release_still_requires_every_active_buffering_plugin_to_agree() {
    let plugin: Arc<ResponseCaching> = Arc::new(default_plugin());
    let mut ctx = make_ctx("GET", "/api/widgets");
    let mut headers = HashMap::new();
    plugin.before_proxy(&mut ctx, &mut headers).await;

    // `no-store` closes this instance's store path outright...
    let no_store_json = response_headers_from(&[
        ("content-type", "application/json"),
        ("cache-control", "no-store"),
    ]);
    let alone: Vec<Arc<dyn Plugin>> = vec![plugin.clone()];
    assert!(retry_refinement_streams(&alone, &ctx, 200, &no_store_json));

    // ...but a response body validator still has to read the JSON document.
    let body_validator = ferrum_edge::plugins::body_validator::BodyValidator::new(&json!({
        "response_required_fields": ["id"]
    }))
    .expect("body_validator config");
    let with_validator: Vec<Arc<dyn Plugin>> = vec![plugin.clone(), Arc::new(body_validator)];
    assert!(
        !retry_refinement_streams(&with_validator, &ctx, 200, &no_store_json),
        "one plugin's release must never stream a body another plugin enforces policy over"
    );
}

/// A retry attempt the proxy discards takes no effect, however many times its
/// transformed headers are classified. Only the selected response applies them,
/// and it applies them exactly once.
#[tokio::test]
async fn a_discarded_transformed_retry_attempt_is_side_effect_free() {
    let _policy_guard = response_cache_replay_policy_guard();
    let plugin: Arc<ResponseCaching> = Arc::new(default_plugin());
    cache_response(
        &plugin,
        "GET",
        "/api/resource",
        200,
        &HashMap::new(),
        b"old",
    )
    .await;
    assert_eq!(response_caching_cache_keys_for_test(&plugin).len(), 1);

    let mut ctx = refresh_ctx(&plugin, "/api/resource").await;
    let plugins: Vec<Arc<dyn Plugin>> = vec![
        plugin.clone(),
        later_header_transformer("cache-control", "no-store"),
    ];

    // The backend says nothing invalidating; the projected final view does.
    let backend = response_headers_from(&[("content-type", "application/json")]);
    for _ in 0..3 {
        assert!(retry_refinement_streams(&plugins, &ctx, 200, &backend));
    }
    assert_eq!(
        response_caching_cache_keys_for_test(&plugin).len(),
        1,
        "a discarded attempt must not evict, mark, or otherwise mutate cache state"
    );

    // The attempt the proxy selects is the only one that takes effects.
    let mut final_headers = backend.clone();
    assert!(!run_after_proxy_hooks_for_test(&plugins, &mut ctx, 200, &mut final_headers).await);
    assert!(
        response_caching_cache_keys_for_test(&plugin).is_empty(),
        "the selected final response still evicts what it supersedes"
    );
    assert_eq!(
        ctx.metadata
            .get(&staging_key(&plugin, "cache_final_header_decision"))
            .map(String::as_str),
        Some("invalidate-base-key"),
        "and it staged that outcome once, so the buffered body hook cannot repeat it"
    );
}

/// The projection is refused wholesale when the remaining chain contains a
/// plugin whose header effects the gateway cannot reproduce, so an unknown or
/// custom plugin keeps the conservative answer.
#[tokio::test]
async fn an_unreproducible_later_plugin_keeps_the_conservative_answer() {
    let plugin: Arc<ResponseCaching> = Arc::new(default_plugin());
    let mut ctx = make_ctx("GET", "/api/widgets");
    let mut headers = HashMap::new();
    plugin.before_proxy(&mut ctx, &mut headers).await;

    let storable = response_headers_from(&[
        ("content-type", "application/json"),
        ("cache-control", "public, max-age=60"),
    ]);

    // A built-in later hook that makes it unstorable releases the body.
    let reproducible: Vec<Arc<dyn Plugin>> = vec![
        plugin.clone(),
        later_header_transformer("cache-control", "no-store"),
    ];
    assert!(retry_refinement_streams(
        &reproducible,
        &ctx,
        200,
        &storable
    ));

    // The SAME rule behind a plugin whose `after_proxy` the gateway cannot
    // reproduce does not: the projection is not a proof there, so the
    // conservative buffered answer stands.
    let unreproducible: Vec<Arc<dyn Plugin>> = vec![
        plugin.clone(),
        Arc::new(OpaqueLaterPlugin),
        later_header_transformer("cache-control", "no-store"),
    ];
    assert!(
        !retry_refinement_streams(&unreproducible, &ctx, 200, &storable),
        "an unreproducible later plugin must keep the conservative buffered answer"
    );
}

/// A stand-in for an operator's custom plugin: it declares nothing the gateway
/// can simulate, so nothing about the final header view is provable behind it.
struct OpaqueLaterPlugin;

#[async_trait::async_trait]
impl Plugin for OpaqueLaterPlugin {
    fn name(&self) -> &str {
        "opaque_later_plugin"
    }
}

/// Finding 1: the entry body is charged for its own lifetime, so an entry the
/// aggregate budget cannot admit is simply not stored — the client still gets
/// its response and nothing uncharged is retained.
#[tokio::test]
async fn a_cacheable_response_is_still_stored_under_a_healthy_budget() {
    let plugin = default_plugin();
    let mut ctx = make_ctx("GET", "/api/widgets");
    let mut headers = HashMap::new();
    plugin.before_proxy(&mut ctx, &mut headers).await;

    let response_headers = public_response_headers();
    plugin
        .on_final_response_body(&mut ctx, 200, &response_headers, b"{\"ok\":true}")
        .await;
    assert_eq!(
        response_caching_cache_keys_for_test(&plugin).len(),
        1,
        "the entry copy acquires its own charge and the store proceeds"
    );
}
