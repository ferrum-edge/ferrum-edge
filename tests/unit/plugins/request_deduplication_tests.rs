use async_trait::async_trait;
use bytes::Bytes;
use ferrum_edge::_test_support::{
    finalize_plugin_rejection_for_test, finalize_plugin_rejection_without_committed_hooks_for_test,
    finalized_response_replay_for_test, request_deduplication_completed_size_snapshot_for_test,
    request_deduplication_expire_completed_entries_for_test,
    request_deduplication_expire_execution_barriers_for_test,
    request_deduplication_expire_inflight_entries_for_test,
    request_deduplication_logical_keys_from_context_for_test,
    request_deduplication_redis_cached_response_payload_is_valid,
    request_deduplication_redis_payload_for_test,
    request_deduplication_redis_record_payload_is_valid,
    request_deduplication_request_identity_for_test,
    request_deduplication_set_request_state_for_test,
    request_deduplication_with_instance_id_for_test,
    set_response_presentation_policy_digest_for_test,
};
use ferrum_edge::config::types::Proxy;
use ferrum_edge::config::{BackendAllowIps, BackendEgressPolicy};
use ferrum_edge::plugins::ai_response_guard::AiResponseGuard;
use ferrum_edge::plugins::ai_tool_governor::AiToolGovernor;
use ferrum_edge::plugins::request_deduplication::{
    DYNAMIC_RESPONSE_PRESENTATION_PLUGINS, RequestDeduplication,
};
use ferrum_edge::plugins::response_transformer::ResponseTransformer;
use ferrum_edge::plugins::serverless_function::ServerlessFunction;
use ferrum_edge::plugins::utils::policy_digest::presentation_policy_digest;
use ferrum_edge::plugins::{
    HTTP_ONLY_PROTOCOLS, Plugin, PluginHttpClient, PluginResult, RequestContext,
    ResponsePresentationPolicy, create_plugin_with_http_client,
    create_plugin_with_http_client_and_config_id, priority,
};
use ferrum_edge::proxy::deferred_log::BodyOutcome;
use serde_json::json;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Barrier;

/// Test shim for the finalized-request-egress phase (GHSA-4vr5-4wm3-x5xv).
///
/// `request_mirror` and `serverless_function` no longer have a `before_proxy`
/// hook. They dispatch over an immutable backend-visible snapshot, so this
/// derives the finalized body from the representation the test staged on the
/// context and folds the backend header overlay back into the mutable map.
async fn finalized_egress(
    plugin: &dyn Plugin,
    ctx: &mut RequestContext,
    headers: &mut HashMap<String, String>,
) -> PluginResult {
    let body: Vec<u8> = ctx
        .request_body_bytes
        .as_ref()
        .map(|body| body.to_vec())
        .or_else(|| {
            ctx.metadata
                .get("request_body")
                .map(|body| body.as_bytes().to_vec())
        })
        .unwrap_or_default();
    let mut overlay = HashMap::new();
    let snapshot = headers.clone();
    let result = plugin
        .dispatch_finalized_request_egress(ctx, &snapshot, &body, &mut overlay)
        .await;
    headers.extend(overlay);
    result
}

/// Stand-in for the effective static response-presentation policy digest a real
/// request copies from its plugin-cache view. Any fixed 32-byte value works:
/// the plugin only ever compares it for equality.
const TEST_PRESENTATION_DIGEST: Option<[u8; 32]> = Some([0x5a; 32]);

/// RequestContext as the protocol entry paths build it when the proxy has no
/// dynamic presentation policy: bound to a fixed stand-in digest.
fn new_ctx(method: &str, path: &str) -> RequestContext {
    new_ctx_from("127.0.0.1", method, path)
}

fn new_ctx_from(client_ip: &str, method: &str, path: &str) -> RequestContext {
    let mut ctx = RequestContext::new(client_ip.to_string(), method.to_string(), path.to_string());
    set_response_presentation_policy_digest_for_test(&mut ctx, TEST_PRESENTATION_DIGEST);
    ctx
}

struct AppendingResponseTransform;

struct FailingMandatoryReplayTransform;

#[async_trait]
impl Plugin for FailingMandatoryReplayTransform {
    fn name(&self) -> &str {
        "failing_mandatory_replay_transform"
    }

    fn requires_replay_response_body_transform(&self, _ctx: &RequestContext) -> bool {
        true
    }

    fn requires_response_body_buffering(&self) -> bool {
        true
    }

    async fn transform_response_body(
        &self,
        _body: &[u8],
        _content_type: Option<&str>,
        _response_headers: &HashMap<String, String>,
    ) -> Option<Vec<u8>> {
        None
    }
}

#[async_trait]
impl Plugin for AppendingResponseTransform {
    fn name(&self) -> &str {
        "appending_response_transform"
    }

    fn priority(&self) -> u16 {
        4000
    }

    fn supported_protocols(&self) -> &'static [ferrum_edge::plugins::ProxyProtocol] {
        HTTP_ONLY_PROTOCOLS
    }

    fn requires_response_body_buffering(&self) -> bool {
        true
    }

    fn should_buffer_response_body(&self, _ctx: &RequestContext) -> bool {
        true
    }

    async fn on_response_body(
        &self,
        ctx: &mut RequestContext,
        _response_status: u16,
        _response_headers: &mut HashMap<String, String>,
        _body: &[u8],
    ) -> PluginResult {
        ctx.metadata
            .insert("test:replay-inspected".to_string(), "true".to_string());
        PluginResult::Continue
    }

    async fn transform_response_body(
        &self,
        body: &[u8],
        _content_type: Option<&str>,
        _response_headers: &HashMap<String, String>,
    ) -> Option<Vec<u8>> {
        let mut transformed = body.to_vec();
        transformed.extend_from_slice(b"|transformed");
        Some(transformed)
    }
}

fn make_plugin(config: serde_json::Value) -> RequestDeduplication {
    RequestDeduplication::new(&config, PluginHttpClient::default()).unwrap()
}

fn request_identity(
    plugin: &RequestDeduplication,
    ctx: &RequestContext,
) -> Option<(String, String)> {
    request_deduplication_request_identity_for_test(plugin, ctx)
}

#[tokio::test]
async fn request_context_debug_redacts_request_deduplication_state() {
    let plugin = make_plugin(json!({}));
    let mut ctx = body_ctx("POST", "/payments", br#"{"amount":100}"#);
    let mut upstream_headers = keyed_headers("ordinary-idempotency-key", "api.example.test", 14);

    assert!(matches!(
        plugin.before_proxy(&mut ctx, &mut upstream_headers).await,
        PluginResult::Continue
    ));
    assert!(request_identity(&plugin, &ctx).is_some());

    let protected_values = [
        ("key", "dedup-debug-key-sentinel-9f21"),
        ("fingerprint", "dedup-debug-fingerprint-sentinel-6c38"),
        (
            "local_inflight_owner_token",
            "dedup-debug-local-owner-sentinel-4a57",
        ),
        ("redis_lock_token", "dedup-debug-redis-lock-sentinel-2d84"),
    ];
    request_deduplication_set_request_state_for_test(
        &plugin,
        &mut ctx,
        protected_values[0].1,
        protected_values[1].1,
        protected_values[2].1,
        Some(protected_values[3].1),
    );

    let debug_output = format!("{ctx:?}");
    assert!(debug_output.contains("RequestDeduplicationRequestState"));
    for (field, sentinel) in protected_values {
        assert!(
            debug_output.contains(&format!(r#"{field}: "<redacted>""#)),
            "missing redacted {field} structure: {debug_output}"
        );
        assert!(
            !debug_output.contains(sentinel),
            "{field} leaked through RequestContext Debug"
        );
    }
}

#[tokio::test]
async fn dedup_lifecycle_state_never_reaches_transaction_log_metadata() {
    use ferrum_edge::_test_support::clone_log_metadata;

    let plugin = make_plugin(json!({}));
    let mut ctx = body_ctx("POST", "/payments", br#"{"amount":100}"#);
    let mut upstream_headers = keyed_headers("log-projection-key", "api.example.test", 14);

    assert!(matches!(
        plugin.before_proxy(&mut ctx, &mut upstream_headers).await,
        PluginResult::Continue
    ));
    assert!(request_identity(&plugin, &ctx).is_some());

    // Defense-in-depth: even if a hostile/custom producer reintroduces the
    // legacy public-metadata names, the shared fail-closed filter omits them.
    for (idx, key) in [
        "_dedup_key",
        "_dedup_fingerprint",
        "_dedup_local_inflight_token",
        "_dedup_redis_lock_token",
    ]
    .into_iter()
    .enumerate()
    {
        ctx.metadata
            .insert(key.to_string(), format!("planted-dedup-sentinel-{idx}"));
    }

    let logged = clone_log_metadata(&ctx);
    for key in [
        "_dedup_key",
        "_dedup_fingerprint",
        "_dedup_local_inflight_token",
        "_dedup_redis_lock_token",
    ] {
        assert!(
            !logged.contains_key(key),
            "{key} must never enter transaction-log metadata"
        );
    }
    for idx in 0..4 {
        let sentinel = format!("planted-dedup-sentinel-{idx}");
        assert!(
            !logged.values().any(|value| value.contains(&sentinel)),
            "dedup lifecycle value leaked into log metadata"
        );
    }

    // Incomplete stream termination retains typed ownership until TTL without
    // copying it into public metadata.
    plugin
        .on_response_stream_terminated(&mut ctx, 200, &BodyOutcome::client_disconnect(0))
        .await;
    assert!(request_identity(&plugin, &ctx).is_some());
    let after_incomplete = clone_log_metadata(&ctx);
    for key in [
        "_dedup_key",
        "_dedup_fingerprint",
        "_dedup_local_inflight_token",
        "_dedup_redis_lock_token",
    ] {
        assert!(!after_incomplete.contains_key(key));
    }
}

fn keyed_headers(key: &str, host: &str, body_len: usize) -> HashMap<String, String> {
    let mut headers = HashMap::new();
    headers.insert("idempotency-key".to_string(), key.to_string());
    headers.insert("host".to_string(), host.to_string());
    headers.insert("content-length".to_string(), body_len.to_string());
    headers.insert("content-type".to_string(), "application/json".to_string());
    headers
}

/// Two distinct-header instances on one request (issue #2378 reproduction shape).
fn dual_keyed_headers(
    idempotency_key: &str,
    operation_key: &str,
    host: &str,
    body_len: usize,
) -> HashMap<String, String> {
    let mut headers = keyed_headers(idempotency_key, host, body_len);
    headers.insert("x-operation-key".to_string(), operation_key.to_string());
    headers
}

fn make_local_sibling(header_name: &str, config_id: &str) -> RequestDeduplication {
    request_deduplication_with_instance_id_for_test(
        &json!({
            "header_name": header_name,
            "scope_by_consumer": false,
        }),
        PluginHttpClient::default(),
        config_id,
    )
    .unwrap()
}

fn make_redis_sibling(header_name: &str, config_id: &str, prefix: &str) -> RequestDeduplication {
    // Unreachable Redis forces local fallback while still constructing Redis-mode
    // instances with distinct explicit prefixes — the #2378 lifecycle shape that
    // is independent of shared-prefix self-conflict (#2379).
    request_deduplication_with_instance_id_for_test(
        &json!({
            "header_name": header_name,
            "scope_by_consumer": false,
            "sync_mode": "redis",
            "redis_url": "redis://127.0.0.1:1/0",
            "redis_connect_timeout_seconds": 1,
            "redis_key_prefix": prefix,
            // Redis mode fails closed with 503 by default; these lifecycle
            // fixtures deliberately exercise the opt-in local-only fallback.
            "on_redis_unavailable": "local_only",
        }),
        PluginHttpClient::default(),
        config_id,
    )
    .unwrap()
}

async fn mark_both_fresh(
    first: &RequestDeduplication,
    second: &RequestDeduplication,
    ctx: &mut RequestContext,
    headers: &mut HashMap<String, String>,
) {
    assert!(matches!(
        first.before_proxy(ctx, headers).await,
        PluginResult::Continue
    ));
    assert!(matches!(
        second.before_proxy(ctx, headers).await,
        PluginResult::Continue
    ));
    let keys = request_deduplication_logical_keys_from_context_for_test(ctx);
    assert_eq!(
        keys.len(),
        2,
        "each instance must own an independent request-private completion slot"
    );
    let first_id = request_identity(first, ctx).expect("first instance ownership");
    let second_id = request_identity(second, ctx).expect("second instance ownership");
    assert_ne!(
        first_id.0, second_id.0,
        "distinct headers must produce distinct logical keys per instance"
    );
}

fn body_ctx(method: &str, path: &str, body: &'static [u8]) -> RequestContext {
    let mut ctx = new_ctx(method, path);
    ctx.request_body_bytes = Some(Bytes::from_static(body));
    ctx
}

fn gzip_body(body: &[u8]) -> Vec<u8> {
    use flate2::Compression;
    use flate2::write::GzEncoder;
    use std::io::Write;

    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(body).expect("gzip write failed");
    encoder.finish().expect("gzip finish failed")
}

async fn complete_response(plugin: &RequestDeduplication, ctx: &mut RequestContext) {
    let mut response_headers = HashMap::new();
    response_headers.insert("content-type".to_string(), "application/json".to_string());
    let result = plugin
        .on_final_response_body(ctx, 201, &response_headers, b"{\"ok\":true}")
        .await;
    assert!(matches!(result, PluginResult::Continue));
}

async fn complete_response_with_body(
    plugin: &RequestDeduplication,
    ctx: &mut RequestContext,
    body: &[u8],
) {
    let response_headers = HashMap::new();
    let result = plugin
        .on_final_response_body(ctx, 200, &response_headers, body)
        .await;
    assert!(matches!(result, PluginResult::Continue));
}

fn assert_completed_size_exact(plugin: &RequestDeduplication) -> usize {
    let (tracked, actual) = request_deduplication_completed_size_snapshot_for_test(plugin);
    assert_eq!(
        tracked, actual,
        "tracked completed-response bytes must match retained completed entries"
    );
    tracked
}

fn assert_fingerprint_conflict(result: PluginResult) {
    match result {
        PluginResult::Reject {
            status_code, body, ..
        } => {
            assert_eq!(status_code, 409);
            assert!(body.contains("different request"), "body was {body}");
        }
        other => panic!("Expected fingerprint mismatch conflict, got {other:?}"),
    }
}

async fn assert_reused_key_for_different_request_conflicts(
    first_ctx: &mut RequestContext,
    first_headers: &mut HashMap<String, String>,
    second_ctx: &mut RequestContext,
    second_headers: &mut HashMap<String, String>,
) {
    let plugin = make_plugin(json!({
        "applicable_methods": ["POST", "PUT", "PATCH"]
    }));

    let result = plugin.before_proxy(first_ctx, first_headers).await;
    assert!(matches!(result, PluginResult::Continue));
    complete_response(&plugin, first_ctx).await;

    let result = plugin.before_proxy(second_ctx, second_headers).await;
    assert_fingerprint_conflict(result);
}

#[test]
fn test_new_default_config() {
    let config = json!({});
    let plugin = make_plugin(config);
    assert_eq!(plugin.name(), "request_deduplication");
    assert_eq!(plugin.priority(), priority::REQUEST_DEDUPLICATION);
    const _: () = {
        assert!(priority::MESH_ROUTE_DISPATCH < priority::REQUEST_TRANSFORMER);
        assert!(priority::REQUEST_TRANSFORMER < priority::REQUEST_DEDUPLICATION);
        assert!(priority::REQUEST_DEDUPLICATION < priority::SERVERLESS_FUNCTION);
    };
    assert_eq!(plugin.supported_protocols(), HTTP_ONLY_PROTOCOLS);
    assert!(plugin.requires_response_body_buffering());
    assert!(!plugin.is_auth_plugin());
    assert!(!plugin.modifies_request_headers());
    assert!(!plugin.modifies_request_body());
    assert!(plugin.requires_request_body_buffering());
    assert!(plugin.requires_request_body_before_before_proxy());
    assert!(plugin.needs_request_body_bytes());
}

#[test]
fn test_new_custom_header() {
    let config = json!({
        "header_name": "X-Request-Id",
        "ttl_seconds": 60,
        "max_entries": 5000
    });
    let plugin = make_plugin(config);
    assert_eq!(plugin.name(), "request_deduplication");
}

#[test]
fn test_new_rejects_non_object_config() {
    let result = RequestDeduplication::new(&json!("bad"), PluginHttpClient::default());
    assert!(result.is_err());
    assert!(result.err().unwrap().contains("config must be an object"));
}

#[test]
fn new_with_instance_id_rejects_blank_stable_identity() {
    for blank in ["", "   ", "\t\n"] {
        let result = request_deduplication_with_instance_id_for_test(
            &json!({}),
            PluginHttpClient::default(),
            blank,
        );
        let err = match result {
            Err(err) => err,
            Ok(_) => panic!("blank plugin config id must fail closed"),
        };
        assert!(
            err.contains("plugin config id must be a non-empty stable identity"),
            "unexpected error for {blank:?}: {err}"
        );
    }
}

#[test]
fn production_factory_rejects_blank_plugin_config_id() {
    for blank in ["", "   ", "\t\n"] {
        let result = create_plugin_with_http_client_and_config_id(
            "request_deduplication",
            &json!({}),
            PluginHttpClient::default(),
            Some(blank),
        );
        let err = match result {
            Err(err) => err,
            Ok(_) => {
                panic!("blank plugin config id must fail closed through the production factory")
            }
        };
        assert!(
            err.contains("plugin config id must be a non-empty stable identity"),
            "unexpected error for {blank:?}: {err}"
        );
    }
}

#[test]
fn production_factory_without_config_id_keeps_direct_construction_coherent() {
    let via_default_factory = create_plugin_with_http_client(
        "request_deduplication",
        &json!({}),
        PluginHttpClient::default(),
    )
    .unwrap()
    .unwrap();
    assert_eq!(via_default_factory.name(), "request_deduplication");
}

#[tokio::test]
async fn production_factory_partitions_logical_keys_by_plugin_config_id() {
    let config = json!({});
    let first = create_plugin_with_http_client_and_config_id(
        "request_deduplication",
        &config,
        PluginHttpClient::default(),
        Some("dedup-short"),
    )
    .unwrap()
    .unwrap();
    let sibling = create_plugin_with_http_client_and_config_id(
        "request_deduplication",
        &config,
        PluginHttpClient::default(),
        Some("dedup-long"),
    )
    .unwrap()
    .unwrap();
    let same_config_peer = create_plugin_with_http_client_and_config_id(
        "request_deduplication",
        &config,
        PluginHttpClient::default(),
        Some("dedup-short"),
    )
    .unwrap()
    .unwrap();
    let whitespace_distinct = create_plugin_with_http_client_and_config_id(
        "request_deduplication",
        &config,
        PluginHttpClient::default(),
        Some(" dedup-short "),
    )
    .unwrap()
    .unwrap();

    async fn logical_key(plugin: &Arc<dyn Plugin>) -> String {
        let mut ctx = body_ctx("POST", "/api/orders", b"{}");
        let mut headers = keyed_headers("shared-key", "api.example", 2);
        assert!(matches!(
            plugin.before_proxy(&mut ctx, &mut headers).await,
            PluginResult::Continue
        ));
        let keys = request_deduplication_logical_keys_from_context_for_test(&ctx);
        assert_eq!(keys.len(), 1, "expected one acquired logical key");
        keys.into_iter().next().unwrap()
    }

    let first_key = logical_key(&first).await;
    let sibling_key = logical_key(&sibling).await;
    let peer_key = logical_key(&same_config_peer).await;
    let whitespace_distinct_key = logical_key(&whitespace_distinct).await;
    assert_ne!(
        first_key, sibling_key,
        "production factory must partition sibling plugin_config_id values"
    );
    assert_eq!(
        first_key, peer_key,
        "corresponding copies of one plugin_config_id must share Redis identity"
    );
    assert_ne!(
        first_key, whitespace_distinct_key,
        "distinct nonblank plugin_config_id bytes must not collapse after validation"
    );
}

/// A custom Redis prefix is allowed to be shared by multiple namespaces, so
/// namespace must remain part of the hashed operation identity even when all
/// resource IDs and request bytes are equal.
#[tokio::test]
async fn explicit_shared_redis_prefix_still_partitions_proxy_namespaces() {
    let plugin = make_redis_sibling(
        "idempotency-key",
        "shared-dedup-config",
        "ferrum:dedup:shared",
    );

    async fn logical_key(plugin: &RequestDeduplication, namespace: &str) -> String {
        let proxy: Proxy = serde_json::from_value(json!({
            "id": "orders",
            "namespace": namespace,
            "hosts": ["api.example"],
            "listen_path": "/",
            "backend_scheme": "http",
            "backend_host": "127.0.0.1",
            "backend_port": 8080
        }))
        .expect("proxy fixture");
        let mut ctx = body_ctx("POST", "/api/orders", b"{}");
        ctx.matched_proxy = Some(Arc::new(proxy));
        let mut headers = keyed_headers("shared-key", "api.example", 2);
        assert!(matches!(
            plugin.before_proxy(&mut ctx, &mut headers).await,
            PluginResult::Continue
        ));
        let keys = request_deduplication_logical_keys_from_context_for_test(&ctx);
        assert_eq!(keys.len(), 1, "expected one acquired logical key");
        keys.into_iter().next().expect("logical key")
    }

    let blue = logical_key(&plugin, "blue").await;
    let green = logical_key(&plugin, "green").await;
    assert_ne!(
        blue, green,
        "equal proxy/config IDs under an explicit shared Redis prefix must remain namespace-scoped"
    );
}

#[test]
fn test_new_rejects_invalid_header_name() {
    let config = json!({
        "header_name": "not a header"
    });
    let result = RequestDeduplication::new(&config, PluginHttpClient::default());
    assert!(result.is_err());
    assert!(result.err().unwrap().contains("header_name"));
}

#[test]
fn test_new_rejects_invalid_numeric_and_bool_types() {
    for config in [
        json!({"ttl_seconds": "300"}),
        json!({"inflight_ttl_seconds": "300"}),
        json!({"max_entries": "100"}),
        json!({"max_entries": 0}),
        json!({"max_entry_size_bytes": "1024"}),
        json!({"max_entry_size_bytes": 0}),
        json!({"max_total_size_bytes": "1048576"}),
        json!({"max_total_size_bytes": 0}),
        json!({"scope_by_consumer": "true"}),
        json!({"enforce_required": "false"}),
    ] {
        let result = RequestDeduplication::new(&config, PluginHttpClient::default());
        assert!(result.is_err(), "config should be rejected: {config:?}");
    }
}

#[test]
fn test_new_rejects_invalid_applicable_methods() {
    for config in [
        json!({"applicable_methods": "POST"}),
        json!({"applicable_methods": ["POST", 123]}),
        json!({"applicable_methods": [""]}),
        json!({"applicable_methods": ["bad method"]}),
    ] {
        let result = RequestDeduplication::new(&config, PluginHttpClient::default());
        assert!(result.is_err(), "config should be rejected: {config:?}");
    }
}

#[test]
fn test_new_zero_ttl_fails() {
    let config = json!({
        "ttl_seconds": 0
    });
    let result = RequestDeduplication::new(&config, PluginHttpClient::default());
    assert!(result.is_err());
    assert!(result.err().unwrap().contains("ttl_seconds"));
}

#[test]
fn test_new_zero_inflight_ttl_fails() {
    let config = json!({
        "inflight_ttl_seconds": 0
    });
    let result = RequestDeduplication::new(&config, PluginHttpClient::default());
    assert!(result.is_err());
    assert!(result.err().unwrap().contains("inflight_ttl_seconds"));
}

#[test]
fn test_new_custom_inflight_ttl() {
    let config = json!({
        "ttl_seconds": 300,
        "inflight_ttl_seconds": 1800
    });
    let plugin = make_plugin(config);
    assert_eq!(plugin.name(), "request_deduplication");
}

#[test]
fn test_new_empty_methods_fails() {
    let config = json!({
        "applicable_methods": []
    });
    let result = RequestDeduplication::new(&config, PluginHttpClient::default());
    assert!(result.is_err());
    assert!(result.err().unwrap().contains("applicable_methods"));
}

#[test]
fn test_new_with_redis_config() {
    let config = json!({
        "sync_mode": "redis",
        "redis_url": "redis://dedup-redis.internal:6379/0",
        "redis_key_prefix": "dedup"
    });
    let plugin = make_plugin(config);
    assert_eq!(plugin.name(), "request_deduplication");
    assert_eq!(
        plugin.warmup_hostnames(),
        vec!["dedup-redis.internal".to_string()]
    );
}

/// GHSA-h2c3-j3cm-7ghh: unknown root keys must fail closed with a
/// path-qualified diagnostic instead of being replaced by permissive defaults.
#[test]
fn unknown_root_keys_are_rejected_with_path_qualified_diagnostics() {
    for (config, unknown, suggestion) in [
        (
            json!({"enforce_requred": true}),
            "enforce_requred",
            "enforce_required",
        ),
        (json!({"sync_mod": "redis"}), "sync_mod", "sync_mode"),
        (
            json!({"scope_by_consumers": false}),
            "scope_by_consumers",
            "scope_by_consumer",
        ),
        (json!({"ttl_second": 30}), "ttl_second", "ttl_seconds"),
        (
            json!({"redis_ur": "redis://host:6379"}),
            "redis_ur",
            "redis_url",
        ),
    ] {
        let Err(error) = RequestDeduplication::new(&config, PluginHttpClient::default()) else {
            panic!("unknown key must be rejected");
        };
        assert!(
            error.contains("request_deduplication: unknown configuration key(s)"),
            "{error}"
        );
        assert!(error.contains(&format!("'config.{unknown}'")), "{error}");
        assert!(error.contains(suggestion), "{error}");
    }

    // Also rejected through the shared admission entrypoint used by file,
    // database, and CP/DP validation.
    assert!(
        ferrum_edge::plugins::validate_plugin_config(
            "request_deduplication",
            &json!({"enforce_requred": true})
        )
        .is_err(),
        "shared plugin-config validation must reject unknown keys"
    );
}

/// Every documented field is accepted, so the closed allowlist cannot drift
/// into rejecting a legitimate configuration.
#[test]
fn every_documented_config_key_is_accepted() {
    let config = json!({
        "header_name": "X-Idempotency-Key",
        "ttl_seconds": 120,
        "inflight_ttl_seconds": 30,
        "max_entries": 100,
        "max_entry_size_bytes": 4096,
        "max_total_size_bytes": 65536,
        "applicable_methods": ["POST", "PUT"],
        "scope_by_consumer": false,
        "enforce_required": true,
        "sync_mode": "redis",
        "redis_url": "redis://dedup-redis.internal:6379/0",
        "redis_tls": false,
        "redis_key_prefix": "ferrum:dedup",
        "redis_pool_size": 2,
        "redis_connect_timeout_seconds": 2,
        "redis_health_check_interval_seconds": 2,
        "redis_username": "dedup",
        "redis_password": "unused-in-tests",
        "on_redis_unavailable": "local_only"
    });
    assert!(RequestDeduplication::new(&config, PluginHttpClient::default()).is_ok());
}

/// GHSA-h2c3-j3cm-7ghh: a Redis-only field supplied outside Redis mode is the
/// signature of a misspelled `sync_mode`, and must fail rather than leaving the
/// deployment silently process-local.
#[test]
fn redis_only_keys_outside_redis_mode_are_rejected() {
    for config in [
        json!({"redis_url": "redis://host:6379"}),
        json!({"sync_mode": "local", "redis_url": "redis://host:6379"}),
        json!({"sync_mode": "local", "redis_key_prefix": "dedup"}),
        json!({"on_redis_unavailable": "local_only"}),
    ] {
        let Err(error) = RequestDeduplication::new(&config, PluginHttpClient::default()) else {
            panic!("Redis-only key outside Redis mode must be rejected");
        };
        assert!(
            error.contains("require sync_mode='redis'"),
            "unexpected error: {error}"
        );
    }
}

#[test]
fn on_redis_unavailable_requires_a_known_policy() {
    const SENTINEL: &str = "sentinel-on-redis-unavailable-fallback-2d84";
    let Err(error) = RequestDeduplication::new(
        &json!({
            "sync_mode": "redis",
            "redis_url": "redis://host:6379",
            "on_redis_unavailable": SENTINEL
        }),
        PluginHttpClient::default(),
    ) else {
        panic!("unknown policy must be rejected");
    };
    assert!(error.contains("'on_redis_unavailable'"), "{error}");
    assert!(
        error.contains("'fail_closed'") && error.contains("'local_only'"),
        "diagnostic must name accepted values: {error}"
    );
    assert!(
        !error.contains(SENTINEL),
        "diagnostic must not echo the rejected value: {error}"
    );
    assert!(
        !error.contains("got:"),
        "diagnostic must stay value-redacted: {error}"
    );
}

/// request_deduplication's Redis admission path must not leak credential-bearing
/// values through shared `RedisConfig` validation diagnostics.
#[test]
fn request_deduplication_redis_validation_diagnostics_are_value_redacted() {
    const PASSWORD: &str = "sentinel-dedup-redis-password-aa11";
    const USER: &str = "sentinel-dedup-redis-user-bb22";

    // No Redis-only keys: admission reaches RedisConfig sync_mode validation.
    let Err(sync_error) = RequestDeduplication::new(
        &json!({
            "sync_mode": format!("redsi-{PASSWORD}"),
        }),
        PluginHttpClient::default(),
    ) else {
        panic!("invalid sync_mode must be rejected");
    };
    assert!(
        sync_error.contains("'sync_mode'") && sync_error.contains("'local' or 'redis'"),
        "expected RedisConfig sync_mode diagnostic: {sync_error}"
    );
    assert!(
        !sync_error.contains(PASSWORD),
        "dedup sync_mode diagnostic must not echo sentinel: {sync_error}"
    );

    // Redis-only keys outside Redis mode: reject without echoing URL credentials.
    let Err(mode_error) = RequestDeduplication::new(
        &json!({
            "sync_mode": "local",
            "redis_url": format!("redis://{USER}:{PASSWORD}@cache.internal:6379/0"),
            "redis_password": PASSWORD,
        }),
        PluginHttpClient::default(),
    ) else {
        panic!("Redis-only keys outside Redis mode must be rejected");
    };
    assert!(
        mode_error.contains("require sync_mode='redis'"),
        "expected redis-only-key diagnostic: {mode_error}"
    );
    for secret in [PASSWORD, USER, "cache.internal"] {
        assert!(
            !mode_error.contains(secret),
            "redis-only-key diagnostic must not echo {secret:?}: {mode_error}"
        );
    }

    let Err(url_error) = RequestDeduplication::new(
        &json!({
            "sync_mode": "redis",
            "redis_url": format!("http://{USER}:{PASSWORD}@cache.internal:6379/0#{PASSWORD}"),
        }),
        PluginHttpClient::default(),
    ) else {
        panic!("invalid redis_url scheme must be rejected");
    };
    assert!(
        url_error.contains("'redis_url'") && url_error.contains("scheme"),
        "expected redis_url diagnostic: {url_error}"
    );
    for secret in [PASSWORD, USER, "http://", "cache.internal"] {
        assert!(
            !url_error.contains(secret),
            "dedup redis_url diagnostic must not echo {secret:?}: {url_error}"
        );
    }
}

/// GHSA-f72h-jm2p-mc73: an unreachable coordination store must not silently
/// downgrade to a per-process ownership decision. The default refuses; the
/// opt-in policy preserves the previous availability behavior.
#[tokio::test]
async fn unreachable_redis_fails_closed_by_default_and_local_only_on_request() {
    let fail_closed = make_plugin(json!({
        "sync_mode": "redis",
        "redis_url": "redis://127.0.0.1:1/0",
        "redis_connect_timeout_seconds": 1
    }));
    let mut ctx = body_ctx("POST", "/payments", br#"{"amount":1}"#);
    let mut headers = keyed_headers("outage-key", "api.example.test", 12);
    match fail_closed.before_proxy(&mut ctx, &mut headers).await {
        PluginResult::Reject { status_code, .. } => assert_eq!(status_code, 503),
        other => panic!("expected fail-closed 503, got {other:?}"),
    }
    assert!(request_identity(&fail_closed, &ctx).is_none());

    let local_only = make_plugin(json!({
        "sync_mode": "redis",
        "redis_url": "redis://127.0.0.1:1/0",
        "redis_connect_timeout_seconds": 1,
        "on_redis_unavailable": "local_only"
    }));
    let mut ctx = body_ctx("POST", "/payments", br#"{"amount":1}"#);
    let mut headers = keyed_headers("outage-key", "api.example.test", 12);
    assert!(matches!(
        local_only.before_proxy(&mut ctx, &mut headers).await,
        PluginResult::Continue
    ));
    assert!(request_identity(&local_only, &ctx).is_some());
}

#[tokio::test]
async fn test_get_request_passes_through() {
    let config = json!({});
    let plugin = make_plugin(config);

    let mut ctx = new_ctx("GET", "/api");
    let mut headers = HashMap::new();
    headers.insert("idempotency-key".to_string(), "abc-123".to_string());

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
}

#[tokio::test]
async fn test_post_without_key_passes_through() {
    let config = json!({});
    let plugin = make_plugin(config);

    let mut ctx = new_ctx("POST", "/api");
    let mut headers = HashMap::new();

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
}

#[tokio::test]
async fn test_enforce_required_rejects_missing_key() {
    let config = json!({
        "enforce_required": true
    });
    let plugin = make_plugin(config);

    let mut ctx = new_ctx("POST", "/api");
    let mut headers = HashMap::new();

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    match result {
        PluginResult::Reject {
            status_code, body, ..
        } => {
            assert_eq!(status_code, 400);
            assert!(body.contains("idempotency"));
            let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
            assert_eq!(
                parsed["error"],
                "Missing required idempotency header: idempotency-key"
            );
        }
        _ => panic!("Expected Reject"),
    }
}

#[tokio::test]
async fn test_first_request_passes_then_replay() {
    let config = json!({});
    let plugin = make_plugin(config);

    // First request with idempotency key — should pass through
    let mut ctx1 = new_ctx("POST", "/api");
    let mut headers1 = HashMap::new();
    headers1.insert("idempotency-key".to_string(), "key-1".to_string());

    let result = plugin.before_proxy(&mut ctx1, &mut headers1).await;
    assert!(matches!(result, PluginResult::Continue));
    assert!(request_identity(&plugin, &ctx1).is_some());

    // Simulate response caching
    let mut response_headers = HashMap::new();
    response_headers.insert("content-type".to_string(), "application/json".to_string());
    let body = b"{\"id\": 123}";

    let _ = plugin
        .on_final_response_body(&mut ctx1, 201, &response_headers, body)
        .await;

    // Second request with same key — should replay
    let mut ctx2 = new_ctx("POST", "/api");
    let mut headers2 = HashMap::new();
    headers2.insert("idempotency-key".to_string(), "key-1".to_string());

    let result = plugin.before_proxy(&mut ctx2, &mut headers2).await;
    match result {
        PluginResult::RejectBinary {
            status_code,
            headers,
            body,
            ..
        } => {
            assert_eq!(status_code, 201);
            assert_eq!(headers.get("x-idempotent-replayed").unwrap(), "true");
            assert_eq!(&body[..], b"{\"id\": 123}");
            assert_eq!(
                ctx2.metadata
                    .get("request_deduplication.replayed")
                    .map(String::as_str),
                Some("true"),
                "replays must publish the bounded marker consumed by transcript audit"
            );
        }
        _ => panic!("Expected RejectBinary replay, got {:?}", result),
    }
}

/// A dedup context as the protocol entry paths build it: bound to the effective
/// static response-presentation policy of the plugin-cache generation that will
/// run on its response path.
fn policy_bound_ctx(digest: Option<[u8; 32]>) -> RequestContext {
    let mut ctx = new_ctx("POST", "/api");
    set_response_presentation_policy_digest_for_test(&mut ctx, digest);
    ctx
}

/// Digest of the effective static response-presentation policy for an ordered
/// list of `response_transformer` configs, exactly as the plugin cache folds it.
fn presentation_digest_for(configs: &[serde_json::Value]) -> [u8; 32] {
    let mut plugins: Vec<ResponseTransformer> = Vec::new();
    for config in configs {
        let plugin = ResponseTransformer::new(config);
        plugins.push(plugin.expect("valid response_transformer config"));
    }
    let mut contributions: Vec<(&str, [u8; 32])> = Vec::new();
    for plugin in &plugins {
        let ResponsePresentationPolicy::Static(digest) = plugin
            .response_presentation_policy()
            .expect("response_transformer must enroll in replay provenance")
        else {
            panic!("response_transformer policy must be statically provable");
        };
        contributions.push((plugin.name(), digest));
    }
    presentation_policy_digest(contributions)
}

fn redaction_transformer(value: &str) -> serde_json::Value {
    json!({
        "runtime_overlay_scope": "redaction",
        "rules": [{
            "operation": "update",
            "target": "header",
            "key": "x-account",
            "value": value,
        }],
    })
}

/// An RTDS gate flip with no config reload must retire a stored replay: the
/// finalized replay path skips the transform the new gate just enabled.
#[tokio::test]
#[allow(clippy::await_holding_lock)] // `test_lock()` must span plugin awaits to serialize overlay state
async fn replay_is_rejected_after_response_policy_changes() {
    use ferrum_edge::modes::mesh::config::{MeshRuntimeOverlay, RuntimeValue};
    use ferrum_edge::plugins::response_transformer::runtime_overlay;

    let _guard = ferrum_edge::modes::mesh::runtime_overlay_consumers::test_lock();
    runtime_overlay::reset_for_test();
    let plugin = make_plugin(json!({}));
    let digest = presentation_digest_for(&[redaction_transformer("redacted")]);
    let mut first_ctx = policy_bound_ctx(Some(digest));
    let mut first_headers =
        HashMap::from([("idempotency-key".to_string(), "policy-change".to_string())]);
    assert!(matches!(
        plugin
            .before_proxy(&mut first_ctx, &mut first_headers)
            .await,
        PluginResult::Continue
    ));
    complete_response(&plugin, &mut first_ctx).await;

    let mut fields = HashMap::new();
    fields.insert(
        "ferrum.response_transformer.redaction.enabled".to_string(),
        RuntimeValue::Bool(true),
    );
    runtime_overlay::apply_overlay(&MeshRuntimeOverlay { fields });

    let mut replay_ctx = policy_bound_ctx(Some(digest));
    let result = plugin
        .before_proxy(&mut replay_ctx, &mut first_headers)
        .await;
    assert!(matches!(
        result,
        PluginResult::Reject {
            status_code: 409,
            ..
        }
    ));
    assert!(!finalized_response_replay_for_test(&replay_ctx));
    runtime_overlay::reset_for_test();
}

/// The residual the gate map alone cannot cover: the RTDS gate publication is
/// byte-identical, but the operator edited the static redaction rule. A replay
/// stored under the old rule must not skip the new one.
#[tokio::test]
#[allow(clippy::await_holding_lock)] // `test_lock()` must span plugin awaits to serialize overlay state
async fn replay_is_rejected_when_static_redaction_rules_change_under_an_unchanged_gate() {
    use ferrum_edge::plugins::response_transformer::runtime_overlay;

    let _guard = ferrum_edge::modes::mesh::runtime_overlay_consumers::test_lock();
    runtime_overlay::reset_for_test();
    let plugin = make_plugin(json!({}));

    let before = presentation_digest_for(&[redaction_transformer("account-id")]);
    let after = presentation_digest_for(&[redaction_transformer("[redacted]")]);
    assert_ne!(
        before, after,
        "a static redaction-rule edit must change the presentation policy digest"
    );

    let mut first_ctx = policy_bound_ctx(Some(before));
    let mut headers = HashMap::from([(
        "idempotency-key".to_string(),
        "static-rule-change".to_string(),
    )]);
    assert!(matches!(
        plugin.before_proxy(&mut first_ctx, &mut headers).await,
        PluginResult::Continue
    ));
    complete_response(&plugin, &mut first_ctx).await;

    // Same process, same gate map, same idempotency key — only the static rules
    // moved. The gate stamp is unchanged, so gate-only provenance would replay.
    let mut replay_ctx = policy_bound_ctx(Some(after));
    let result = plugin.before_proxy(&mut replay_ctx, &mut headers).await;
    assert!(
        matches!(
            result,
            PluginResult::Reject {
                status_code: 409,
                ..
            }
        ),
        "a replay stored under superseded static rules must be refused, got {result:?}"
    );
    assert!(!finalized_response_replay_for_test(&replay_ctx));
    runtime_overlay::reset_for_test();
}

/// Equivalent policy must stay replayable: an unrelated reload that rebuilds the
/// same configuration derives the same digest, so retained responses survive.
#[tokio::test]
#[allow(clippy::await_holding_lock)] // `test_lock()` must span plugin awaits to serialize overlay state
async fn replay_survives_a_rebuild_of_equivalent_response_policy() {
    use ferrum_edge::plugins::response_transformer::runtime_overlay;

    let _guard = ferrum_edge::modes::mesh::runtime_overlay_consumers::test_lock();
    runtime_overlay::reset_for_test();
    let plugin = make_plugin(json!({}));

    let stored_under = presentation_digest_for(&[redaction_transformer("[redacted]")]);
    // Rebuilt from an equivalent config whose keys were written in a different
    // order — the digest is content-derived and order-independent.
    let rebuilt = presentation_digest_for(&[json!({
        "rules": [{
            "key": "x-account",
            "value": "[redacted]",
            "target": "header",
            "operation": "update",
        }],
        "runtime_overlay_scope": "redaction",
    })]);
    assert_eq!(
        stored_under, rebuilt,
        "equivalent static policy must derive an identical digest across rebuilds"
    );

    let mut first_ctx = policy_bound_ctx(Some(stored_under));
    let mut headers = HashMap::from([(
        "idempotency-key".to_string(),
        "equivalent-policy".to_string(),
    )]);
    assert!(matches!(
        plugin.before_proxy(&mut first_ctx, &mut headers).await,
        PluginResult::Continue
    ));
    complete_response(&plugin, &mut first_ctx).await;

    let mut replay_ctx = policy_bound_ctx(Some(rebuilt));
    let result = plugin.before_proxy(&mut replay_ctx, &mut headers).await;
    assert!(
        matches!(
            result,
            PluginResult::RejectBinary {
                status_code: 201,
                ..
            }
        ),
        "an equivalent policy must still replay, got {result:?}"
    );
    assert!(finalized_response_replay_for_test(&replay_ctx));
    runtime_overlay::reset_for_test();
}

/// Response header/body rules are not commutative, so the same instances in a
/// different configured order are a different presentation policy.
#[test]
fn presentation_policy_digest_is_order_sensitive_across_transformer_instances() {
    let first = json!({
        "rules": [{"operation": "remove", "target": "header", "key": "x-internal"}],
    });
    let second = json!({
        "rules": [{
            "operation": "add",
            "target": "header",
            "key": "x-internal",
            "value": "public",
        }],
    });

    let forward = presentation_digest_for(&[first.clone(), second.clone()]);
    let reversed = presentation_digest_for(&[second, first.clone()]);
    assert_ne!(
        forward, reversed,
        "reordered transformer instances produce a different client representation \
         and must not share replay provenance"
    );

    let single = presentation_digest_for(&[first]);
    assert_ne!(
        forward, single,
        "adding a transformer instance must change the presentation policy digest"
    );
    let empty = presentation_policy_digest(Vec::<(&str, [u8; 32])>::new());
    assert_ne!(
        empty, single,
        "an empty policy is itself a policy and must not collide with a configured one"
    );
}

/// Digest of the effective static response-presentation policy for an ordered
/// list of `(plugin_name, config)` pairs, exactly as the plugin cache folds it
/// over one proxy's configured execution order. Unlike `presentation_digest_for`
/// this spans plugin *types*, which is what the completeness claim rests on.
fn presentation_digest_for_plugin_specs(specs: &[(&str, serde_json::Value)]) -> [u8; 32] {
    let plugins: Vec<Arc<dyn Plugin>> = specs
        .iter()
        .map(|(name, config)| {
            create_plugin_with_http_client(name, config, PluginHttpClient::default())
                .unwrap_or_else(|err| panic!("{name} config must be valid: {err}"))
                .unwrap_or_else(|| panic!("{name} must be a built-in plugin"))
        })
        .collect();
    let contributions: Vec<(&str, [u8; 32])> = plugins
        .iter()
        .filter_map(|plugin| match plugin.response_presentation_policy() {
            Some(ResponsePresentationPolicy::Static(digest)) => Some((plugin.name(), digest)),
            Some(ResponsePresentationPolicy::Dynamic) => {
                panic!(
                    "{} has no statically provable policy to fold",
                    plugin.name()
                )
            }
            None => None,
        })
        .collect();
    presentation_policy_digest(contributions)
}

/// `sse` with the given wrapping policy. `wrap_non_sse_responses` rewrites the
/// client-visible body into `data: ...` event framing, and `require_get_method`
/// is off so the policy is reachable on the non-safe methods dedup covers.
fn sse_wrapping_config(wrap: bool, retry_ms: u64) -> serde_json::Value {
    json!({
        "require_get_method": false,
        "require_accept_header": false,
        "wrap_non_sse_responses": wrap,
        "retry_ms": retry_ms,
    })
}

fn mcp_gateway_config(upstream_url: &str) -> serde_json::Value {
    json!({
        "enabled": true,
        "mode": "aggregate_router",
        "endpoint": {"path": "/mcp", "protocol_versions": ["2025-11-25"]},
        "servers": {
            "github": {
                "upstream_url": upstream_url,
                "namespace": "github",
                "enabled": true,
            }
        },
    })
}

/// The completeness residual this repair closes: the RTDS gate map and every
/// `response_transformer` rule are unchanged, but an `sse` wrap was enabled.
/// The finalized-replay path skips that wrap while `after_proxy` still relabels
/// the response `text/event-stream`, so a replay stored before the change would
/// be delivered unwrapped under an event-stream label.
#[tokio::test]
#[allow(clippy::await_holding_lock)] // `test_lock()` must span plugin awaits to serialize overlay state
async fn replay_is_rejected_when_a_non_response_transformer_presentation_policy_changes() {
    let _guard = ferrum_edge::modes::mesh::runtime_overlay_consumers::test_lock();
    ferrum_edge::plugins::response_transformer::runtime_overlay::reset_for_test();
    let plugin = make_plugin(json!({}));
    let unchanged_transformer = redaction_transformer("[redacted]");

    let before = presentation_digest_for_plugin_specs(&[
        ("sse", sse_wrapping_config(false, 3000)),
        ("response_transformer", unchanged_transformer.clone()),
    ]);
    let after = presentation_digest_for_plugin_specs(&[
        ("sse", sse_wrapping_config(true, 3000)),
        ("response_transformer", unchanged_transformer),
    ]);
    assert_ne!(
        before, after,
        "enabling an sse body wrap must change the presentation policy digest"
    );

    let mut first_ctx = policy_bound_ctx(Some(before));
    let mut headers = HashMap::from([("idempotency-key".to_string(), "sse-wrap".to_string())]);
    assert!(matches!(
        plugin.before_proxy(&mut first_ctx, &mut headers).await,
        PluginResult::Continue
    ));
    complete_response(&plugin, &mut first_ctx).await;

    let mut replay_ctx = policy_bound_ctx(Some(after));
    let result = plugin.before_proxy(&mut replay_ctx, &mut headers).await;
    assert!(
        matches!(
            result,
            PluginResult::Reject {
                status_code: 409,
                ..
            }
        ),
        "a replay stored before the sse wrap was enabled must be refused, got {result:?}"
    );
    assert!(!finalized_response_replay_for_test(&replay_ctx));
}

/// `mcp_gateway` must not claim a statically provable presentation policy. Its
/// public URI/name rewrite is resolved against a per-session catalog re-listed
/// from upstream on a discovery TTL, so no digest computed at construction
/// describes it and a static enrollment would be a false compatibility claim.
#[test]
fn mcp_gateway_reports_a_dynamic_presentation_policy() {
    let plugin = create_plugin_with_http_client(
        "mcp_gateway",
        &mcp_gateway_config("http://mcp-alpha:8080"),
        PluginHttpClient::default(),
    )
    .expect("mcp_gateway config must be valid")
    .expect("mcp_gateway must be a built-in plugin");

    assert_eq!(
        plugin.response_presentation_policy(),
        Some(ResponsePresentationPolicy::Dynamic),
        "mcp_gateway's rewrite comes from live catalog state, not configuration"
    );
}

#[test]
fn internally_disabled_mcp_gateway_reports_no_presentation_policy() {
    let mut config = mcp_gateway_config("http://mcp-alpha:8080");
    config["enabled"] = serde_json::Value::Bool(false);
    let plugin =
        create_plugin_with_http_client("mcp_gateway", &config, PluginHttpClient::default())
            .expect("disabled mcp_gateway config must be valid")
            .expect("disabled mcp_gateway must remain a built-in plugin");

    assert_eq!(
        plugin.response_presentation_policy(),
        None,
        "an internally disabled mcp_gateway applies no response rewrite"
    );
}

/// The name list config admission uses must not drift from the runtime
/// behavior it stands in for: admission works on `PluginConfig` names before any
/// plugin exists, so the join between the two surfaces is by name alone.
#[test]
fn every_dynamic_presentation_plugin_name_reports_dynamic_when_constructed() {
    for name in DYNAMIC_RESPONSE_PRESENTATION_PLUGINS {
        let config = match *name {
            "mcp_gateway" => mcp_gateway_config("http://mcp-alpha:8080"),
            other => panic!("no test config for dynamic presentation plugin '{other}'"),
        };
        let plugin = create_plugin_with_http_client(name, &config, PluginHttpClient::default())
            .unwrap_or_else(|err| panic!("{name} config must be valid: {err}"))
            .unwrap_or_else(|| panic!("{name} must be a built-in plugin"));
        assert_eq!(
            plugin.response_presentation_policy(),
            Some(ResponsePresentationPolicy::Dynamic),
            "{name} is listed as dynamic for config admission but does not report Dynamic"
        );
    }
}

/// A proxy whose presentation policy cannot be established retains nothing for
/// replay. Without this, a `Dynamic` plugin's `None` digest would compare equal
/// to the next request's `None` and replay under a catalog nobody witnessed.
#[tokio::test]
#[allow(clippy::await_holding_lock)] // `test_lock()` must span plugin awaits to serialize overlay state
async fn unprovable_presentation_policy_retains_no_replayable_representation() {
    let _guard = ferrum_edge::modes::mesh::runtime_overlay_consumers::test_lock();
    ferrum_edge::plugins::response_transformer::runtime_overlay::reset_for_test();
    let plugin = make_plugin(json!({}));

    let mut first_ctx = policy_bound_ctx(None);
    let mut headers = HashMap::from([("idempotency-key".to_string(), "unprovable".to_string())]);
    assert!(matches!(
        plugin.before_proxy(&mut first_ctx, &mut headers).await,
        PluginResult::Continue
    ));
    complete_response(&plugin, &mut first_ctx).await;

    // Same unestablished policy on both sides. "Unknown" must not match
    // "unknown" — the second request is refused rather than replayed.
    let mut replay_ctx = policy_bound_ctx(None);
    let result = plugin.before_proxy(&mut replay_ctx, &mut headers).await;
    assert!(
        matches!(
            result,
            PluginResult::Reject {
                status_code: 409,
                ..
            }
        ),
        "an unprovable presentation policy must never replay, got {result:?}"
    );
    assert!(!finalized_response_replay_for_test(&replay_ctx));
}

/// A representation stored under a provable policy must not be replayed to a
/// later request whose policy could not be established — the direction that
/// matters after a reload adds an `mcp_gateway` to a proxy that already has
/// retained responses.
#[tokio::test]
#[allow(clippy::await_holding_lock)] // `test_lock()` must span plugin awaits to serialize overlay state
async fn provable_stored_policy_does_not_replay_under_an_unprovable_live_policy() {
    let _guard = ferrum_edge::modes::mesh::runtime_overlay_consumers::test_lock();
    ferrum_edge::plugins::response_transformer::runtime_overlay::reset_for_test();
    let plugin = make_plugin(json!({}));

    let stored_under = presentation_digest_for(&[redaction_transformer("[redacted]")]);
    let mut first_ctx = policy_bound_ctx(Some(stored_under));
    let mut headers = HashMap::from([(
        "idempotency-key".to_string(),
        "provable-then-not".to_string(),
    )]);
    assert!(matches!(
        plugin.before_proxy(&mut first_ctx, &mut headers).await,
        PluginResult::Continue
    ));
    complete_response(&plugin, &mut first_ctx).await;

    let mut replay_ctx = policy_bound_ctx(None);
    let result = plugin.before_proxy(&mut replay_ctx, &mut headers).await;
    assert!(
        matches!(
            result,
            PluginResult::Reject {
                status_code: 409,
                ..
            }
        ),
        "a stored replay must not be served once the live policy is unprovable, got {result:?}"
    );
    assert!(!finalized_response_replay_for_test(&replay_ctx));
}

/// The complement of the rejection above: an unrelated reload that rebuilds an
/// equivalent multi-plugin presentation policy must keep replays serviceable,
/// so provenance retires only representations that are genuinely superseded.
#[tokio::test]
#[allow(clippy::await_holding_lock)] // `test_lock()` must span plugin awaits to serialize overlay state
async fn replay_survives_an_equivalent_rebuild_of_a_multi_plugin_presentation_policy() {
    let _guard = ferrum_edge::modes::mesh::runtime_overlay_consumers::test_lock();
    ferrum_edge::plugins::response_transformer::runtime_overlay::reset_for_test();
    let plugin = make_plugin(json!({}));

    let stored_under = presentation_digest_for_plugin_specs(&[
        ("sse", sse_wrapping_config(true, 3000)),
        ("response_transformer", redaction_transformer("[redacted]")),
    ]);
    // Same accepted policy, written with the object members in another order.
    let rebuilt = presentation_digest_for_plugin_specs(&[
        (
            "sse",
            json!({
                "retry_ms": 3000,
                "wrap_non_sse_responses": true,
                "require_accept_header": false,
                "require_get_method": false,
            }),
        ),
        (
            "response_transformer",
            json!({
                "rules": [{
                    "key": "x-account",
                    "value": "[redacted]",
                    "target": "header",
                    "operation": "update",
                }],
                "runtime_overlay_scope": "redaction",
            }),
        ),
    ]);
    assert_eq!(
        stored_under, rebuilt,
        "equivalent multi-plugin policy must derive an identical digest across rebuilds"
    );

    let mut first_ctx = policy_bound_ctx(Some(stored_under));
    let mut headers = HashMap::from([(
        "idempotency-key".to_string(),
        "equivalent-multi".to_string(),
    )]);
    assert!(matches!(
        plugin.before_proxy(&mut first_ctx, &mut headers).await,
        PluginResult::Continue
    ));
    complete_response(&plugin, &mut first_ctx).await;

    let mut replay_ctx = policy_bound_ctx(Some(rebuilt));
    let result = plugin.before_proxy(&mut replay_ctx, &mut headers).await;
    assert!(
        matches!(
            result,
            PluginResult::RejectBinary {
                status_code: 201,
                ..
            }
        ),
        "an equivalent policy must still replay, got {result:?}"
    );
    assert!(finalized_response_replay_for_test(&replay_ctx));
}

/// Presence, multiplicity, and configured order across plugin *types* all move
/// the digest. Order matters in production because `priority_override` and
/// multiple instances can put an `sse` wrap on either side of a
/// `response_transformer` body rule, and the two orders are different bytes.
#[test]
fn presentation_policy_digest_covers_presence_multiplicity_and_order_across_plugin_types() {
    let sse = ("sse", sse_wrapping_config(true, 3000));
    let transformer = ("response_transformer", redaction_transformer("[redacted]"));

    let transformer_only = presentation_digest_for_plugin_specs(std::slice::from_ref(&transformer));
    let with_sse = presentation_digest_for_plugin_specs(&[sse.clone(), transformer.clone()]);
    assert_ne!(
        transformer_only, with_sse,
        "adding an enrolled plugin of another type must change the digest"
    );

    let reversed = presentation_digest_for_plugin_specs(&[transformer.clone(), sse.clone()]);
    assert_ne!(
        with_sse, reversed,
        "an sse wrap before vs. after a body rule is a different representation"
    );

    let duplicated =
        presentation_digest_for_plugin_specs(&[sse.clone(), sse.clone(), transformer.clone()]);
    assert_ne!(
        with_sse, duplicated,
        "a second instance of the same plugin must change the digest"
    );
}

/// Pins the audited exclusion set. These plugins transform response bodies but
/// deliberately contribute no provenance: `compression` and `grpc_web` are
/// coding/framing mechanics bound by the request fingerprint rather than static
/// presentation policy, and the AI guards re-run their current-policy decision
/// over the replayed bytes through `requires_replay_response_body_transform`.
/// Enrolling one of them later must be a deliberate change, not a drift.
#[test]
fn audited_non_presentation_body_transforms_do_not_contribute_provenance() {
    let guard = json!({"pii_patterns": ["email"], "action": "redact"});
    let governor = json!({
        "default_action": "allow",
        "tools": { "filesystem.write": { "action": "deny" } }
    });
    for (name, config) in [
        ("compression", json!({})),
        ("grpc_web", json!({})),
        ("ai_response_guard", guard),
        ("ai_tool_governor", governor),
    ] {
        let plugin = create_plugin_with_http_client(name, &config, PluginHttpClient::default())
            .unwrap_or_else(|err| panic!("{name} config must be valid: {err}"))
            .unwrap_or_else(|| panic!("{name} must be a built-in plugin"));
        assert!(
            plugin.response_presentation_policy().is_none(),
            "{name} is an audited exclusion from replay provenance; enrolling it must be \
             a deliberate change with its own reasoning"
        );
    }
}

/// A request that never observed the effective static policy has unprovable
/// provenance and must not leave a replayable representation in Redis.
#[test]
fn redis_persistence_is_refused_without_complete_provenance() {
    let plugin = make_plugin(json!({}));
    assert!(
        request_deduplication_redis_payload_for_test(
            &plugin,
            201,
            HashMap::new(),
            b"{\"ok\":true}",
            None,
        )
        .is_none(),
        "incomplete replay provenance must never be persisted for cross-process replay"
    );
}

#[tokio::test]
async fn committed_replay_skips_second_response_body_transform() {
    let dedup = make_plugin(json!({}));
    let mut first_ctx = new_ctx("POST", "/api");
    let mut first_headers =
        HashMap::from([("idempotency-key".to_string(), "finalized".to_string())]);
    assert!(matches!(
        dedup.before_proxy(&mut first_ctx, &mut first_headers).await,
        PluginResult::Continue
    ));
    assert!(matches!(
        dedup
            .on_final_response_body(
                &mut first_ctx,
                200,
                &HashMap::from([("content-type".to_string(), "text/plain".to_string())]),
                b"presented-once",
            )
            .await,
        PluginResult::Continue
    ));

    let mut replay_ctx = new_ctx("POST", "/api");
    let mut replay_headers =
        HashMap::from([("idempotency-key".to_string(), "finalized".to_string())]);
    let replay = dedup
        .before_proxy(&mut replay_ctx, &mut replay_headers)
        .await;
    let transforms: Vec<Arc<dyn Plugin>> = vec![Arc::new(AppendingResponseTransform)];
    match finalize_plugin_rejection_for_test(&transforms, &mut replay_ctx, replay).await {
        PluginResult::RejectBinary { body, .. } => assert_eq!(&body[..], b"presented-once"),
        other => panic!("expected finalized replay, got {other:?}"),
    }
    assert_eq!(
        replay_ctx
            .metadata
            .get("test:replay-inspected")
            .map(String::as_str),
        Some("true"),
        "finalized replays must still run response inspection"
    );

    let mut ordinary_ctx = new_ctx("POST", "/api");
    let ordinary = PluginResult::RejectBinary {
        status_code: 200,
        body: Bytes::from_static(b"presented-once"),
        headers: HashMap::from([("content-type".to_string(), "text/plain".to_string())]),
    };
    match finalize_plugin_rejection_for_test(&transforms, &mut ordinary_ctx, ordinary).await {
        PluginResult::RejectBinary { body, .. } => {
            assert_eq!(&body[..], b"presented-once|transformed")
        }
        other => panic!("expected ordinary transformed response, got {other:?}"),
    }
}

#[tokio::test]
async fn committed_replay_runs_current_ai_response_redaction() {
    let dedup = make_plugin(json!({}));
    let response_headers =
        HashMap::from([("content-type".to_string(), "application/json".to_string())]);
    let stale_body = br#"{"choices":[{"message":{"content":"Contact user@example.com"}}]}"#;

    let mut first_ctx = new_ctx("POST", "/chat");
    let mut first_headers =
        HashMap::from([("idempotency-key".to_string(), "guard-replay".to_string())]);
    assert!(matches!(
        dedup.before_proxy(&mut first_ctx, &mut first_headers).await,
        PluginResult::Continue
    ));
    assert!(matches!(
        dedup
            .on_final_response_body(&mut first_ctx, 200, &response_headers, stale_body)
            .await,
        PluginResult::Continue
    ));

    let guard = AiResponseGuard::new(&json!({
        "pii_patterns": ["email"],
        "action": "redact"
    }))
    .unwrap();
    let plugins: Vec<Arc<dyn Plugin>> = vec![Arc::new(guard)];
    let mut replay_ctx = new_ctx("POST", "/chat");
    let mut replay_headers =
        HashMap::from([("idempotency-key".to_string(), "guard-replay".to_string())]);
    let replay = dedup
        .before_proxy(&mut replay_ctx, &mut replay_headers)
        .await;

    match finalize_plugin_rejection_for_test(&plugins, &mut replay_ctx, replay).await {
        PluginResult::RejectBinary {
            status_code, body, ..
        } => {
            assert_eq!(status_code, 200);
            let body = String::from_utf8(body.to_vec()).unwrap();
            assert!(
                !body.contains("user@example.com"),
                "stale PII replayed: {body}"
            );
            assert!(body.contains("[REDACTED:pii:email]"), "{body}");
        }
        other => panic!("expected redacted finalized replay, got {other:?}"),
    }
}

#[tokio::test]
async fn committed_replay_runs_current_tool_argument_redaction() {
    let dedup = make_plugin(json!({}));
    let response_headers =
        HashMap::from([("content-type".to_string(), "application/json".to_string())]);
    let stale_body = json!({
        "id": "chatcmpl-replay",
        "object": "chat.completion",
        "model": "gpt-4o",
        "choices": [{
            "message": {
                "role": "assistant",
                "tool_calls": [{
                    "id": "call_1",
                    "type": "function",
                    "function": {
                        "name": "filesystem.write",
                        "arguments": "{\"token\":\"sk-STALESECRET123\"}"
                    }
                }]
            }
        }]
    })
    .to_string()
    .into_bytes();

    let mut first_ctx = new_ctx("POST", "/chat");
    let mut first_headers =
        HashMap::from([("idempotency-key".to_string(), "governor-replay".to_string())]);
    assert!(matches!(
        dedup.before_proxy(&mut first_ctx, &mut first_headers).await,
        PluginResult::Continue
    ));
    assert!(matches!(
        dedup
            .on_final_response_body(&mut first_ctx, 200, &response_headers, &stale_body)
            .await,
        PluginResult::Continue
    ));

    let governor = AiToolGovernor::new(
        &json!({
            "default_action": "allow",
            "tools": {
                "filesystem.write": {
                    "action": "redact_args",
                    "blocked_arg_patterns": [{
                        "name": "secret",
                        "regex": "sk-[A-Za-z0-9]+"
                    }]
                }
            }
        }),
        PluginHttpClient::default(),
    )
    .unwrap();
    let plugins: Vec<Arc<dyn Plugin>> = vec![Arc::new(governor)];
    let mut replay_ctx = new_ctx("POST", "/chat");
    let mut replay_headers =
        HashMap::from([("idempotency-key".to_string(), "governor-replay".to_string())]);
    let replay = dedup
        .before_proxy(&mut replay_ctx, &mut replay_headers)
        .await;

    match finalize_plugin_rejection_for_test(&plugins, &mut replay_ctx, replay).await {
        PluginResult::RejectBinary {
            status_code, body, ..
        } => {
            assert_eq!(status_code, 200);
            let body = String::from_utf8(body.to_vec()).unwrap();
            assert!(
                !body.contains("sk-STALESECRET123"),
                "stale tool secret replayed: {body}"
            );
            assert!(body.contains("[REDACTED_TOOL_ARG:secret]"), "{body}");
        }
        other => panic!("expected governed finalized replay, got {other:?}"),
    }
}

#[tokio::test]
async fn committed_replay_fails_closed_when_required_transform_cannot_rewrite() {
    let dedup = make_plugin(json!({}));
    let mut first_ctx = new_ctx("POST", "/api");
    let mut first_headers = HashMap::from([(
        "idempotency-key".to_string(),
        "failed-redaction".to_string(),
    )]);
    assert!(matches!(
        dedup.before_proxy(&mut first_ctx, &mut first_headers).await,
        PluginResult::Continue
    ));
    assert!(matches!(
        dedup
            .on_final_response_body(
                &mut first_ctx,
                200,
                &HashMap::from([("content-type".to_string(), "text/plain".to_string())]),
                b"sensitive replay",
            )
            .await,
        PluginResult::Continue
    ));

    let mut replay_ctx = new_ctx("POST", "/api");
    let mut replay_headers = HashMap::from([(
        "idempotency-key".to_string(),
        "failed-redaction".to_string(),
    )]);
    let replay = dedup
        .before_proxy(&mut replay_ctx, &mut replay_headers)
        .await;
    let plugins: Vec<Arc<dyn Plugin>> = vec![Arc::new(FailingMandatoryReplayTransform)];

    match finalize_plugin_rejection_for_test(&plugins, &mut replay_ctx, replay).await {
        PluginResult::RejectBinary {
            status_code, body, ..
        } => {
            assert_eq!(status_code, 502);
            assert_eq!(&body[..], br#"{"error":"response redaction failed"}"#);
        }
        other => panic!("required replay rewrite must fail closed, got {other:?}"),
    }
}

// Marker set by the proxy on `ctx.metadata` while the response-body hooks run
// over a synthetic 2xx plugin short-circuit body (mirrors
// `crate::proxy::SYNTHETIC_SHORT_CIRCUIT_METADATA_KEY`, which is `pub(crate)` and
// therefore not reachable from this external test crate).
const SYNTHETIC_SHORT_CIRCUIT_METADATA_KEY: &str = "ferrum:synthetic_short_circuit";

// Marker set by an ownership producer (e.g. `ai_federation`) on `ctx.metadata`
// once a billable/side-effecting external operation has a committed or ambiguous
// outcome behind a synthetic short-circuit (mirrors the `pub(crate)`
// `crate::plugins::EXTERNAL_OPERATION_COMPLETED_METADATA_KEY`, which is not
// reachable from this external test crate).
const EXTERNAL_OPERATION_COMPLETED_METADATA_KEY: &str = "ferrum:external_operation_completed";

// A FRESH request that this plugin marked in-flight, then short-circuited by a
// LATER `before_proxy` plugin (e.g. a 2xx `fault_injection` abort / synthetic AI
// response), must NOT have its synthetic body stored under the idempotency key.
// A subsequent request with the same key must be treated as a brand-new request
// (Continue), not replayed from a poisoned cache entry.
#[tokio::test]
async fn synthetic_short_circuit_2xx_is_not_stored_under_dedup_key() {
    let plugin = make_plugin(json!({}));

    // First request acquires the in-flight marker and a dedup key.
    let mut ctx1 = new_ctx("POST", "/api");
    let mut headers1 = HashMap::new();
    headers1.insert("idempotency-key".to_string(), "key-1".to_string());

    let result = plugin.before_proxy(&mut ctx1, &mut headers1).await;
    assert!(matches!(result, PluginResult::Continue));
    assert!(request_identity(&plugin, &ctx1).is_some());

    // A later before_proxy plugin short-circuits with a synthetic 2xx body. The
    // proxy marks the context before running the response-body hooks; emulate it.
    ctx1.metadata.insert(
        SYNTHETIC_SHORT_CIRCUIT_METADATA_KEY.to_string(),
        "true".to_string(),
    );
    let mut response_headers = HashMap::new();
    response_headers.insert("content-type".to_string(), "application/json".to_string());
    let result = plugin
        .on_final_response_body(&mut ctx1, 200, &response_headers, b"{\"synthetic\": true}")
        .await;
    assert!(matches!(result, PluginResult::Continue));

    // Nothing was cached: no completed-response bytes are retained, and the
    // in-flight marker was released (not left dangling until TTL).
    assert_eq!(
        assert_completed_size_exact(&plugin),
        0,
        "synthetic short-circuit body must not be stored as a completed response"
    );

    // A second request with the SAME key is treated as Fresh — it passes
    // through to the backend rather than replaying the synthetic body.
    let mut ctx2 = new_ctx("POST", "/api");
    let mut headers2 = HashMap::new();
    headers2.insert("idempotency-key".to_string(), "key-1".to_string());

    let result = plugin.before_proxy(&mut ctx2, &mut headers2).await;
    assert!(
        matches!(result, PluginResult::Continue),
        "second request with same key must pass through, not replay a synthetic body; got {result:?}"
    );
    assert!(request_identity(&plugin, &ctx2).is_some());
}

// Marker set by the shared H1/H2/H3 reject finalizer for every finalized
// successful HTTP 2xx synthetic short-circuit (including empty 200 and 204), independent
// of whether synthetic response-body hooks ran. Mirrors
// `crate::proxy::FINALIZED_SYNTHETIC_RESPONSE_METADATA_KEY`.
const FINALIZED_SYNTHETIC_RESPONSE_METADATA_KEY: &str = "ferrum:finalized_synthetic_response";

async fn finalize_empty_synthetic_and_assert_second_request_continues(
    status_code: u16,
    idempotency_key: &str,
) {
    let dedup = Arc::new(make_plugin(json!({})));
    let plugins: Vec<Arc<dyn Plugin>> = vec![Arc::clone(&dedup) as Arc<dyn Plugin>];

    let mut ctx = new_ctx("POST", "/orders");
    let mut headers = HashMap::new();
    headers.insert("idempotency-key".to_string(), idempotency_key.to_string());
    assert!(matches!(
        dedup.before_proxy(&mut ctx, &mut headers).await,
        PluginResult::Continue
    ));
    assert!(request_identity(&dedup, &ctx).is_some());

    let finalized = finalize_plugin_rejection_for_test(
        &plugins,
        &mut ctx,
        PluginResult::Reject {
            status_code,
            body: String::new(),
            headers: HashMap::new(),
        },
    )
    .await;
    match finalized {
        PluginResult::RejectBinary {
            status_code: final_status,
            ..
        } => assert_eq!(final_status, status_code),
        other => panic!("expected finalized RejectBinary, got {other:?}"),
    }
    assert!(
        !ctx.metadata
            .contains_key(FINALIZED_SYNTHETIC_RESPONSE_METADATA_KEY),
        "internal finalized-synthetic signal must be consumed before transaction logging"
    );
    assert_eq!(
        assert_completed_size_exact(&dedup),
        0,
        "empty/204 synthetic successes must not be stored as completed responses"
    );

    let mut retry_ctx = new_ctx("POST", "/orders");
    let mut retry_headers = HashMap::new();
    retry_headers.insert("idempotency-key".to_string(), idempotency_key.to_string());
    let retry = dedup.before_proxy(&mut retry_ctx, &mut retry_headers).await;
    assert!(
        matches!(retry, PluginResult::Continue),
        "identical request after finalized empty/204 synthetic success must not see a stale 409; got {retry:?}"
    );
}

#[tokio::test]
async fn empty_synthetic_200_releases_dedup_inflight_via_finalized_signal() {
    finalize_empty_synthetic_and_assert_second_request_continues(200, "empty-200-key").await;
}

#[tokio::test]
async fn synthetic_204_releases_dedup_inflight_via_finalized_signal() {
    finalize_empty_synthetic_and_assert_second_request_continues(204, "empty-204-key").await;
}

#[tokio::test]
async fn h3_deferred_committed_hooks_keep_finalized_signal_for_empty_synthetic_success() {
    let dedup = Arc::new(make_plugin(json!({})));
    let plugins: Vec<Arc<dyn Plugin>> = vec![Arc::clone(&dedup) as Arc<dyn Plugin>];

    let mut ctx = new_ctx("POST", "/orders");
    let mut headers = HashMap::new();
    headers.insert(
        "idempotency-key".to_string(),
        "h3-empty-204-key".to_string(),
    );
    assert!(matches!(
        dedup.before_proxy(&mut ctx, &mut headers).await,
        PluginResult::Continue
    ));

    let finalized = finalize_plugin_rejection_without_committed_hooks_for_test(
        &plugins,
        &mut ctx,
        PluginResult::Reject {
            status_code: 204,
            body: String::new(),
            headers: HashMap::new(),
        },
    )
    .await;
    assert!(matches!(
        finalized,
        PluginResult::RejectBinary {
            status_code: 204,
            ..
        }
    ));
    assert!(
        ctx.metadata
            .contains_key(FINALIZED_SYNTHETIC_RESPONSE_METADATA_KEY),
        "H3 finalizer mode must preserve the marker for its later committed-hook phase"
    );

    dedup
        .on_response_committed(&mut ctx, 204, &HashMap::new(), &[])
        .await;
    ctx.metadata
        .remove(FINALIZED_SYNTHETIC_RESPONSE_METADATA_KEY);

    let mut retry_ctx = new_ctx("POST", "/orders");
    let mut retry_headers = HashMap::new();
    retry_headers.insert(
        "idempotency-key".to_string(),
        "h3-empty-204-key".to_string(),
    );
    let retry = dedup.before_proxy(&mut retry_ctx, &mut retry_headers).await;
    assert!(
        matches!(retry, PluginResult::Continue),
        "later H3 committed hook must release in-flight ownership; got {retry:?}"
    );
}

#[tokio::test]
async fn non_2xx_plugin_reject_retains_dedup_inflight_until_ttl() {
    let dedup = Arc::new(make_plugin(json!({
        "inflight_ttl_seconds": 60,
        "ttl_seconds": 60
    })));
    let plugins: Vec<Arc<dyn Plugin>> = vec![Arc::clone(&dedup) as Arc<dyn Plugin>];

    let mut ctx = new_ctx("POST", "/orders");
    let mut headers = HashMap::new();
    headers.insert(
        "idempotency-key".to_string(),
        "non-2xx-retain-key".to_string(),
    );
    assert!(matches!(
        dedup.before_proxy(&mut ctx, &mut headers).await,
        PluginResult::Continue
    ));

    let finalized = finalize_plugin_rejection_for_test(
        &plugins,
        &mut ctx,
        PluginResult::Reject {
            status_code: 503,
            body: r#"{"error":"upstream unavailable"}"#.to_string(),
            headers: HashMap::new(),
        },
    )
    .await;
    assert!(matches!(
        finalized,
        PluginResult::RejectBinary {
            status_code: 503,
            ..
        }
    ));
    assert!(
        !ctx.metadata
            .contains_key(FINALIZED_SYNTHETIC_RESPONSE_METADATA_KEY),
        "non-2xx rejects must not set the finalized-synthetic success signal"
    );

    let mut retry_ctx = new_ctx("POST", "/orders");
    let mut retry_headers = HashMap::new();
    retry_headers.insert(
        "idempotency-key".to_string(),
        "non-2xx-retain-key".to_string(),
    );
    assert!(
        matches!(
            dedup.before_proxy(&mut retry_ctx, &mut retry_headers).await,
            PluginResult::Reject {
                status_code: 409,
                ..
            }
        ),
        "non-2xx downstream rejection must intentionally retain in-flight ownership until TTL"
    );

    request_deduplication_expire_inflight_entries_for_test(&dedup);
    let mut after_ttl_ctx = new_ctx("POST", "/orders");
    let mut after_ttl_headers = HashMap::new();
    after_ttl_headers.insert(
        "idempotency-key".to_string(),
        "non-2xx-retain-key".to_string(),
    );
    assert!(matches!(
        dedup
            .before_proxy(&mut after_ttl_ctx, &mut after_ttl_headers)
            .await,
        PluginResult::Continue
    ));
}

#[tokio::test]
async fn late_finalized_synthetic_release_does_not_clear_successor_marker() {
    let dedup = Arc::new(make_plugin(json!({
        "inflight_ttl_seconds": 1,
        "ttl_seconds": 60
    })));
    let plugins: Vec<Arc<dyn Plugin>> = vec![Arc::clone(&dedup) as Arc<dyn Plugin>];

    let mut first_ctx = new_ctx("POST", "/orders");
    let mut first_headers = HashMap::new();
    first_headers.insert(
        "idempotency-key".to_string(),
        "successor-safe-key".to_string(),
    );
    assert!(matches!(
        dedup.before_proxy(&mut first_ctx, &mut first_headers).await,
        PluginResult::Continue
    ));

    // Simulate the original request dying without committing; TTL cleanup makes
    // the key available for a successor with a new owner token.
    request_deduplication_expire_inflight_entries_for_test(&dedup);

    let mut successor_ctx = new_ctx("POST", "/orders");
    let mut successor_headers = HashMap::new();
    successor_headers.insert(
        "idempotency-key".to_string(),
        "successor-safe-key".to_string(),
    );
    assert!(matches!(
        dedup
            .before_proxy(&mut successor_ctx, &mut successor_headers)
            .await,
        PluginResult::Continue
    ));

    // A late finalizer for the original request still carries that request's
    // ownership state. Token matching must leave the successor's marker intact.
    let _ = finalize_plugin_rejection_for_test(
        &plugins,
        &mut first_ctx,
        PluginResult::Reject {
            status_code: 200,
            body: String::new(),
            headers: HashMap::new(),
        },
    )
    .await;

    let mut conflict_ctx = new_ctx("POST", "/orders");
    let mut conflict_headers = HashMap::new();
    conflict_headers.insert(
        "idempotency-key".to_string(),
        "successor-safe-key".to_string(),
    );
    assert!(
        matches!(
            dedup
                .before_proxy(&mut conflict_ctx, &mut conflict_headers)
                .await,
            PluginResult::Reject {
                status_code: 409,
                ..
            }
        ),
        "late finalized-synthetic release must not clear a successor's in-flight marker"
    );
}

// A FRESH request marked in-flight by this plugin, then short-circuited by a
// synthetic response AFTER a committed/ambiguous external operation (the
// `ai_federation` provider-call lifecycle), must not release the in-flight
// marker on the early final-body pass and must not cache the synthetic body.
// Instead the observe-only committed hook publishes a non-replayable 409
// tombstone so an identical retry is rejected deterministically for the cache
// TTL rather than either re-running the side effect (fresh) or eating a bare
// "already in progress" in-flight conflict. This isolates the shared dedup
// lifecycle exercised end-to-end by the `ai_federation` suite, without the
// federation plugin, so a future dedup refactor cannot silently drop it again.
#[tokio::test]
async fn external_operation_completed_publishes_non_replayable_tombstone_at_commit() {
    let plugin = make_plugin(json!({}));

    // First request acquires the in-flight marker and a dedup key.
    let mut ctx1 = new_ctx("POST", "/api");
    let mut headers1 = HashMap::new();
    headers1.insert("idempotency-key".to_string(), "ext-op-key".to_string());
    assert!(matches!(
        plugin.before_proxy(&mut ctx1, &mut headers1).await,
        PluginResult::Continue
    ));
    assert!(request_identity(&plugin, &ctx1).is_some());

    // The proxy marks the synthetic short-circuit before running the response
    // body hooks; the external-operation marker is what a committed provider
    // call sets. The early final-body pass must retain ownership: it neither
    // stores the synthetic body nor releases the in-flight marker.
    ctx1.metadata.insert(
        SYNTHETIC_SHORT_CIRCUIT_METADATA_KEY.to_string(),
        "true".to_string(),
    );
    ctx1.metadata.insert(
        EXTERNAL_OPERATION_COMPLETED_METADATA_KEY.to_string(),
        "true".to_string(),
    );
    let mut response_headers = HashMap::new();
    response_headers.insert("content-type".to_string(), "application/json".to_string());
    assert!(matches!(
        plugin
            .on_final_response_body(&mut ctx1, 200, &response_headers, b"{\"synthetic\": true}")
            .await,
        PluginResult::Continue
    ));
    assert_eq!(
        assert_completed_size_exact(&plugin),
        0,
        "synthetic external-operation body must not be stored as a replayable response"
    );

    // The proxy clears the synthetic marker before the committed hook. The
    // observe-only committed hook then publishes the non-replayable tombstone.
    ctx1.metadata.remove(SYNTHETIC_SHORT_CIRCUIT_METADATA_KEY);
    plugin
        .on_response_committed(&mut ctx1, 200, &response_headers, b"{\"synthetic\": true}")
        .await;

    // A retry with the SAME key must be rejected as a completed non-replayable
    // operation (409 "cannot be replayed safely"), NOT treated as fresh (which
    // would re-run the side effect) and NOT returned as a bare in-flight 409.
    let mut ctx2 = new_ctx("POST", "/api");
    let mut headers2 = HashMap::new();
    headers2.insert("idempotency-key".to_string(), "ext-op-key".to_string());
    match plugin.before_proxy(&mut ctx2, &mut headers2).await {
        PluginResult::RejectBinary {
            status_code,
            body,
            headers,
        } => {
            assert_eq!(status_code, 409);
            assert!(
                String::from_utf8_lossy(&body).contains("cannot be replayed safely"),
                "retry after a committed external operation must return the non-replayable tombstone, got {}",
                String::from_utf8_lossy(&body)
            );
            assert_eq!(
                headers.get("x-idempotent-replayed").map(String::as_str),
                Some("true")
            );
        }
        other => panic!("expected non-replayable completed tombstone, got {other:?}"),
    }
}

/// GHSA-8cr6-rw38-7j59: the external-operation tombstone replaces an in-flight
/// marker that blocked duplicates for `inflight_ttl_seconds`, so it must never
/// expire sooner than that lease. `inflight_ttl_seconds` may legitimately exceed
/// `ttl_seconds` (a long-running backend with a short replay-retention window);
/// retaining the barrier for only `ttl_seconds` there would make an
/// already-performed billable operation executable again EARLIER than the bare
/// marker did.
#[tokio::test]
async fn external_operation_tombstone_outlives_a_shorter_ttl_than_the_inflight_lease() {
    // Short replay retention, long in-flight protection.
    let plugin = make_plugin(json!({
        "ttl_seconds": 1,
        "inflight_ttl_seconds": 60
    }));

    let mut ctx1 = new_ctx("POST", "/api");
    let mut headers1 = HashMap::new();
    headers1.insert("idempotency-key".to_string(), "barrier-key".to_string());
    assert!(matches!(
        plugin.before_proxy(&mut ctx1, &mut headers1).await,
        PluginResult::Continue
    ));

    ctx1.metadata.insert(
        SYNTHETIC_SHORT_CIRCUIT_METADATA_KEY.to_string(),
        "true".to_string(),
    );
    ctx1.metadata.insert(
        EXTERNAL_OPERATION_COMPLETED_METADATA_KEY.to_string(),
        "true".to_string(),
    );
    let mut response_headers = HashMap::new();
    response_headers.insert("content-type".to_string(), "application/json".to_string());
    assert!(matches!(
        plugin
            .on_final_response_body(&mut ctx1, 200, &response_headers, b"{\"synthetic\": true}")
            .await,
        PluginResult::Continue
    ));
    ctx1.metadata.remove(SYNTHETIC_SHORT_CIRCUIT_METADATA_KEY);
    plugin
        .on_response_committed(&mut ctx1, 200, &response_headers, b"{\"synthetic\": true}")
        .await;

    // Past `ttl_seconds`, well inside `inflight_ttl_seconds`. An ordinary
    // completed replay would legitimately have expired here; the execution
    // barrier must not.
    tokio::time::sleep(std::time::Duration::from_millis(1_300)).await;

    let mut ctx2 = new_ctx("POST", "/api");
    let mut headers2 = HashMap::new();
    headers2.insert("idempotency-key".to_string(), "barrier-key".to_string());
    match plugin.before_proxy(&mut ctx2, &mut headers2).await {
        PluginResult::RejectBinary {
            status_code, body, ..
        } => {
            assert_eq!(status_code, 409);
            assert!(
                String::from_utf8_lossy(&body).contains("cannot be replayed safely"),
                "unexpected barrier body: {}",
                String::from_utf8_lossy(&body)
            );
        }
        other => panic!(
            "the external-operation barrier must outlive ttl_seconds when \
             inflight_ttl_seconds is longer, got {other:?}"
        ),
    }
}

/// GHSA-8cr6-rw38-7j59: neither response-byte admission limit may demote a
/// completed external operation back to an `InFlight` lease. The fixed-size
/// fallback barrier owns the longer completion deadline and consumes no
/// completed-response byte budget.
#[tokio::test]
async fn external_operation_barrier_survives_tiny_entry_and_total_byte_budgets() {
    for (label, config) in [
        (
            "entry",
            json!({
                "ttl_seconds": 60,
                "inflight_ttl_seconds": 1,
                "max_entry_size_bytes": 1,
                "max_total_size_bytes": 8192
            }),
        ),
        (
            "total",
            json!({
                "ttl_seconds": 60,
                "inflight_ttl_seconds": 1,
                "max_entry_size_bytes": 8192,
                "max_total_size_bytes": 1
            }),
        ),
    ] {
        let plugin = make_plugin(config);
        let key = format!("tiny-{label}-barrier");
        let mut owner_ctx = new_ctx("POST", "/api");
        let mut owner_headers = HashMap::from([("idempotency-key".to_string(), key.clone())]);
        assert!(matches!(
            plugin
                .before_proxy(&mut owner_ctx, &mut owner_headers)
                .await,
            PluginResult::Continue
        ));

        owner_ctx.metadata.insert(
            SYNTHETIC_SHORT_CIRCUIT_METADATA_KEY.to_string(),
            "true".to_string(),
        );
        owner_ctx.metadata.insert(
            EXTERNAL_OPERATION_COMPLETED_METADATA_KEY.to_string(),
            "true".to_string(),
        );
        assert!(matches!(
            plugin
                .on_final_response_body(
                    &mut owner_ctx,
                    200,
                    &HashMap::new(),
                    b"externally-executed"
                )
                .await,
            PluginResult::Continue
        ));
        owner_ctx
            .metadata
            .remove(SYNTHETIC_SHORT_CIRCUIT_METADATA_KEY);
        plugin
            .on_response_committed(&mut owner_ctx, 200, &HashMap::new(), b"externally-executed")
            .await;

        assert_eq!(plugin.tracked_keys_count(), Some(1));
        assert_eq!(
            assert_completed_size_exact(&plugin),
            0,
            "{label} budget must retain no response bytes"
        );

        // If admission had merely retained the old in-flight marker, this
        // deterministic expiry would reopen the operation. It must not affect
        // the explicit completion barrier.
        request_deduplication_expire_inflight_entries_for_test(&plugin);
        let mut protected_ctx = new_ctx("POST", "/api");
        let mut protected_headers = HashMap::from([("idempotency-key".to_string(), key.clone())]);
        assert!(
            matches!(
                plugin
                    .before_proxy(&mut protected_ctx, &mut protected_headers)
                    .await,
                PluginResult::Reject {
                    status_code: 409,
                    ..
                }
            ),
            "{label} budget shortened the completion barrier to inflight_ttl_seconds"
        );

        // The key becomes executable only after the barrier's own authoritative
        // max(ttl, inflight_ttl) deadline.
        request_deduplication_expire_execution_barriers_for_test(&plugin);
        let mut expired_ctx = new_ctx("POST", "/api");
        let mut expired_headers = HashMap::from([("idempotency-key".to_string(), key.clone())]);
        assert!(
            matches!(
                plugin
                    .before_proxy(&mut expired_ctx, &mut expired_headers)
                    .await,
                PluginResult::Continue
            ),
            "{label} barrier did not expire at its own retention deadline"
        );
    }
}

/// A response-byte admission skip must not shorten an external operation's
/// protection when the replay TTL is shorter than the in-flight lease.
#[tokio::test]
async fn oversized_external_operation_barrier_outlives_short_replay_ttl() {
    for (label, config) in [
        (
            "entry",
            json!({
                "ttl_seconds": 1,
                "inflight_ttl_seconds": 60,
                "max_entry_size_bytes": 1,
                "max_total_size_bytes": 8192
            }),
        ),
        (
            "total",
            json!({
                "ttl_seconds": 1,
                "inflight_ttl_seconds": 60,
                "max_entry_size_bytes": 8192,
                "max_total_size_bytes": 1
            }),
        ),
    ] {
        let plugin = make_plugin(config);
        let key = format!("long-lease-{label}");
        let mut owner_ctx = new_ctx("POST", "/api");
        let mut owner_headers = HashMap::from([("idempotency-key".to_string(), key.clone())]);
        assert!(matches!(
            plugin
                .before_proxy(&mut owner_ctx, &mut owner_headers)
                .await,
            PluginResult::Continue
        ));
        owner_ctx.metadata.insert(
            EXTERNAL_OPERATION_COMPLETED_METADATA_KEY.to_string(),
            "true".to_string(),
        );
        assert!(matches!(
            plugin
                .on_final_response_body(&mut owner_ctx, 200, &HashMap::new(), b"executed")
                .await,
            PluginResult::Continue
        ));

        tokio::time::sleep(std::time::Duration::from_millis(1_200)).await;

        let mut retry_ctx = new_ctx("POST", "/api");
        let mut retry_headers = HashMap::from([("idempotency-key".to_string(), key)]);
        assert!(
            matches!(
                plugin
                    .before_proxy(&mut retry_ctx, &mut retry_headers)
                    .await,
                PluginResult::Reject {
                    status_code: 409,
                    ..
                }
            ),
            "{label} size-skip barrier expired at ttl_seconds instead of inflight_ttl_seconds"
        );
    }
}

/// Total-capacity skip overflow must also retain the in-flight lease when replay
/// TTL is shorter than `inflight_ttl_seconds`.
#[tokio::test]
async fn total_capacity_barrier_overflow_outlives_short_replay_ttl() {
    let plugin = make_plugin(json!({
        "max_entries": 1,
        "ttl_seconds": 1,
        "inflight_ttl_seconds": 60,
        "max_entry_size_bytes": 8192,
        "max_total_size_bytes": 1
    }));

    for key in ["total-overflow-a", "total-overflow-b"] {
        let mut owner_ctx = new_ctx("POST", "/api");
        let mut owner_headers = HashMap::from([("idempotency-key".to_string(), key.to_string())]);
        assert!(matches!(
            plugin
                .before_proxy(&mut owner_ctx, &mut owner_headers)
                .await,
            PluginResult::Continue
        ));
        owner_ctx.metadata.insert(
            EXTERNAL_OPERATION_COMPLETED_METADATA_KEY.to_string(),
            "true".to_string(),
        );
        assert!(matches!(
            plugin
                .on_final_response_body(&mut owner_ctx, 200, &HashMap::new(), b"executed")
                .await,
            PluginResult::Continue
        ));
    }

    tokio::time::sleep(std::time::Duration::from_millis(1_200)).await;

    let mut blocked_ctx = new_ctx("POST", "/api");
    let mut blocked_headers = HashMap::from([(
        "idempotency-key".to_string(),
        "total-overflow-c".to_string(),
    )]);
    match plugin
        .before_proxy(&mut blocked_ctx, &mut blocked_headers)
        .await
    {
        PluginResult::Reject {
            status_code, body, ..
        } => {
            assert_eq!(status_code, 503);
            assert!(body.contains("execution-barrier capacity"));
        }
        other => {
            panic!("total-capacity barrier overflow must fail closed past ttl_seconds: {other:?}")
        }
    }
}

/// Per-key execution barriers are hard-capped. Additional completed operations
/// collapse into one fixed process-global refusal deadline rather than growing
/// attacker-influenced key storage or failing open.
#[tokio::test]
async fn execution_barrier_capacity_overflow_is_bounded_and_fail_closed() {
    let plugin = make_plugin(json!({
        "max_entries": 1,
        "ttl_seconds": 60,
        "inflight_ttl_seconds": 1,
        "max_entry_size_bytes": 1
    }));

    for key in ["barrier-cap-a", "barrier-cap-b"] {
        let mut ctx = new_ctx("POST", "/api");
        let mut headers = HashMap::from([("idempotency-key".to_string(), key.to_string())]);
        assert!(matches!(
            plugin.before_proxy(&mut ctx, &mut headers).await,
            PluginResult::Continue
        ));
        ctx.metadata.insert(
            EXTERNAL_OPERATION_COMPLETED_METADATA_KEY.to_string(),
            "true".to_string(),
        );
        plugin
            .on_response_committed(&mut ctx, 200, &HashMap::new(), b"done")
            .await;
    }

    // Only the first per-key barrier persists. The second remains a raw lease
    // only until its ordinary in-flight expiry; the fixed global deadline is
    // the durable fail-closed protection.
    request_deduplication_expire_inflight_entries_for_test(&plugin);
    let mut blocked_ctx = new_ctx("POST", "/api");
    let mut blocked_headers =
        HashMap::from([("idempotency-key".to_string(), "barrier-cap-c".to_string())]);
    match plugin
        .before_proxy(&mut blocked_ctx, &mut blocked_headers)
        .await
    {
        PluginResult::Reject {
            status_code, body, ..
        } => {
            assert_eq!(status_code, 503);
            assert!(body.contains("execution-barrier capacity"));
        }
        _ => panic!("execution-barrier overflow must fail closed"),
    }
    assert_eq!(
        plugin.tracked_keys_count(),
        Some(1),
        "overflow must not retain an additional long-lived per-key barrier"
    );
    assert_eq!(assert_completed_size_exact(&plugin), 0);

    request_deduplication_expire_execution_barriers_for_test(&plugin);
    let mut expired_ctx = new_ctx("POST", "/api");
    assert!(matches!(
        plugin
            .before_proxy(&mut expired_ctx, &mut blocked_headers)
            .await,
        PluginResult::Continue
    ));
}

/// A stale terminal hook must not publish over or clear the successor that
/// acquired after the execution barrier's authoritative deadline.
#[tokio::test]
async fn expired_execution_barrier_stale_owner_cannot_touch_successor() {
    let plugin = make_plugin(json!({
        "ttl_seconds": 60,
        "inflight_ttl_seconds": 1,
        "max_entry_size_bytes": 1
    }));
    let mut original_ctx = new_ctx("POST", "/api");
    let mut original_headers = HashMap::from([(
        "idempotency-key".to_string(),
        "barrier-stale-owner".to_string(),
    )]);
    assert!(matches!(
        plugin
            .before_proxy(&mut original_ctx, &mut original_headers)
            .await,
        PluginResult::Continue
    ));
    let (logical_key, fingerprint) =
        request_identity(&plugin, &original_ctx).expect("owner identity");
    original_ctx.metadata.insert(
        EXTERNAL_OPERATION_COMPLETED_METADATA_KEY.to_string(),
        "true".to_string(),
    );
    plugin
        .on_response_committed(&mut original_ctx, 200, &HashMap::new(), b"done")
        .await;

    request_deduplication_expire_execution_barriers_for_test(&plugin);
    let mut successor_ctx = new_ctx("POST", "/api");
    let mut successor_headers = original_headers.clone();
    assert!(matches!(
        plugin
            .before_proxy(&mut successor_ctx, &mut successor_headers)
            .await,
        PluginResult::Continue
    ));

    let mut stale_ctx = new_ctx("POST", "/api");
    request_deduplication_set_request_state_for_test(
        &plugin,
        &mut stale_ctx,
        &logical_key,
        &fingerprint,
        "stale-owner-token",
        None,
    );
    stale_ctx.metadata.insert(
        EXTERNAL_OPERATION_COMPLETED_METADATA_KEY.to_string(),
        "true".to_string(),
    );
    plugin
        .on_response_committed(&mut stale_ctx, 200, &HashMap::new(), b"stale")
        .await;

    let mut duplicate_ctx = new_ctx("POST", "/api");
    let mut duplicate_headers = original_headers;
    assert!(
        matches!(
            plugin
                .before_proxy(&mut duplicate_ctx, &mut duplicate_headers)
                .await,
            PluginResult::Reject {
                status_code: 409,
                ..
            }
        ),
        "stale barrier owner cleared or published over its successor"
    );
}

/// Capacity eviction must inherit the protected completion's original
/// retention clock. Starting a fresh in-flight clock at eviction would shorten
/// a `ttl_seconds > inflight_ttl_seconds` completion under later pressure.
#[tokio::test]
async fn protected_completion_eviction_preserves_original_barrier_deadline() {
    let plugin = make_plugin(json!({
        "max_entries": 1,
        "ttl_seconds": 60,
        "inflight_ttl_seconds": 1
    }));

    let mut protected_ctx = new_ctx("POST", "/api");
    let mut protected_headers = HashMap::from([(
        "idempotency-key".to_string(),
        "evicted-protected-completion".to_string(),
    )]);
    assert!(matches!(
        plugin
            .before_proxy(&mut protected_ctx, &mut protected_headers)
            .await,
        PluginResult::Continue
    ));
    protected_ctx.metadata.insert(
        EXTERNAL_OPERATION_COMPLETED_METADATA_KEY.to_string(),
        "true".to_string(),
    );
    plugin
        .on_response_committed(&mut protected_ctx, 200, &HashMap::new(), b"done")
        .await;
    assert!(assert_completed_size_exact(&plugin) > 0);

    // A later ordinary completion creates pressure. The protected completion
    // becomes a fixed-size barrier; trimming continues to remove the ordinary
    // replay because barrier conversion releases bytes but not a map slot.
    let mut pressure_ctx = new_ctx("POST", "/pressure");
    let mut pressure_headers = HashMap::from([(
        "idempotency-key".to_string(),
        "ordinary-pressure".to_string(),
    )]);
    assert!(matches!(
        plugin
            .before_proxy(&mut pressure_ctx, &mut pressure_headers)
            .await,
        PluginResult::Continue
    ));
    complete_response(&plugin, &mut pressure_ctx).await;
    assert_eq!(plugin.tracked_keys_count(), Some(1));
    assert_eq!(assert_completed_size_exact(&plugin), 0);

    request_deduplication_expire_inflight_entries_for_test(&plugin);
    let mut still_protected_ctx = new_ctx("POST", "/api");
    let mut still_protected_headers = protected_headers.clone();
    assert!(
        matches!(
            plugin
                .before_proxy(&mut still_protected_ctx, &mut still_protected_headers)
                .await,
            PluginResult::Reject {
                status_code: 409,
                ..
            }
        ),
        "capacity eviction shortened ttl_seconds to a fresh inflight_ttl_seconds lease"
    );

    request_deduplication_expire_execution_barriers_for_test(&plugin);
    let mut expired_ctx = new_ctx("POST", "/api");
    assert!(
        matches!(
            plugin
                .before_proxy(&mut expired_ctx, &mut protected_headers)
                .await,
            PluginResult::Continue
        ),
        "evicted barrier did not expire at the protected completion deadline"
    );
}

#[tokio::test]
async fn terminal_serverless_remote_502_is_stored_at_response_commit() {
    use wiremock::matchers::method;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(502).set_body_string("executed-once"))
        .mount(&server)
        .await;
    let dedup = make_plugin(json!({}));
    let serverless = ServerlessFunction::new(
        &json!({
            "provider": "azure_functions",
            "function_url": format!("{}/mutate", server.uri()),
            "mode": "terminate"
        }),
        PluginHttpClient::default(),
    )
    .unwrap();

    let mut first_ctx = new_ctx("POST", "/api");
    let mut first_headers = HashMap::new();
    first_headers.insert("idempotency-key".to_string(), "side-effect-key".to_string());
    assert!(matches!(
        dedup.before_proxy(&mut first_ctx, &mut first_headers).await,
        PluginResult::Continue
    ));
    let (status, response_headers, body) =
        match finalized_egress(&serverless, &mut first_ctx, &mut first_headers).await {
            PluginResult::RejectBinary {
                status_code,
                headers,
                body,
            } => (status_code, headers, body),
            other => panic!("expected terminal serverless response, got {other:?}"),
        };
    assert_eq!(status, 502);
    assert!(dedup.requires_response_committed_hook());
    dedup
        .on_response_committed(&mut first_ctx, status, &response_headers, &body)
        .await;

    let mut retry_ctx = new_ctx("POST", "/api");
    let mut retry_headers = HashMap::new();
    retry_headers.insert("idempotency-key".to_string(), "side-effect-key".to_string());
    match dedup.before_proxy(&mut retry_ctx, &mut retry_headers).await {
        PluginResult::RejectBinary {
            status_code,
            body,
            headers,
        } => {
            assert_eq!(status_code, 502);
            assert_eq!(&body[..], b"executed-once");
            assert_eq!(
                headers.get("x-idempotent-replayed").map(String::as_str),
                Some("true")
            );
        }
        other => panic!("retry must replay without invoking again, got {other:?}"),
    }
    assert_eq!(server.received_requests().await.unwrap().len(), 1);
}

/// Assert an idempotency key is still owned by a durable, non-executable
/// completion after its in-flight lease was expired.
///
/// The refusal may be the fixed non-replayable barrier, or the policy-mismatch
/// refusal a stored completion produces when the live policy moved or cannot be
/// established. Both are 409 barriers; what must never happen is admission of a
/// fresh execution, or handing back the externally executed response as a replay.
fn assert_barrier_refusal(result: PluginResult, context: &str) {
    let (status_code, body) = match result {
        PluginResult::Reject {
            status_code, body, ..
        } => (status_code, Bytes::from(body)),
        PluginResult::RejectBinary {
            status_code, body, ..
        } => (status_code, body),
        other => panic!("{context}; got {other:?}"),
    };
    assert_eq!(status_code, 409, "{context}");
    let body = String::from_utf8_lossy(&body);
    assert!(
        !body.contains("charged-once"),
        "{context}; the externally executed representation must not be replayed: {body}"
    );
    assert!(
        !body.contains("already in progress"),
        "{context}; the barrier must be a durable completion, not a surviving in-flight lease: \
         {body}"
    );
}

/// Terminate-mode serverless invocation whose committed response is refused for
/// replay because the request straddled a response-side gate publication.
///
/// GHSA-8cr6-rw38-7j59: the function already ran, so giving up only the replay
/// would leave the raw `inflight_ttl_seconds` lease as the sole protection and
/// make the billable operation executable again the moment it expired. The
/// committed hook must convert that exact ownership into the durable
/// non-replayable 409 execution barrier instead.
#[tokio::test]
#[allow(clippy::await_holding_lock)] // `test_lock()` must span plugin awaits to serialize overlay state
async fn serverless_commit_straddling_a_policy_publication_publishes_a_durable_barrier() {
    use ferrum_edge::modes::mesh::config::{MeshRuntimeOverlay, RuntimeValue};
    use ferrum_edge::plugins::response_transformer::runtime_overlay;
    use wiremock::matchers::method;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let _guard = ferrum_edge::modes::mesh::runtime_overlay_consumers::test_lock();
    runtime_overlay::reset_for_test();

    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_string("charged-once"))
        .mount(&server)
        .await;
    let dedup = make_plugin(json!({}));
    let serverless = ServerlessFunction::new(
        &json!({
            "provider": "azure_functions",
            "function_url": format!("{}/mutate", server.uri()),
            "mode": "terminate"
        }),
        PluginHttpClient::default(),
    )
    .unwrap();

    let mut ctx = new_ctx("POST", "/api");
    let mut headers = HashMap::from([(
        "idempotency-key".to_string(),
        "straddled-side-effect".to_string(),
    )]);
    // Pins this request's response-policy stamp.
    assert!(matches!(
        dedup.before_proxy(&mut ctx, &mut headers).await,
        PluginResult::Continue
    ));
    let (status, response_headers, body) =
        match finalized_egress(&serverless, &mut ctx, &mut headers).await {
            PluginResult::RejectBinary {
                status_code,
                headers,
                body,
            } => (status_code, headers, body),
            other => panic!("expected terminal serverless response, got {other:?}"),
        };
    assert_eq!(status, 200);

    // A response-side gate publication lands after the function executed and
    // before the response is committed: the representation straddles it, so it
    // belongs to no provable policy and cannot be retained as a replay.
    let mut fields = HashMap::new();
    fields.insert(
        "ferrum.response_transformer.redaction.enabled".to_string(),
        RuntimeValue::Bool(true),
    );
    runtime_overlay::apply_overlay(&MeshRuntimeOverlay { fields });

    dedup
        .on_response_committed(&mut ctx, status, &response_headers, &body)
        .await;

    // The barrier must not be the bounded in-flight lease.
    request_deduplication_expire_inflight_entries_for_test(&dedup);

    let mut retry_ctx = new_ctx("POST", "/api");
    let mut retry_headers = HashMap::from([(
        "idempotency-key".to_string(),
        "straddled-side-effect".to_string(),
    )]);
    // A durable completion now owns the key. Whether it is refused as the fixed
    // non-replayable barrier or as a completion stored under a policy the retry
    // no longer shares, it is a 409 refusal rather than a fresh execution, and it
    // never hands back the real function response.
    assert_barrier_refusal(
        dedup.before_proxy(&mut retry_ctx, &mut retry_headers).await,
        "a committed serverless side effect whose response straddled a policy publication must \
         leave a durable execution barrier, not become executable again",
    );
    assert_eq!(
        server.received_requests().await.unwrap().len(),
        1,
        "the protected operation must not be re-executed"
    );
    runtime_overlay::reset_for_test();
}

/// Same barrier requirement for the other refusal shape: the effective static
/// response-presentation policy could not be established at all (no plugin-cache
/// view, or a `ResponsePresentationPolicy::Dynamic` plugin on the proxy), so the
/// provenance is incomplete and the committed response is not replayable.
#[tokio::test]
async fn serverless_commit_without_provable_policy_publishes_a_durable_barrier() {
    use wiremock::matchers::method;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_string("charged-once"))
        .mount(&server)
        .await;
    let dedup = make_plugin(json!({}));
    let serverless = ServerlessFunction::new(
        &json!({
            "provider": "azure_functions",
            "function_url": format!("{}/mutate", server.uri()),
            "mode": "terminate"
        }),
        PluginHttpClient::default(),
    )
    .unwrap();

    // Incomplete provenance: no effective presentation-policy digest.
    let mut ctx = policy_bound_ctx(None);
    let mut headers = HashMap::from([(
        "idempotency-key".to_string(),
        "dynamic-policy-side-effect".to_string(),
    )]);
    assert!(matches!(
        dedup.before_proxy(&mut ctx, &mut headers).await,
        PluginResult::Continue
    ));
    let (status, response_headers, body) =
        match finalized_egress(&serverless, &mut ctx, &mut headers).await {
            PluginResult::RejectBinary {
                status_code,
                headers,
                body,
            } => (status_code, headers, body),
            other => panic!("expected terminal serverless response, got {other:?}"),
        };

    dedup
        .on_response_committed(&mut ctx, status, &response_headers, &body)
        .await;
    request_deduplication_expire_inflight_entries_for_test(&dedup);

    let mut retry_ctx = policy_bound_ctx(None);
    let mut retry_headers = HashMap::from([(
        "idempotency-key".to_string(),
        "dynamic-policy-side-effect".to_string(),
    )]);
    assert_barrier_refusal(
        dedup.before_proxy(&mut retry_ctx, &mut retry_headers).await,
        "a committed serverless side effect with unprovable replay provenance must leave a \
         durable execution barrier",
    );
    assert_eq!(
        server.received_requests().await.unwrap().len(),
        1,
        "the protected operation must not be re-executed"
    );
}

/// The control for the two barrier tests above: a serverless response with
/// stable, complete policy provenance must still be published as an ordinary
/// replayable completion. Barrier conversion is the exception, not a blanket
/// downgrade of every externally executed response.
#[tokio::test]
#[allow(clippy::await_holding_lock)] // `test_lock()` must span plugin awaits to serialize overlay state
async fn serverless_commit_with_provable_policy_stays_replayable() {
    use ferrum_edge::plugins::response_transformer::runtime_overlay;
    use wiremock::matchers::method;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let _guard = ferrum_edge::modes::mesh::runtime_overlay_consumers::test_lock();
    runtime_overlay::reset_for_test();

    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_string("charged-once"))
        .mount(&server)
        .await;
    let dedup = make_plugin(json!({}));
    let serverless = ServerlessFunction::new(
        &json!({
            "provider": "azure_functions",
            "function_url": format!("{}/mutate", server.uri()),
            "mode": "terminate"
        }),
        PluginHttpClient::default(),
    )
    .unwrap();

    let mut ctx = new_ctx("POST", "/api");
    let mut headers = HashMap::from([(
        "idempotency-key".to_string(),
        "provable-side-effect".to_string(),
    )]);
    assert!(matches!(
        dedup.before_proxy(&mut ctx, &mut headers).await,
        PluginResult::Continue
    ));
    let (status, response_headers, body) =
        match finalized_egress(&serverless, &mut ctx, &mut headers).await {
            PluginResult::RejectBinary {
                status_code,
                headers,
                body,
            } => (status_code, headers, body),
            other => panic!("expected terminal serverless response, got {other:?}"),
        };

    // No policy publication between invocation and commit.
    dedup
        .on_response_committed(&mut ctx, status, &response_headers, &body)
        .await;
    request_deduplication_expire_inflight_entries_for_test(&dedup);

    let mut retry_ctx = new_ctx("POST", "/api");
    let mut retry_headers = HashMap::from([(
        "idempotency-key".to_string(),
        "provable-side-effect".to_string(),
    )]);
    match dedup.before_proxy(&mut retry_ctx, &mut retry_headers).await {
        PluginResult::RejectBinary {
            status_code,
            body,
            headers,
        } => {
            assert_eq!(status_code, 200);
            assert_eq!(&body[..], b"charged-once");
            assert_eq!(
                headers.get("x-idempotent-replayed").map(String::as_str),
                Some("true")
            );
        }
        other => panic!("a provable serverless completion must stay replayable, got {other:?}"),
    }
    assert_eq!(server.received_requests().await.unwrap().len(), 1);
    runtime_overlay::reset_for_test();
}

#[tokio::test]
async fn terminal_serverless_completion_is_owned_by_every_dedup_instance() {
    use wiremock::matchers::method;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(503).set_body_string("one-side-effect"))
        .mount(&server)
        .await;

    let first = make_plugin(json!({"header_name": "idempotency-key-a"}));
    let second = make_plugin(json!({"header_name": "idempotency-key-b"}));
    let serverless = ServerlessFunction::new(
        &json!({
            "provider": "azure_functions",
            "function_url": format!("{}/mutate", server.uri()),
            "mode": "terminate"
        }),
        PluginHttpClient::default(),
    )
    .unwrap();

    let mut ctx = new_ctx("POST", "/api");
    let mut headers = HashMap::from([
        ("idempotency-key-a".to_string(), "owner-a".to_string()),
        ("idempotency-key-b".to_string(), "owner-b".to_string()),
    ]);
    for plugin in [&first, &second] {
        assert!(matches!(
            plugin.before_proxy(&mut ctx, &mut headers).await,
            PluginResult::Continue
        ));
    }

    let (status, response_headers, body) =
        match finalized_egress(&serverless, &mut ctx, &mut headers).await {
            PluginResult::RejectBinary {
                status_code,
                headers,
                body,
            } => (status_code, headers, body),
            other => panic!("expected terminal serverless response, got {other:?}"),
        };
    assert_eq!(status, 503);

    // The ordinary final-body phase must leave both owners pending until the
    // settled committed terminal response is available.
    for plugin in [&first, &second] {
        assert!(matches!(
            plugin
                .on_final_response_body(&mut ctx, status, &response_headers, &body)
                .await,
            PluginResult::Continue
        ));
        assert_eq!(plugin.tracked_keys_count(), Some(1));
    }

    // Each committed hook consumes only its own provenance and publishes into
    // its own cache. The first hook must not clear the second owner's marker.
    first
        .on_response_committed(&mut ctx, status, &response_headers, &body)
        .await;
    second
        .on_response_committed(&mut ctx, status, &response_headers, &body)
        .await;

    for (plugin, header_name, key) in [
        (&first, "idempotency-key-a", "owner-a"),
        (&second, "idempotency-key-b", "owner-b"),
    ] {
        let mut retry_ctx = new_ctx("POST", "/api");
        let mut retry_headers = HashMap::from([
            ("idempotency-key-a".to_string(), "owner-a".to_string()),
            ("idempotency-key-b".to_string(), "owner-b".to_string()),
        ]);
        assert_eq!(
            retry_headers.get(header_name).map(String::as_str),
            Some(key)
        );
        match plugin
            .before_proxy(&mut retry_ctx, &mut retry_headers)
            .await
        {
            PluginResult::RejectBinary {
                status_code, body, ..
            } => {
                assert_eq!(status_code, 503);
                assert_eq!(&body[..], b"one-side-effect");
            }
            other => panic!("instance {header_name} did not retain its replay: {other:?}"),
        }
    }
    assert_eq!(server.received_requests().await.unwrap().len(), 1);
}

#[tokio::test]
async fn terminal_serverless_ambiguous_query_releases_every_dedup_owner() {
    let first = make_plugin(json!({}));
    let second = make_plugin(json!({}));
    let serverless = ServerlessFunction::new(
        &json!({
            "provider": "azure_functions",
            "function_url": "https://function.example/invoke",
            "mode": "terminate",
            "forward_query_params": true
        }),
        PluginHttpClient::default(),
    )
    .unwrap();
    let mut ctx = new_ctx("POST", "/api");
    ctx.set_raw_query_string("role=user&role=admin".to_string());
    let mut headers = HashMap::from([("idempotency-key".to_string(), "correctable".to_string())]);
    for dedup in [&first, &second] {
        assert!(matches!(
            dedup.before_proxy(&mut ctx, &mut headers).await,
            PluginResult::Continue
        ));
    }
    let (status, response_headers, body) =
        match finalized_egress(&serverless, &mut ctx, &mut headers).await {
            PluginResult::Reject {
                status_code,
                headers,
                body,
            } => (status_code, headers, body),
            other => panic!("ambiguous query must reject before invocation, got {other:?}"),
        };
    assert!(body.contains("duplicate_query_parameter"));
    for dedup in [&first, &second] {
        dedup
            .on_response_committed(&mut ctx, status, &response_headers, body.as_bytes())
            .await;
    }

    for dedup in [&first, &second] {
        let mut retry_ctx = new_ctx("POST", "/api");
        retry_ctx.set_raw_query_string("role=user&role=admin".to_string());
        let mut retry_headers =
            HashMap::from([("idempotency-key".to_string(), "correctable".to_string())]);
        assert!(matches!(
            dedup.before_proxy(&mut retry_ctx, &mut retry_headers).await,
            PluginResult::Continue
        ));
    }
}

#[tokio::test]
async fn terminal_serverless_encoded_body_releases_dedup_owner() {
    let dedup = make_plugin(json!({}));
    let serverless = ServerlessFunction::new(
        &json!({
            "provider": "azure_functions",
            "function_url": "https://function.example/invoke",
            "mode": "terminate",
            "forward_body": true
        }),
        PluginHttpClient::default(),
    )
    .unwrap();
    let compressed = gzip_body(b"opaque");
    let mut ctx = new_ctx("POST", "/api");
    ctx.request_body_bytes = Some(Bytes::copy_from_slice(&compressed));
    let mut headers = HashMap::from([
        ("idempotency-key".to_string(), "encoded".to_string()),
        ("content-encoding".to_string(), "gzip".to_string()),
        ("content-length".to_string(), compressed.len().to_string()),
    ]);
    assert!(matches!(
        dedup.before_proxy(&mut ctx, &mut headers).await,
        PluginResult::Continue
    ));
    let (status, response_headers, body) =
        match finalized_egress(&serverless, &mut ctx, &mut headers).await {
            PluginResult::Reject {
                status_code,
                headers,
                body,
            } => (status_code, headers, body),
            other => panic!("encoded body must reject before invocation, got {other:?}"),
        };
    assert!(body.contains("encoded_request_body_unsupported"));
    dedup
        .on_response_committed(&mut ctx, status, &response_headers, body.as_bytes())
        .await;

    let mut retry_ctx = new_ctx("POST", "/api");
    retry_ctx.request_body_bytes = Some(Bytes::from(compressed.clone()));
    let mut retry_headers = HashMap::from([
        ("idempotency-key".to_string(), "encoded".to_string()),
        ("content-encoding".to_string(), "gzip".to_string()),
        ("content-length".to_string(), compressed.len().to_string()),
    ]);
    assert!(matches!(
        dedup.before_proxy(&mut retry_ctx, &mut retry_headers).await,
        PluginResult::Continue
    ));
}

#[tokio::test]
async fn terminal_serverless_origin_encoded_marker_releases_dedup_owner() {
    // A header-only request_transformer that stripped Content-Encoding leaves
    // the live header map identity-clean, but the init-time marker preserves the
    // original non-identity coding, so the serverless egress still fails closed —
    // and because nothing external ran, the dedup in-flight lock is released.
    const ORIGIN_ENCODED_REQUEST_METADATA_KEY: &str = "ferrum:origin_encoded_request";

    let dedup = make_plugin(json!({}));
    let serverless = ServerlessFunction::new(
        &json!({
            "provider": "azure_functions",
            "function_url": "https://function.example/invoke",
            "mode": "terminate",
            "forward_body": true
        }),
        PluginHttpClient::default(),
    )
    .unwrap();
    let mut ctx = new_ctx("POST", "/api");
    ctx.request_body_bytes = Some(Bytes::from_static(b"opaque-compressed"));
    ctx.metadata.insert(
        ORIGIN_ENCODED_REQUEST_METADATA_KEY.to_string(),
        "true".to_string(),
    );
    // No content-encoding on the live map — the transformer removed it.
    let mut headers = HashMap::from([("idempotency-key".to_string(), "stripped".to_string())]);
    assert!(matches!(
        dedup.before_proxy(&mut ctx, &mut headers).await,
        PluginResult::Continue
    ));
    let (status, response_headers, body) =
        match finalized_egress(&serverless, &mut ctx, &mut headers).await {
            PluginResult::Reject {
                status_code,
                headers,
                body,
            } => (status_code, headers, body),
            other => panic!("stripped-but-original encoding must reject, got {other:?}"),
        };
    assert!(body.contains("encoded_request_body_unsupported"));
    dedup
        .on_response_committed(&mut ctx, status, &response_headers, body.as_bytes())
        .await;

    let mut retry_ctx = new_ctx("POST", "/api");
    retry_ctx.request_body_bytes = Some(Bytes::from_static(b"opaque-compressed"));
    let mut retry_headers =
        HashMap::from([("idempotency-key".to_string(), "stripped".to_string())]);
    assert!(matches!(
        dedup.before_proxy(&mut retry_ctx, &mut retry_headers).await,
        PluginResult::Continue
    ));
}

#[tokio::test]
async fn terminal_serverless_ambiguous_query_releases_dedup_owner() {
    // A governed query ambiguity (`+`) fails closed before any external call,
    // so the dedup in-flight lock is released for an identical retry.
    let dedup = make_plugin(json!({}));
    let serverless = ServerlessFunction::new(
        &json!({
            "provider": "azure_functions",
            "function_url": "https://function.example/invoke",
            "mode": "terminate",
            "forward_query_params": true
        }),
        PluginHttpClient::default(),
    )
    .unwrap();
    let mut ctx = new_ctx("POST", "/api");
    ctx.set_raw_query_string("name=alice+bob".to_string());
    let mut headers = HashMap::from([("idempotency-key".to_string(), "ambiguous".to_string())]);
    assert!(matches!(
        dedup.before_proxy(&mut ctx, &mut headers).await,
        PluginResult::Continue
    ));
    let (status, response_headers, body) =
        match finalized_egress(&serverless, &mut ctx, &mut headers).await {
            PluginResult::Reject {
                status_code,
                headers,
                body,
            } => (status_code, headers, body),
            other => panic!("ambiguous query must reject, got {other:?}"),
        };
    assert!(body.contains("ambiguous_query_encoding"));
    dedup
        .on_response_committed(&mut ctx, status, &response_headers, body.as_bytes())
        .await;

    let mut retry_ctx = new_ctx("POST", "/api");
    retry_ctx.set_raw_query_string("name=alice+bob".to_string());
    let mut retry_headers =
        HashMap::from([("idempotency-key".to_string(), "ambiguous".to_string())]);
    assert!(matches!(
        dedup.before_proxy(&mut retry_ctx, &mut retry_headers).await,
        PluginResult::Continue
    ));
}

#[tokio::test]
async fn terminal_serverless_pre_wire_invocation_failure_releases_dedup_owner() {
    // A proven pre-wire transport failure (connection refused: nothing reached
    // the function) must release the dedup in-flight lock rather than retain the
    // anticipatory side-effect marker, so an identical retry is not blocked/
    // replayed until inflight_ttl for an operation that never ran.
    let closed_addr = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap();
    // Listener dropped above — the port is now refused.

    let dedup = make_plugin(json!({}));
    let serverless = ServerlessFunction::new(
        &json!({
            "provider": "azure_functions",
            "function_url": format!("http://{closed_addr}/invoke"),
            "mode": "terminate",
            "timeout_ms": 2000
        }),
        PluginHttpClient::default(),
    )
    .unwrap();

    let mut ctx = new_ctx("POST", "/api");
    let mut headers = HashMap::from([("idempotency-key".to_string(), "pre-wire".to_string())]);
    assert!(matches!(
        dedup.before_proxy(&mut ctx, &mut headers).await,
        PluginResult::Continue
    ));
    let (status, response_headers, body) =
        match finalized_egress(&serverless, &mut ctx, &mut headers).await {
            PluginResult::Reject {
                status_code,
                headers,
                body,
            } => (status_code, headers, body),
            other => panic!("pre-wire failure must reject, got {other:?}"),
        };
    assert!(body.contains("invocation_failed"));
    dedup
        .on_response_committed(&mut ctx, status, &response_headers, body.as_bytes())
        .await;

    let mut retry_ctx = new_ctx("POST", "/api");
    let mut retry_headers =
        HashMap::from([("idempotency-key".to_string(), "pre-wire".to_string())]);
    assert!(matches!(
        dedup.before_proxy(&mut retry_ctx, &mut retry_headers).await,
        PluginResult::Continue
    ));
}

#[tokio::test]
async fn terminal_serverless_literal_ip_egress_denial_releases_dedup_owner() {
    let policy = BackendEgressPolicy::from_env(BackendAllowIps::Both, "", "", true).unwrap();
    let dedup = make_plugin(json!({}));
    let serverless = ServerlessFunction::new(
        &json!({
            "provider": "azure_functions",
            "function_url": "http://169.254.169.254/invoke",
            "mode": "terminate"
        }),
        PluginHttpClient::default_with_backend_allow_ips(policy),
    )
    .unwrap();

    let mut ctx = new_ctx("POST", "/api");
    let mut headers =
        HashMap::from([("idempotency-key".to_string(), "literal-denial".to_string())]);
    assert!(matches!(
        dedup.before_proxy(&mut ctx, &mut headers).await,
        PluginResult::Continue
    ));
    let (status, response_headers, body) =
        match finalized_egress(&serverless, &mut ctx, &mut headers).await {
            PluginResult::Reject {
                status_code,
                headers,
                body,
            } => (status_code, headers, body),
            other => panic!("literal-IP denial must reject pre-wire, got {other:?}"),
        };
    assert!(body.contains("invocation_failed"));
    dedup
        .on_response_committed(&mut ctx, status, &response_headers, body.as_bytes())
        .await;

    let mut retry_ctx = new_ctx("POST", "/api");
    let mut retry_headers =
        HashMap::from([("idempotency-key".to_string(), "literal-denial".to_string())]);
    assert!(matches!(
        dedup.before_proxy(&mut retry_ctx, &mut retry_headers).await,
        PluginResult::Continue
    ));
}

#[tokio::test]
async fn terminal_replay_survives_active_capacity_then_becomes_tombstone() {
    use wiremock::matchers::method;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_string("side-effect-result"))
        .mount(&server)
        .await;
    let dedup = make_plugin(json!({
        "max_entries": 1,
        "ttl_seconds": 300,
        "inflight_ttl_seconds": 300
    }));
    let serverless = ServerlessFunction::new(
        &json!({
            "provider": "azure_functions",
            "function_url": format!("{}/mutate", server.uri()),
            "mode": "terminate"
        }),
        PluginHttpClient::default(),
    )
    .unwrap();

    let mut first_ctx = new_ctx("POST", "/api");
    let mut first_headers =
        HashMap::from([("idempotency-key".to_string(), "terminal-a".to_string())]);
    assert!(matches!(
        dedup.before_proxy(&mut first_ctx, &mut first_headers).await,
        PluginResult::Continue
    ));
    let (status, response_headers, body) =
        match finalized_egress(&serverless, &mut first_ctx, &mut first_headers).await {
            PluginResult::RejectBinary {
                status_code,
                headers,
                body,
            } => (status_code, headers, body),
            other => panic!("expected terminal serverless response, got {other:?}"),
        };

    // A distinct active request saturates max_entries before the terminal
    // response publishes. The owned completion must remain replayable instead
    // of being selected as the only capacity-eviction candidate.
    let mut second_ctx = new_ctx("POST", "/other");
    let mut second_headers =
        HashMap::from([("idempotency-key".to_string(), "ordinary-b".to_string())]);
    assert!(matches!(
        dedup
            .before_proxy(&mut second_ctx, &mut second_headers)
            .await,
        PluginResult::Continue
    ));
    assert!(matches!(
        dedup
            .on_final_response_body(&mut first_ctx, status, &response_headers, &body)
            .await,
        PluginResult::Continue
    ));
    dedup
        .on_response_committed(&mut first_ctx, status, &response_headers, &body)
        .await;

    let mut replay_ctx = new_ctx("POST", "/api");
    let mut replay_headers =
        HashMap::from([("idempotency-key".to_string(), "terminal-a".to_string())]);
    match dedup
        .before_proxy(&mut replay_ctx, &mut replay_headers)
        .await
    {
        PluginResult::RejectBinary {
            status_code,
            headers,
            body,
        } => {
            assert_eq!(status_code, 200);
            assert_eq!(&body[..], b"side-effect-result");
            assert_eq!(
                headers.get("x-idempotent-replayed").map(String::as_str),
                Some("true")
            );
        }
        other => panic!("owned completion was not replayable under active pressure: {other:?}"),
    }

    // Once the other request completes, strict capacity can no longer retain
    // both responses. Evicting the protected terminal replay must leave an
    // fixed-size execution barrier with the completion's original retention,
    // so a later Redis outage/lock expiry cannot allow the external side effect
    // to execute again.
    complete_response(&dedup, &mut second_ctx).await;
    let mut tombstone_ctx = new_ctx("POST", "/api");
    let mut tombstone_headers =
        HashMap::from([("idempotency-key".to_string(), "terminal-a".to_string())]);
    assert!(matches!(
        dedup
            .before_proxy(&mut tombstone_ctx, &mut tombstone_headers)
            .await,
        PluginResult::Reject {
            status_code: 409,
            ..
        }
    ));
    assert_eq!(server.received_requests().await.unwrap().len(), 1);
}

#[tokio::test]
async fn oversized_terminal_serverless_response_retains_inflight_protection() {
    use wiremock::matchers::method;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(vec![b'x'; 128]))
        .mount(&server)
        .await;
    let dedup = make_plugin(json!({"max_entry_size_bytes": 32}));
    let serverless = ServerlessFunction::new(
        &json!({
            "provider": "azure_functions",
            "function_url": format!("{}/mutate", server.uri()),
            "mode": "terminate"
        }),
        PluginHttpClient::default(),
    )
    .unwrap();

    let mut first_ctx = new_ctx("POST", "/api");
    let mut first_headers =
        HashMap::from([("idempotency-key".to_string(), "oversized-key".to_string())]);
    assert!(matches!(
        dedup.before_proxy(&mut first_ctx, &mut first_headers).await,
        PluginResult::Continue
    ));
    let (status, response_headers, body) =
        match finalized_egress(&serverless, &mut first_ctx, &mut first_headers).await {
            PluginResult::RejectBinary {
                status_code,
                headers,
                body,
            } => (status_code, headers, body),
            other => panic!("expected oversized terminal response, got {other:?}"),
        };
    dedup
        .on_response_committed(&mut first_ctx, status, &response_headers, &body)
        .await;
    assert_eq!(dedup.tracked_keys_count(), Some(1));

    let mut retry_ctx = new_ctx("POST", "/api");
    let mut retry_headers =
        HashMap::from([("idempotency-key".to_string(), "oversized-key".to_string())]);
    assert!(matches!(
        dedup.before_proxy(&mut retry_ctx, &mut retry_headers).await,
        PluginResult::Reject {
            status_code: 409,
            ..
        }
    ));
    assert_eq!(server.received_requests().await.unwrap().len(), 1);
}

#[tokio::test]
async fn oversized_buffered_fallback_retains_uncertain_serverless_protection() {
    use wiremock::matchers::method;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(600).set_body_string("invalid status"))
        .mount(&server)
        .await;
    let dedup = make_plugin(json!({"max_entry_size_bytes": 32}));
    let serverless = ServerlessFunction::new(
        &json!({
            "provider": "azure_functions",
            "function_url": format!("{}/mutate", server.uri()),
            "mode": "terminate",
            "on_error": "continue"
        }),
        PluginHttpClient::default(),
    )
    .unwrap();

    let mut first_ctx = new_ctx("POST", "/api");
    let mut first_headers = HashMap::from([(
        "idempotency-key".to_string(),
        "oversized-fallback-key".to_string(),
    )]);
    assert!(matches!(
        dedup.before_proxy(&mut first_ctx, &mut first_headers).await,
        PluginResult::Continue
    ));
    assert!(matches!(
        finalized_egress(&serverless, &mut first_ctx, &mut first_headers).await,
        PluginResult::Continue
    ));

    let backend_body = vec![b'y'; 128];
    assert!(matches!(
        dedup
            .on_final_response_body(&mut first_ctx, 200, &HashMap::new(), &backend_body)
            .await,
        PluginResult::Continue
    ));
    dedup
        .on_response_committed(&mut first_ctx, 200, &HashMap::new(), &backend_body)
        .await;
    assert_eq!(dedup.tracked_keys_count(), Some(1));

    let mut retry_ctx = new_ctx("POST", "/api");
    let mut retry_headers = HashMap::from([(
        "idempotency-key".to_string(),
        "oversized-fallback-key".to_string(),
    )]);
    assert!(matches!(
        dedup.before_proxy(&mut retry_ctx, &mut retry_headers).await,
        PluginResult::Reject {
            status_code: 409,
            ..
        }
    ));
    assert_eq!(server.received_requests().await.unwrap().len(), 1);
}

#[tokio::test]
async fn multiple_instances_release_only_their_own_inflight_ownership() {
    let first = make_plugin(json!({"header_name": "Idempotency-Key"}));
    let second = make_plugin(json!({"header_name": "Idempotency-Key"}));
    let mut ctx = body_ctx("POST", "/api", br#"{"value":1}"#);
    let mut headers = keyed_headers("shared-key", "example.test", 11);

    assert!(matches!(
        first.before_proxy(&mut ctx, &mut headers).await,
        PluginResult::Continue
    ));
    assert!(matches!(
        second.before_proxy(&mut ctx, &mut headers).await,
        PluginResult::Continue
    ));

    ctx.metadata.insert(
        "ferrum:release_dedup_inflight_on_commit".to_string(),
        "true".to_string(),
    );
    first
        .on_response_committed(&mut ctx, 503, &HashMap::new(), b"rejected")
        .await;

    let mut first_retry_ctx = body_ctx("POST", "/api", br#"{"value":1}"#);
    let mut first_retry_headers = keyed_headers("shared-key", "example.test", 11);
    assert!(matches!(
        first
            .before_proxy(&mut first_retry_ctx, &mut first_retry_headers)
            .await,
        PluginResult::Continue
    ));

    let mut second_retry_ctx = body_ctx("POST", "/api", br#"{"value":1}"#);
    let mut second_retry_headers = keyed_headers("shared-key", "example.test", 11);
    assert!(matches!(
        second
            .before_proxy(&mut second_retry_ctx, &mut second_retry_headers)
            .await,
        PluginResult::Reject {
            status_code: 409,
            ..
        }
    ));

    second
        .on_response_committed(&mut ctx, 503, &HashMap::new(), b"rejected")
        .await;
}

/// Two proxy-scoped instances with distinct headers must each complete and
/// release their own ownership. Before #2378, shared request-metadata slots
/// meant the earlier instance retained a stale in-flight marker after a
/// successful response.
async fn two_instances_buffered_completion_releases_independently(
    first: RequestDeduplication,
    second: RequestDeduplication,
) {
    let body = br#"{"order":1}"#;
    let mut ctx = body_ctx("POST", "/orders", body);
    let mut headers = dual_keyed_headers("key-a", "key-b", "orders.example", body.len());
    mark_both_fresh(&first, &second, &mut ctx, &mut headers).await;
    assert_eq!(first.tracked_keys_count(), Some(1));
    assert_eq!(second.tracked_keys_count(), Some(1));

    complete_response(&first, &mut ctx).await;
    assert!(
        request_identity(&first, &ctx).is_none(),
        "first instance must consume only its own completion state"
    );
    assert!(
        request_identity(&second, &ctx).is_some(),
        "second instance must retain its ownership after the first completes"
    );
    complete_response(&second, &mut ctx).await;
    assert!(request_identity(&second, &ctx).is_none());
    assert_eq!(first.tracked_keys_count(), Some(1));
    assert_eq!(second.tracked_keys_count(), Some(1));

    let mut retry_a = body_ctx("POST", "/orders", body);
    let mut retry_a_headers = dual_keyed_headers("key-a", "key-b", "orders.example", body.len());
    match first.before_proxy(&mut retry_a, &mut retry_a_headers).await {
        PluginResult::RejectBinary {
            status_code,
            headers: response_headers,
            ..
        } => {
            assert_eq!(status_code, 201);
            assert_eq!(
                response_headers
                    .get("x-idempotent-replayed")
                    .map(String::as_str),
                Some("true"),
                "repeated key A must observe completed replay, not a stale 409"
            );
        }
        other => panic!("expected completed replay for key A, got {other:?}"),
    }

    let mut retry_b = body_ctx("POST", "/orders", body);
    let mut retry_b_headers = dual_keyed_headers("key-a", "key-b", "orders.example", body.len());
    match second
        .before_proxy(&mut retry_b, &mut retry_b_headers)
        .await
    {
        PluginResult::RejectBinary {
            status_code,
            headers: response_headers,
            ..
        } => {
            assert_eq!(status_code, 201);
            assert_eq!(
                response_headers
                    .get("x-idempotent-replayed")
                    .map(String::as_str),
                Some("true"),
                "repeated key B must observe completed replay, not a stale 409"
            );
        }
        other => panic!("expected completed replay for key B, got {other:?}"),
    }
}

#[tokio::test]
async fn two_instances_distinct_headers_local_buffered_completion_releases_independently() {
    two_instances_buffered_completion_releases_independently(
        make_local_sibling("Idempotency-Key", "dedup-a"),
        make_local_sibling("X-Operation-Key", "dedup-b"),
    )
    .await;
}

#[tokio::test]
async fn two_instances_distinct_headers_redis_prefixed_buffered_completion_releases_independently()
{
    two_instances_buffered_completion_releases_independently(
        make_redis_sibling("Idempotency-Key", "dedup-a", "orders:dedup:a"),
        make_redis_sibling("X-Operation-Key", "dedup-b", "orders:dedup:b"),
    )
    .await;
}

async fn two_instances_streamed_completion_releases_independently(
    first: RequestDeduplication,
    second: RequestDeduplication,
) {
    let mut ctx = new_ctx("POST", "/orders");
    let mut headers = dual_keyed_headers("stream-a", "stream-b", "orders.example", 0);
    mark_both_fresh(&first, &second, &mut ctx, &mut headers).await;
    assert!(first.should_buffer_response_body(&ctx));
    assert!(second.should_buffer_response_body(&ctx));
    assert!(!first.should_buffer_response_body_for_content_type(
        &ctx,
        Some("text/event-stream"),
        200,
        &HashMap::new()
    ));
    assert!(!second.should_buffer_response_body_for_content_type(
        &ctx,
        Some("text/event-stream"),
        200,
        &HashMap::new()
    ));

    first
        .on_response_stream_terminated(&mut ctx, 200, &BodyOutcome::success(16))
        .await;
    assert!(
        request_identity(&first, &ctx).is_none(),
        "clean stream end must release only the first instance's ownership"
    );
    assert!(request_identity(&second, &ctx).is_some());
    assert_eq!(first.tracked_keys_count(), Some(0));
    assert_eq!(second.tracked_keys_count(), Some(1));

    second
        .on_response_stream_terminated(&mut ctx, 200, &BodyOutcome::success(16))
        .await;
    assert!(request_identity(&second, &ctx).is_none());
    assert_eq!(second.tracked_keys_count(), Some(0));

    let mut retry_a = new_ctx("POST", "/orders");
    let mut retry_a_headers = dual_keyed_headers("stream-a", "stream-b", "orders.example", 0);
    assert!(
        matches!(
            first.before_proxy(&mut retry_a, &mut retry_a_headers).await,
            PluginResult::Continue
        ),
        "clean streamed completion must not leave a stale in-flight conflict for key A"
    );

    let mut retry_b = new_ctx("POST", "/orders");
    let mut retry_b_headers = dual_keyed_headers("stream-a", "stream-b", "orders.example", 0);
    assert!(
        matches!(
            second
                .before_proxy(&mut retry_b, &mut retry_b_headers)
                .await,
            PluginResult::Continue
        ),
        "clean streamed completion must not leave a stale in-flight conflict for key B"
    );
}

#[tokio::test]
async fn two_instances_distinct_headers_local_streamed_completion_releases_independently() {
    two_instances_streamed_completion_releases_independently(
        make_local_sibling("Idempotency-Key", "dedup-a"),
        make_local_sibling("X-Operation-Key", "dedup-b"),
    )
    .await;
}

#[tokio::test]
async fn two_instances_distinct_headers_redis_prefixed_streamed_completion_releases_independently()
{
    two_instances_streamed_completion_releases_independently(
        make_redis_sibling("Idempotency-Key", "dedup-a", "orders:dedup:a"),
        make_redis_sibling("X-Operation-Key", "dedup-b", "orders:dedup:b"),
    )
    .await;
}

async fn two_instances_interrupted_stream_retains_independently(
    first: RequestDeduplication,
    second: RequestDeduplication,
) {
    let mut ctx = new_ctx("POST", "/orders");
    let mut headers = dual_keyed_headers("hold-a", "hold-b", "orders.example", 0);
    mark_both_fresh(&first, &second, &mut ctx, &mut headers).await;

    first
        .on_response_stream_terminated(&mut ctx, 200, &BodyOutcome::client_disconnect(8))
        .await;
    assert!(
        request_identity(&first, &ctx).is_some(),
        "interrupted stream must retain first-instance ownership until TTL"
    );
    assert!(
        request_identity(&second, &ctx).is_some(),
        "first instance's interrupted stream must not consume the second instance's state"
    );
    assert_eq!(first.tracked_keys_count(), Some(1));
    assert_eq!(second.tracked_keys_count(), Some(1));

    second
        .on_response_stream_terminated(&mut ctx, 200, &BodyOutcome::client_disconnect(8))
        .await;
    assert!(request_identity(&second, &ctx).is_some());
    assert_eq!(second.tracked_keys_count(), Some(1));

    let mut retry_a = new_ctx("POST", "/orders");
    let mut retry_a_headers = dual_keyed_headers("hold-a", "hold-b", "orders.example", 0);
    assert!(
        matches!(
            first.before_proxy(&mut retry_a, &mut retry_a_headers).await,
            PluginResult::Reject {
                status_code: 409,
                ..
            }
        ),
        "interrupted stream for key A must keep blocking retries until TTL"
    );

    let mut retry_b = new_ctx("POST", "/orders");
    let mut retry_b_headers = dual_keyed_headers("hold-a", "hold-b", "orders.example", 0);
    assert!(
        matches!(
            second
                .before_proxy(&mut retry_b, &mut retry_b_headers)
                .await,
            PluginResult::Reject {
                status_code: 409,
                ..
            }
        ),
        "interrupted stream for key B must keep blocking retries until TTL"
    );
}

#[tokio::test]
async fn two_instances_distinct_headers_local_interrupted_stream_retains_independently() {
    two_instances_interrupted_stream_retains_independently(
        make_local_sibling("Idempotency-Key", "dedup-a"),
        make_local_sibling("X-Operation-Key", "dedup-b"),
    )
    .await;
}

#[tokio::test]
async fn two_instances_distinct_headers_redis_prefixed_interrupted_stream_retains_independently() {
    two_instances_interrupted_stream_retains_independently(
        make_redis_sibling("Idempotency-Key", "dedup-a", "orders:dedup:a"),
        make_redis_sibling("X-Operation-Key", "dedup-b", "orders:dedup:b"),
    )
    .await;
}

#[tokio::test]
async fn test_concurrent_duplicate_returns_conflict() {
    let config = json!({});
    let plugin = make_plugin(config);

    // First request marks key as in-flight
    let mut ctx1 = new_ctx("POST", "/api");
    let mut headers1 = HashMap::new();
    headers1.insert("idempotency-key".to_string(), "inflight-key".to_string());

    let result = plugin.before_proxy(&mut ctx1, &mut headers1).await;
    assert!(matches!(result, PluginResult::Continue));

    // Second request with same key while first is still in-flight
    let mut ctx2 = new_ctx("POST", "/api");
    let mut headers2 = HashMap::new();
    headers2.insert("idempotency-key".to_string(), "inflight-key".to_string());

    let result = plugin.before_proxy(&mut ctx2, &mut headers2).await;
    match result {
        PluginResult::Reject {
            status_code, body, ..
        } => {
            assert_eq!(status_code, 409);
            assert!(body.contains("already in progress"));
        }
        _ => panic!("Expected 409 Conflict"),
    }
}

#[tokio::test]
async fn test_concurrent_first_requests_only_one_reaches_backend() {
    let plugin = Arc::new(make_plugin(json!({})));
    let barrier = Arc::new(Barrier::new(16));
    let mut handles = Vec::new();

    for _ in 0..16 {
        let plugin = Arc::clone(&plugin);
        let barrier = Arc::clone(&barrier);
        handles.push(tokio::spawn(async move {
            let mut ctx = new_ctx("POST", "/api");
            let mut headers = HashMap::new();
            headers.insert("idempotency-key".to_string(), "race-key".to_string());

            barrier.wait().await;
            plugin.before_proxy(&mut ctx, &mut headers).await
        }));
    }

    let mut continues = 0;
    let mut conflicts = 0;
    for handle in handles {
        match handle.await.unwrap() {
            PluginResult::Continue => continues += 1,
            PluginResult::Reject {
                status_code: 409, ..
            } => conflicts += 1,
            other => panic!("unexpected result: {other:?}"),
        }
    }

    assert_eq!(continues, 1);
    assert_eq!(conflicts, 15);
}

#[tokio::test]
async fn test_different_keys_independent() {
    let config = json!({});
    let plugin = make_plugin(config);

    // First request
    let mut ctx1 = new_ctx("POST", "/api");
    let mut headers1 = HashMap::new();
    headers1.insert("idempotency-key".to_string(), "key-a".to_string());

    let result = plugin.before_proxy(&mut ctx1, &mut headers1).await;
    assert!(matches!(result, PluginResult::Continue));

    // Different key — should also pass
    let mut ctx2 = new_ctx("POST", "/api");
    let mut headers2 = HashMap::new();
    headers2.insert("idempotency-key".to_string(), "key-b".to_string());

    let result = plugin.before_proxy(&mut ctx2, &mut headers2).await;
    assert!(matches!(result, PluginResult::Continue));
}

#[tokio::test]
async fn test_put_method_deduplicates() {
    let config = json!({});
    let plugin = make_plugin(config);

    let mut ctx = new_ctx("PUT", "/api");
    let mut headers = HashMap::new();
    headers.insert("idempotency-key".to_string(), "put-key".to_string());

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
    assert!(request_identity(&plugin, &ctx).is_some());
}

#[tokio::test]
async fn test_custom_applicable_methods() {
    let config = json!({
        "applicable_methods": ["DELETE"]
    });
    let plugin = make_plugin(config);

    // POST should pass through (not in applicable_methods)
    let mut ctx = new_ctx("POST", "/api");
    let mut headers = HashMap::new();
    headers.insert("idempotency-key".to_string(), "key-1".to_string());

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
    assert!(request_identity(&plugin, &ctx).is_none());

    // DELETE should be deduplication-eligible
    let mut ctx2 = new_ctx("DELETE", "/api");
    let mut headers2 = HashMap::new();
    headers2.insert("idempotency-key".to_string(), "key-2".to_string());

    let result = plugin.before_proxy(&mut ctx2, &mut headers2).await;
    assert!(matches!(result, PluginResult::Continue));
    assert!(request_identity(&plugin, &ctx2).is_some());
}

#[test]
fn test_requires_response_body_buffering() {
    let config = json!({});
    let plugin = make_plugin(config);
    assert!(plugin.requires_response_body_buffering());
}

#[tokio::test]
async fn test_response_buffering_only_for_fresh_dedup_keys() {
    let config = json!({});
    let plugin = make_plugin(config);

    let mut get_ctx = new_ctx("GET", "/api");
    let mut get_headers = HashMap::new();
    get_headers.insert("idempotency-key".to_string(), "get-key".to_string());
    let result = plugin.before_proxy(&mut get_ctx, &mut get_headers).await;
    assert!(matches!(result, PluginResult::Continue));
    assert!(!plugin.should_buffer_response_body(&get_ctx));

    let mut keyless_post_ctx = new_ctx("POST", "/api");
    let mut keyless_post_headers = HashMap::new();
    let result = plugin
        .before_proxy(&mut keyless_post_ctx, &mut keyless_post_headers)
        .await;
    assert!(matches!(result, PluginResult::Continue));
    assert!(!plugin.should_buffer_response_body(&keyless_post_ctx));

    let mut keyed_post_ctx = new_ctx("POST", "/api");
    let mut keyed_post_headers = HashMap::new();
    keyed_post_headers.insert("idempotency-key".to_string(), "post-key".to_string());
    let result = plugin
        .before_proxy(&mut keyed_post_ctx, &mut keyed_post_headers)
        .await;
    assert!(matches!(result, PluginResult::Continue));
    assert!(plugin.should_buffer_response_body(&keyed_post_ctx));
}

#[tokio::test]
async fn test_response_buffering_releases_event_stream_content_type() {
    let config = json!({});
    let plugin = make_plugin(config);

    let mut ctx = new_ctx("POST", "/api");
    let mut headers = HashMap::new();
    headers.insert("idempotency-key".to_string(), "stream-key".to_string());
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));

    assert!(plugin.should_buffer_response_body_for_content_type(
        &ctx,
        Some("application/json"),
        200,
        &HashMap::new()
    ));
    assert!(!plugin.should_buffer_response_body_for_content_type(
        &ctx,
        Some("text/event-stream"),
        200,
        &HashMap::new()
    ));
}

/// A keyed request whose response is streamed as `text/event-stream` is handed
/// to the client incrementally, so `on_final_response_body` (which transitions
/// the `InFlight` marker to a cached `Completed` entry) never runs. On a clean
/// stream completion the marker stays in-flight for the lifetime of the stream,
/// then `on_response_stream_terminated` releases it without storing a replay
/// body — so the next matching key re-executes instead of eating a stale 409
/// for the rest of `inflight_ttl_seconds`.
#[tokio::test]
async fn test_streamed_event_stream_releases_inflight_marker_on_clean_completion() {
    let config = json!({});
    let plugin = make_plugin(config);

    let mut ctx = new_ctx("POST", "/api");
    let mut headers = HashMap::new();
    headers.insert("idempotency-key".to_string(), "sse-key".to_string());
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
    // The fresh key is marked in-flight and stays that way for the stream.
    assert_eq!(plugin.tracked_keys_count(), Some(1));
    assert!(request_identity(&plugin, &ctx).is_some());

    // The SSE response is streamed (not buffered), confirmed by the content-type
    // refinement declining to buffer it.
    assert!(!plugin.should_buffer_response_body_for_content_type(
        &ctx,
        Some("text/event-stream"),
        200,
        &HashMap::new()
    ));

    // A duplicate request arriving while the stream is still active must be
    // rejected with 409 — the in-flight lock is exactly the protection this
    // plugin promises for the still-running request.
    let mut dup_ctx = new_ctx("POST", "/api");
    let mut dup_headers = HashMap::new();
    dup_headers.insert("idempotency-key".to_string(), "sse-key".to_string());
    let result = plugin.before_proxy(&mut dup_ctx, &mut dup_headers).await;
    assert!(
        matches!(
            result,
            PluginResult::Reject {
                status_code: 409,
                ..
            }
        ),
        "duplicate during an active streamed SSE response must 409, got {result:?}"
    );

    plugin
        .on_response_stream_terminated(&mut ctx, 200, &BodyOutcome::success(32))
        .await;
    assert_eq!(
        plugin.tracked_keys_count(),
        Some(0),
        "a cleanly completed streamed SSE response must release the in-flight marker instead of waiting for TTL"
    );

    let mut after_ctx = new_ctx("POST", "/api");
    let mut after_headers = HashMap::new();
    after_headers.insert("idempotency-key".to_string(), "sse-key".to_string());
    let result = plugin
        .before_proxy(&mut after_ctx, &mut after_headers)
        .await;
    assert!(
        matches!(result, PluginResult::Continue),
        "duplicate after a cleanly completed streamed SSE response should re-execute, not get stale 409 or cached replay; got {result:?}"
    );
}

/// A terminate-mode function can execute externally and then fail before a
/// usable response is available. With `on_error: continue`, a streamed backend
/// response has no replay body to publish, so even clean stream completion must
/// retain the in-flight marker until TTL rather than re-executing the uncertain
/// function side effect on an immediate retry.
#[tokio::test]
async fn test_streamed_fallback_retains_marker_after_uncertain_serverless_side_effect() {
    use wiremock::matchers::method;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(600).set_body_string("invalid status"))
        .mount(&server)
        .await;
    let dedup = make_plugin(json!({}));
    let serverless = ServerlessFunction::new(
        &json!({
            "provider": "azure_functions",
            "function_url": format!("{}/mutate", server.uri()),
            "mode": "terminate",
            "on_error": "continue"
        }),
        PluginHttpClient::default(),
    )
    .unwrap();

    let mut ctx = new_ctx("POST", "/api");
    let mut headers = HashMap::new();
    headers.insert(
        "idempotency-key".to_string(),
        "serverless-stream-key".to_string(),
    );
    assert!(matches!(
        dedup.before_proxy(&mut ctx, &mut headers).await,
        PluginResult::Continue
    ));
    assert!(matches!(
        finalized_egress(&serverless, &mut ctx, &mut headers).await,
        PluginResult::Continue
    ));

    dedup
        .on_response_stream_terminated(&mut ctx, 200, &BodyOutcome::success(32))
        .await;
    assert_eq!(
        dedup.tracked_keys_count(),
        Some(1),
        "an uncertain serverless side effect must retain a completion for the streamed fallback"
    );

    let mut retry_ctx = new_ctx("POST", "/api");
    let mut retry_headers = HashMap::new();
    retry_headers.insert(
        "idempotency-key".to_string(),
        "serverless-stream-key".to_string(),
    );
    // GHSA-8cr6-rw38-7j59: the streamed fallback publishes a durable
    // non-replayable tombstone rather than a bare in-flight marker, so the
    // retry is refused for the completed-response TTL instead of becoming
    // executable again the moment `inflight_ttl_seconds` elapses.
    match dedup.before_proxy(&mut retry_ctx, &mut retry_headers).await {
        PluginResult::RejectBinary {
            status_code, body, ..
        } => {
            assert_eq!(status_code, 409);
            assert!(
                String::from_utf8_lossy(&body).contains("cannot be replayed safely"),
                "unexpected tombstone body"
            );
        }
        other => panic!("expected a non-replayable completion tombstone, got {other:?}"),
    }
    assert_eq!(server.received_requests().await.unwrap().len(), 1);
}

/// GHSA-8cr6-rw38-7j59: an interrupted stream (client disconnect) behind a
/// terminate-mode serverless invocation must also leave a durable completion,
/// not merely an in-flight marker that expires into a fresh execution.
#[tokio::test]
async fn interrupted_stream_after_serverless_side_effect_publishes_durable_tombstone() {
    use wiremock::matchers::method;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(600).set_body_string("invalid status"))
        .mount(&server)
        .await;
    let dedup = make_plugin(json!({}));
    let serverless = ServerlessFunction::new(
        &json!({
            "provider": "azure_functions",
            "function_url": format!("{}/mutate", server.uri()),
            "mode": "terminate",
            "on_error": "continue"
        }),
        PluginHttpClient::default(),
    )
    .unwrap();

    let mut ctx = new_ctx("POST", "/api");
    let mut headers = HashMap::new();
    headers.insert(
        "idempotency-key".to_string(),
        "serverless-interrupted-key".to_string(),
    );
    assert!(matches!(
        dedup.before_proxy(&mut ctx, &mut headers).await,
        PluginResult::Continue
    ));
    assert!(matches!(
        finalized_egress(&serverless, &mut ctx, &mut headers).await,
        PluginResult::Continue
    ));

    dedup
        .on_response_stream_terminated(&mut ctx, 200, &BodyOutcome::client_disconnect(8))
        .await;

    // The completion outlives the in-flight lease: expiring in-flight markers
    // must not resurrect an executable key.
    request_deduplication_expire_inflight_entries_for_test(&dedup);

    let mut retry_ctx = new_ctx("POST", "/api");
    let mut retry_headers = HashMap::new();
    retry_headers.insert(
        "idempotency-key".to_string(),
        "serverless-interrupted-key".to_string(),
    );
    match dedup.before_proxy(&mut retry_ctx, &mut retry_headers).await {
        PluginResult::RejectBinary { status_code, .. } => assert_eq!(status_code, 409),
        other => panic!("expected a non-replayable completion tombstone, got {other:?}"),
    }
    assert_eq!(server.received_requests().await.unwrap().len(), 1);
}

/// An interrupted streamed SSE response — client disconnect or mid-stream error,
/// i.e. `!body_completed` — delivered no full response to the client and is the
/// case most likely to be retried with the same idempotency key. Releasing the
/// marker there would let that retry re-execute a side-effecting backend
/// operation with no replay/tombstone protection, so the marker is retained
/// until `inflight_ttl_seconds` and duplicates keep receiving 409.
#[tokio::test]
async fn test_streamed_event_stream_retains_inflight_marker_on_client_disconnect() {
    let config = json!({});
    let plugin = make_plugin(config);

    let mut ctx = new_ctx("POST", "/api");
    let mut headers = HashMap::new();
    headers.insert("idempotency-key".to_string(), "sse-key".to_string());
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
    assert_eq!(plugin.tracked_keys_count(), Some(1));

    // The client stopped consuming mid-stream (Drop safety net): the body never
    // completed, so the marker must survive to block an immediate retry.
    plugin
        .on_response_stream_terminated(&mut ctx, 200, &BodyOutcome::client_disconnect(32))
        .await;
    assert_eq!(
        plugin.tracked_keys_count(),
        Some(1),
        "an interrupted streamed SSE response must keep the in-flight marker until TTL so a same-key retry cannot re-execute"
    );

    let mut after_ctx = new_ctx("POST", "/api");
    let mut after_headers = HashMap::new();
    after_headers.insert("idempotency-key".to_string(), "sse-key".to_string());
    let result = plugin
        .before_proxy(&mut after_ctx, &mut after_headers)
        .await;
    assert!(
        matches!(
            result,
            PluginResult::Reject {
                status_code: 409,
                ..
            }
        ),
        "duplicate after an interrupted streamed SSE response must stay blocked until TTL, got {result:?}"
    );
}

#[tokio::test]
async fn test_stale_stream_end_does_not_clear_successor_inflight_marker() {
    let plugin = make_plugin(json!({
        "inflight_ttl_seconds": 1
    }));

    let mut original_ctx = new_ctx("POST", "/api");
    let mut original_headers = HashMap::new();
    original_headers.insert("idempotency-key".to_string(), "sse-key".to_string());
    let result = plugin
        .before_proxy(&mut original_ctx, &mut original_headers)
        .await;
    assert!(matches!(result, PluginResult::Continue));

    request_deduplication_expire_inflight_entries_for_test(&plugin);

    let mut successor_ctx = new_ctx("POST", "/api");
    let mut successor_headers = HashMap::new();
    successor_headers.insert("idempotency-key".to_string(), "sse-key".to_string());
    let result = plugin
        .before_proxy(&mut successor_ctx, &mut successor_headers)
        .await;
    assert!(
        matches!(result, PluginResult::Continue),
        "successor should replace the stale in-flight marker, got {result:?}"
    );
    assert_eq!(plugin.tracked_keys_count(), Some(1));

    plugin
        .on_response_stream_terminated(&mut original_ctx, 200, &BodyOutcome::success(32))
        .await;

    let mut duplicate_ctx = new_ctx("POST", "/api");
    let mut duplicate_headers = HashMap::new();
    duplicate_headers.insert("idempotency-key".to_string(), "sse-key".to_string());
    let result = plugin
        .before_proxy(&mut duplicate_ctx, &mut duplicate_headers)
        .await;
    assert!(
        matches!(
            result,
            PluginResult::Reject {
                status_code: 409,
                ..
            }
        ),
        "late stream-end from the stale owner must not clear the successor marker; got {result:?}"
    );

    plugin
        .on_response_stream_terminated(&mut successor_ctx, 200, &BodyOutcome::success(32))
        .await;
    assert_eq!(
        plugin.tracked_keys_count(),
        Some(0),
        "the successor's own clean completion releases its marker via token-matched removal"
    );
}

/// A buffered (non-SSE) keyed response keeps the marker in-flight through the
/// header phase and transitions it to a cached `Completed` entry via
/// `on_final_response_body`, which only runs on the buffered path.
#[tokio::test]
async fn test_buffered_response_transitions_inflight_to_completed() {
    let config = json!({});
    let plugin = make_plugin(config);

    let mut ctx = new_ctx("POST", "/api");
    let mut headers = HashMap::new();
    headers.insert("idempotency-key".to_string(), "json-key".to_string());
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
    assert_eq!(plugin.tracked_keys_count(), Some(1));
    assert!(request_identity(&plugin, &ctx).is_some());

    // A JSON response is buffered (the content-type refinement still votes to
    // buffer), so `on_final_response_body` runs and caches it.
    assert!(plugin.should_buffer_response_body_for_content_type(
        &ctx,
        Some("application/json"),
        200,
        &HashMap::new()
    ));
    let response_headers = HashMap::new();
    let result = plugin
        .on_final_response_body(&mut ctx, 200, &response_headers, b"{}")
        .await;
    assert!(matches!(result, PluginResult::Continue));
    assert_eq!(plugin.tracked_keys_count(), Some(1));
}

#[test]
fn test_tracked_keys_count() {
    let config = json!({});
    let plugin = make_plugin(config);
    assert_eq!(plugin.tracked_keys_count(), Some(0));
}

#[tokio::test]
async fn test_completion_clears_inflight_then_replays() {
    // Verify normal lifecycle: in-flight → completed → replay works correctly
    // and does not return 409 Conflict after the response is captured.
    let config = json!({});
    let plugin = make_plugin(config);

    // First request marks key as in-flight
    let mut ctx1 = new_ctx("POST", "/api");
    let mut headers1 = HashMap::new();
    headers1.insert("idempotency-key".to_string(), "lifecycle-key".to_string());
    let result = plugin.before_proxy(&mut ctx1, &mut headers1).await;
    assert!(matches!(result, PluginResult::Continue));

    // Capture response — converts InFlight → Completed
    let response_headers = HashMap::new();
    let body = b"completion body";
    let _ = plugin
        .on_final_response_body(&mut ctx1, 200, &response_headers, body)
        .await;

    // Now duplicate request should REPLAY, not get 409 Conflict
    let mut ctx2 = new_ctx("POST", "/api");
    let mut headers2 = HashMap::new();
    headers2.insert("idempotency-key".to_string(), "lifecycle-key".to_string());
    let result = plugin.before_proxy(&mut ctx2, &mut headers2).await;
    match result {
        PluginResult::RejectBinary {
            status_code, body, ..
        } => {
            assert_eq!(status_code, 200);
            assert_eq!(&body[..], b"completion body");
        }
        _ => panic!(
            "Expected RejectBinary replay after completion, got {:?}",
            result
        ),
    }
}

#[tokio::test]
async fn test_response_below_entry_limit_is_retained() {
    let plugin = make_plugin(json!({
        "max_entry_size_bytes": 2048,
        "max_total_size_bytes": 8192
    }));

    let mut ctx1 = new_ctx("POST", "/api");
    let mut headers1 = HashMap::new();
    headers1.insert(
        "idempotency-key".to_string(),
        "below-entry-limit".to_string(),
    );
    let result = plugin.before_proxy(&mut ctx1, &mut headers1).await;
    assert!(matches!(result, PluginResult::Continue));
    complete_response_with_body(&plugin, &mut ctx1, b"small retained response").await;
    assert!(assert_completed_size_exact(&plugin) > 0);

    let mut ctx2 = new_ctx("POST", "/api");
    let mut headers2 = HashMap::new();
    headers2.insert(
        "idempotency-key".to_string(),
        "below-entry-limit".to_string(),
    );
    let result = plugin.before_proxy(&mut ctx2, &mut headers2).await;
    assert!(matches!(
        result,
        PluginResult::RejectBinary {
            status_code: 200,
            ..
        }
    ));
}

#[tokio::test]
async fn test_oversized_response_is_not_retained_and_clears_inflight() {
    let plugin = make_plugin(json!({
        "max_entry_size_bytes": 1,
        "max_total_size_bytes": 8192
    }));

    let mut ctx1 = new_ctx("POST", "/api");
    let mut headers1 = HashMap::new();
    headers1.insert("idempotency-key".to_string(), "oversized-entry".to_string());
    let result = plugin.before_proxy(&mut ctx1, &mut headers1).await;
    assert!(matches!(result, PluginResult::Continue));
    complete_response_with_body(&plugin, &mut ctx1, b"too large").await;

    assert_eq!(plugin.tracked_keys_count(), Some(0));
    assert_eq!(assert_completed_size_exact(&plugin), 0);

    let mut ctx2 = new_ctx("POST", "/api");
    let mut headers2 = HashMap::new();
    headers2.insert("idempotency-key".to_string(), "oversized-entry".to_string());
    let result = plugin.before_proxy(&mut ctx2, &mut headers2).await;
    assert!(
        matches!(result, PluginResult::Continue),
        "oversized completion must clear in-flight state so the next request can execute"
    );
}

#[tokio::test]
async fn test_total_retained_bytes_cap_skips_new_completion() {
    let plugin = make_plugin(json!({
        "max_entry_size_bytes": 2048,
        "max_total_size_bytes": 768
    }));
    let body = vec![b'a'; 500];

    let mut ctx1 = new_ctx("POST", "/api");
    let mut headers1 = HashMap::new();
    headers1.insert("idempotency-key".to_string(), "total-cap-a".to_string());
    let result = plugin.before_proxy(&mut ctx1, &mut headers1).await;
    assert!(matches!(result, PluginResult::Continue));
    complete_response_with_body(&plugin, &mut ctx1, &body).await;
    let first_size = assert_completed_size_exact(&plugin);
    assert!(
        first_size <= 768,
        "first entry should fit under the configured total cap, got {first_size}"
    );

    let mut ctx2 = new_ctx("POST", "/api");
    let mut headers2 = HashMap::new();
    headers2.insert("idempotency-key".to_string(), "total-cap-b".to_string());
    let result = plugin.before_proxy(&mut ctx2, &mut headers2).await;
    assert!(matches!(result, PluginResult::Continue));
    complete_response_with_body(&plugin, &mut ctx2, &body).await;

    assert_eq!(plugin.tracked_keys_count(), Some(1));
    assert_eq!(assert_completed_size_exact(&plugin), first_size);

    let mut retry_ctx = new_ctx("POST", "/api");
    let mut retry_headers = HashMap::new();
    retry_headers.insert("idempotency-key".to_string(), "total-cap-b".to_string());
    let result = plugin
        .before_proxy(&mut retry_ctx, &mut retry_headers)
        .await;
    assert!(
        matches!(result, PluginResult::Continue),
        "total-cap skip must clear the skipped key's in-flight marker"
    );

    assert!(
        request_deduplication_redis_payload_for_test(
            &plugin,
            200,
            HashMap::new(),
            &body,
            TEST_PRESENTATION_DIGEST,
        )
        .is_some(),
        "a local total-cap skip must still be small enough for Redis publication"
    );
}

#[tokio::test]
async fn test_redis_total_cap_publish_failure_keeps_local_inflight() {
    let plugin = make_plugin(json!({
        "sync_mode": "redis",
        "redis_url": "redis://127.0.0.1:1/0",
        "redis_connect_timeout_seconds": 1,
        "on_redis_unavailable": "local_only",
        "max_entry_size_bytes": 2048,
        "max_total_size_bytes": 768
    }));
    let body = vec![b'a'; 500];

    let mut ctx1 = new_ctx("POST", "/api");
    let mut headers1 = HashMap::new();
    headers1.insert(
        "idempotency-key".to_string(),
        "redis-total-cap-a".to_string(),
    );
    let result = plugin.before_proxy(&mut ctx1, &mut headers1).await;
    assert!(matches!(result, PluginResult::Continue));
    complete_response_with_body(&plugin, &mut ctx1, &body).await;
    let first_size = assert_completed_size_exact(&plugin);
    assert!(
        first_size <= 768,
        "first entry should fit under the configured total cap, got {first_size}"
    );

    let mut ctx2 = new_ctx("POST", "/api");
    let mut headers2 = HashMap::new();
    headers2.insert(
        "idempotency-key".to_string(),
        "redis-total-cap-b".to_string(),
    );
    let result = plugin.before_proxy(&mut ctx2, &mut headers2).await;
    assert!(matches!(result, PluginResult::Continue));
    complete_response_with_body(&plugin, &mut ctx2, &body).await;

    assert_eq!(assert_completed_size_exact(&plugin), first_size);
    assert_eq!(plugin.tracked_keys_count(), Some(2));

    let mut retry_ctx = new_ctx("POST", "/api");
    let mut retry_headers = HashMap::new();
    retry_headers.insert(
        "idempotency-key".to_string(),
        "redis-total-cap-b".to_string(),
    );
    let result = plugin
        .before_proxy(&mut retry_ctx, &mut retry_headers)
        .await;
    match result {
        PluginResult::Reject { status_code, .. } => assert_eq!(status_code, 409),
        other => {
            panic!("Expected Redis publish failure to preserve local in-flight lock, got {other:?}")
        }
    }
}

#[tokio::test]
async fn test_inflight_marker_carries_timestamp() {
    // Smoke test: confirm InFlight marker can be inserted multiple times for
    // distinct keys without panic and tracked_keys_count reflects the inserts.
    // Stale-marker eviction uses `inflight_ttl_seconds` (defaults to
    // `ttl_seconds`); a full timing test would slow CI.
    let config = json!({});
    let plugin = make_plugin(config);

    for i in 0..5 {
        let mut ctx = new_ctx("POST", "/api");
        let mut headers = HashMap::new();
        headers.insert(
            "idempotency-key".to_string(),
            format!("inflight-marker-{i}"),
        );
        let result = plugin.before_proxy(&mut ctx, &mut headers).await;
        assert!(matches!(result, PluginResult::Continue));
    }

    // All 5 distinct keys should be tracked
    assert_eq!(plugin.tracked_keys_count(), Some(5));
}

#[tokio::test]
async fn test_completed_entries_evict_over_capacity_on_insert() {
    let config = json!({
        "ttl_seconds": 300,
        "max_entries": 2
    });
    let plugin = make_plugin(config);

    for i in 0..3 {
        let mut ctx = new_ctx("POST", "/api");
        let mut headers = HashMap::new();
        headers.insert("idempotency-key".to_string(), format!("completed-{i}"));
        let result = plugin.before_proxy(&mut ctx, &mut headers).await;
        assert!(matches!(result, PluginResult::Continue));

        let response_headers = HashMap::new();
        let result = plugin
            .on_final_response_body(&mut ctx, 200, &response_headers, b"cached")
            .await;
        assert!(matches!(result, PluginResult::Continue));
    }

    assert_eq!(plugin.tracked_keys_count(), Some(2));
    assert!(assert_completed_size_exact(&plugin) > 0);
}

#[tokio::test]
async fn test_expired_completed_entries_release_retained_bytes() {
    let plugin = make_plugin(json!({
        "ttl_seconds": 300,
        "max_entry_size_bytes": 2048,
        "max_total_size_bytes": 8192
    }));

    let mut ctx1 = new_ctx("POST", "/api");
    let mut headers1 = HashMap::new();
    headers1.insert("idempotency-key".to_string(), "expires-size".to_string());
    let result = plugin.before_proxy(&mut ctx1, &mut headers1).await;
    assert!(matches!(result, PluginResult::Continue));
    complete_response_with_body(&plugin, &mut ctx1, b"expires").await;
    assert!(assert_completed_size_exact(&plugin) > 0);

    request_deduplication_expire_completed_entries_for_test(&plugin);

    let mut cleanup_ctx = new_ctx("POST", "/api");
    let mut cleanup_headers = HashMap::new();
    cleanup_headers.insert("idempotency-key".to_string(), "cleanup-trigger".to_string());
    let result = plugin
        .before_proxy(&mut cleanup_ctx, &mut cleanup_headers)
        .await;
    assert!(matches!(result, PluginResult::Continue));
    assert_eq!(assert_completed_size_exact(&plugin), 0);
}

#[tokio::test]
async fn test_active_inflight_entries_survive_capacity_pressure() {
    let config = json!({
        "ttl_seconds": 300,
        "max_entries": 2
    });
    let plugin = make_plugin(config);

    for i in 0..3 {
        let mut ctx = new_ctx("POST", "/api");
        let mut headers = HashMap::new();
        headers.insert("idempotency-key".to_string(), format!("inflight-{i}"));
        let result = plugin.before_proxy(&mut ctx, &mut headers).await;
        assert!(matches!(result, PluginResult::Continue));
    }

    assert_eq!(plugin.tracked_keys_count(), Some(3));

    let mut duplicate_ctx = new_ctx("POST", "/api");
    let mut duplicate_headers = HashMap::new();
    duplicate_headers.insert("idempotency-key".to_string(), "inflight-0".to_string());
    let result = plugin
        .before_proxy(&mut duplicate_ctx, &mut duplicate_headers)
        .await;

    match result {
        PluginResult::Reject { status_code, .. } => assert_eq!(status_code, 409),
        other => panic!("Expected duplicate in-flight request to be rejected, got {other:?}"),
    }
}

/// A cached response with `Set-Cookie: session=A` from the first client must
/// NOT be replayed verbatim to a second client sharing the same idempotency
/// key. Without sanitization, the second client would receive the first
/// client's session cookie — a direct session-hijack vector when
/// `scope_by_consumer=false` or for anonymous traffic. Replay must still
/// surface the `x-idempotent-replayed: true` marker so operators can tell a
/// replay apart from a fresh response.
#[tokio::test]
async fn test_replay_strips_set_cookie_session_hijack_protection() {
    let config = json!({});
    let plugin = make_plugin(config);

    // First client: cache a response carrying a session cookie.
    let mut ctx1 = new_ctx("POST", "/api/checkout");
    let mut headers1 = HashMap::new();
    headers1.insert("idempotency-key".to_string(), "shared-key".to_string());
    let result = plugin.before_proxy(&mut ctx1, &mut headers1).await;
    assert!(matches!(result, PluginResult::Continue));

    let mut response_headers = HashMap::new();
    response_headers.insert("content-type".to_string(), "application/json".to_string());
    response_headers.insert(
        "Set-Cookie".to_string(),
        "session=USER_A_SESSION_TOKEN; HttpOnly; Secure".to_string(),
    );
    response_headers.insert("set-cookie2".to_string(), "legacy=USER_A".to_string());
    let body = b"{\"order_id\": 42}";
    let _ = plugin
        .on_final_response_body(&mut ctx1, 200, &response_headers, body)
        .await;

    // Second client (anonymous, same idempotency key): must NOT receive
    // user A's Set-Cookie even though replay returns user A's body.
    // Same canonical caller: the anonymous replay partition binds the
    // gateway-resolved peer address, so this test isolates response-header
    // stripping rather than cross-caller replay.
    let mut ctx2 = new_ctx_from("127.0.0.1", "POST", "/api/checkout");
    let mut headers2 = HashMap::new();
    headers2.insert("idempotency-key".to_string(), "shared-key".to_string());

    let result = plugin.before_proxy(&mut ctx2, &mut headers2).await;
    match result {
        PluginResult::RejectBinary {
            status_code,
            headers,
            body,
            ..
        } => {
            assert_eq!(status_code, 200);
            // Critical: session-bearing headers must be stripped on replay.
            assert!(
                !headers.contains_key("Set-Cookie"),
                "Set-Cookie must be stripped from replayed response (session hijack vector)"
            );
            assert!(
                !headers.contains_key("set-cookie2"),
                "set-cookie2 must be stripped from replayed response"
            );
            // Replay marker still added so operators / clients can detect a replay.
            assert_eq!(
                headers.get("x-idempotent-replayed").map(String::as_str),
                Some("true")
            );
            // Body and safe headers still flow through.
            assert_eq!(&body[..], b"{\"order_id\": 42}");
            assert_eq!(
                headers.get("content-type").map(String::as_str),
                Some("application/json")
            );
        }
        other => panic!("Expected RejectBinary replay, got {:?}", other),
    }
}

/// Authorization, www-authenticate, and per-request trace IDs must be
/// stripped on replay. The original request's `Authorization: Bearer <leaked>`
/// being echoed back to a different consumer is an information-disclosure
/// vector, and replaying the original `traceparent` would splice every cache
/// hit into the original transaction's trace.
#[tokio::test]
async fn test_replay_strips_authorization_and_trace_headers() {
    let config = json!({});
    let plugin = make_plugin(config);

    let mut ctx1 = new_ctx("POST", "/api");
    let mut headers1 = HashMap::new();
    headers1.insert("idempotency-key".to_string(), "auth-key".to_string());
    let _ = plugin.before_proxy(&mut ctx1, &mut headers1).await;

    let mut response_headers = HashMap::new();
    response_headers.insert(
        "Authorization".to_string(),
        "Bearer leaked-token".to_string(),
    );
    response_headers.insert(
        "WWW-Authenticate".to_string(),
        "Bearer realm=\"api\"".to_string(),
    );
    response_headers.insert("X-Request-Id".to_string(), "req-original-12345".to_string());
    response_headers.insert(
        "traceparent".to_string(),
        "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01".to_string(),
    );
    response_headers.insert("X-RateLimit-Remaining".to_string(), "42".to_string());
    response_headers.insert("content-type".to_string(), "application/json".to_string());
    let _ = plugin
        .on_final_response_body(&mut ctx1, 200, &response_headers, b"{}")
        .await;

    // Same canonical caller (see the anonymous replay partition above); this
    // test isolates response-header stripping, not cross-caller replay.
    let mut ctx2 = new_ctx_from("127.0.0.1", "POST", "/api");
    let mut headers2 = HashMap::new();
    headers2.insert("idempotency-key".to_string(), "auth-key".to_string());

    let result = plugin.before_proxy(&mut ctx2, &mut headers2).await;
    match result {
        PluginResult::RejectBinary { headers, .. } => {
            // Sensitive headers stripped (case-insensitive check).
            assert!(
                !headers
                    .keys()
                    .any(|k| k.eq_ignore_ascii_case("Authorization")),
                "Authorization must be stripped (info-disclosure vector)"
            );
            assert!(
                !headers
                    .keys()
                    .any(|k| k.eq_ignore_ascii_case("WWW-Authenticate"))
            );
            assert!(
                !headers
                    .keys()
                    .any(|k| k.eq_ignore_ascii_case("X-Request-Id")),
                "Per-request trace IDs must be stripped"
            );
            assert!(
                !headers
                    .keys()
                    .any(|k| k.eq_ignore_ascii_case("traceparent"))
            );
            assert!(
                !headers
                    .keys()
                    .any(|k| k.eq_ignore_ascii_case("X-RateLimit-Remaining")),
                "Rate-limit counters must be stripped"
            );
            // Replay marker still present.
            assert_eq!(
                headers.get("x-idempotent-replayed").map(String::as_str),
                Some("true")
            );
            // Safe headers retained.
            assert_eq!(
                headers.get("content-type").map(String::as_str),
                Some("application/json")
            );
        }
        other => panic!("Expected RejectBinary replay, got {:?}", other),
    }
}

/// `Set-Cookie` set on a different case (case-insensitive HTTP header
/// matching) must still be stripped on replay. Backends emit cookies under
/// many casings (`Set-Cookie`, `set-cookie`, `SET-COOKIE`); a case-sensitive
/// strip would silently leak sessions.
#[tokio::test]
async fn test_replay_strips_set_cookie_case_insensitively() {
    let config = json!({});
    let plugin = make_plugin(config);

    let mut ctx1 = new_ctx("POST", "/api");
    let mut headers1 = HashMap::new();
    headers1.insert("idempotency-key".to_string(), "case-key".to_string());
    let _ = plugin.before_proxy(&mut ctx1, &mut headers1).await;

    let mut response_headers = HashMap::new();
    // Mixed casings — all must be stripped.
    response_headers.insert("set-cookie".to_string(), "session=A".to_string());
    response_headers.insert("Set-Cookie".to_string(), "session=B".to_string());
    response_headers.insert("SET-COOKIE".to_string(), "session=C".to_string());
    response_headers.insert("content-type".to_string(), "application/json".to_string());
    let _ = plugin
        .on_final_response_body(&mut ctx1, 200, &response_headers, b"{}")
        .await;

    // Same canonical caller (see the anonymous replay partition above); this
    // test isolates response-header stripping, not cross-caller replay.
    let mut ctx2 = new_ctx_from("127.0.0.1", "POST", "/api");
    let mut headers2 = HashMap::new();
    headers2.insert("idempotency-key".to_string(), "case-key".to_string());
    let result = plugin.before_proxy(&mut ctx2, &mut headers2).await;
    match result {
        PluginResult::RejectBinary { headers, .. } => {
            assert!(
                !headers.keys().any(|k| k.eq_ignore_ascii_case("set-cookie")),
                "All casings of Set-Cookie must be stripped"
            );
            assert_eq!(
                headers.get("x-idempotent-replayed").map(String::as_str),
                Some("true")
            );
            assert_eq!(
                headers.get("content-type").map(String::as_str),
                Some("application/json")
            );
        }
        other => panic!("Expected RejectBinary replay, got {:?}", other),
    }
}

#[tokio::test]
async fn test_keyed_applicable_methods_buffer_request_body_for_fingerprint() {
    let plugin = make_plugin(json!({}));

    let mut keyed_post = body_ctx("POST", "/api", b"{\"a\":1}");
    keyed_post.headers = keyed_headers("body-key", "api.example", 7);
    assert!(plugin.should_buffer_request_body(&keyed_post));

    let keyless_without_declared_body = new_ctx("POST", "/api");
    assert!(
        !plugin.should_buffer_request_body(&keyless_without_declared_body),
        "keyless optional requests must not lose streaming semantics"
    );

    let mut keyless_declared_body = new_ctx("POST", "/api");
    keyless_declared_body
        .headers
        .insert("content-length".to_string(), "7".to_string());
    assert!(
        !plugin.should_buffer_request_body(&keyless_declared_body),
        "keyless optional requests must not be rejected by body buffering limits before this plugin ignores them"
    );

    let required_keyless = new_ctx("POST", "/api");
    let required_plugin = make_plugin(json!({
        "enforce_required": true
    }));
    assert!(required_plugin.should_buffer_request_body(&required_keyless));

    let mut keyed_get = new_ctx("GET", "/api");
    keyed_get.headers = keyed_headers("body-key", "api.example", 0);
    assert!(!plugin.should_buffer_request_body(&keyed_get));
}

#[tokio::test]
async fn test_keyed_idempotency_header_can_fingerprint_prebuffered_body() {
    let plugin = make_plugin(json!({}));

    let mut ctx = body_ctx("POST", "/api", b"{\"a\":1}");
    ctx.headers
        .insert("content-length".to_string(), "7".to_string());
    ctx.headers
        .insert("idempotency-key".to_string(), "transformed-key".to_string());
    assert!(
        plugin.should_buffer_request_body(&ctx),
        "declared-body applicable requests must prebuffer before earlier plugins can add the key"
    );

    let mut headers = keyed_headers("transformed-key", "api.example", 7);
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
    assert!(request_identity(&plugin, &ctx).is_some());
}

#[tokio::test]
async fn test_keyed_idempotency_header_buffers_implicit_http2_body() {
    let plugin = make_plugin(json!({}));

    let mut ctx = new_ctx("POST", "/api");
    ctx.headers.insert(
        "idempotency-key".to_string(),
        "implicit-body-key".to_string(),
    );
    assert!(
        plugin.should_buffer_request_body(&ctx),
        "keyed HTTP/2 and HTTP/3 POST bodies may arrive without length or transfer headers"
    );
}

#[tokio::test]
async fn test_identical_request_bodies_replay_cached_response() {
    let plugin = make_plugin(json!({}));

    let mut ctx1 = body_ctx("POST", "/api/orders", b"{\"order\":1}");
    let mut headers1 = keyed_headers("same-body", "api.example", 11);
    let result = plugin.before_proxy(&mut ctx1, &mut headers1).await;
    assert!(matches!(result, PluginResult::Continue));
    complete_response(&plugin, &mut ctx1).await;

    let mut ctx2 = body_ctx("POST", "/api/orders", b"{\"order\":1}");
    let mut headers2 = keyed_headers("same-body", "api.example", 11);
    let result = plugin.before_proxy(&mut ctx2, &mut headers2).await;
    match result {
        PluginResult::RejectBinary {
            status_code, body, ..
        } => {
            assert_eq!(status_code, 201);
            assert_eq!(&body[..], b"{\"ok\":true}");
        }
        other => panic!("Expected replay for identical body, got {other:?}"),
    }
}

#[tokio::test]
async fn test_reused_key_different_method_returns_409() {
    let mut first_ctx = body_ctx("POST", "/api/orders", b"{\"order\":1}");
    let mut first_headers = keyed_headers("method-key", "api.example", 11);
    let mut second_ctx = body_ctx("PUT", "/api/orders", b"{\"order\":1}");
    let mut second_headers = keyed_headers("method-key", "api.example", 11);

    assert_reused_key_for_different_request_conflicts(
        &mut first_ctx,
        &mut first_headers,
        &mut second_ctx,
        &mut second_headers,
    )
    .await;
}

#[tokio::test]
async fn test_reused_key_different_authority_returns_409() {
    let mut first_ctx = body_ctx("POST", "/api/orders", b"{\"order\":1}");
    let mut first_headers = keyed_headers("authority-key", "api.example", 11);
    let mut second_ctx = body_ctx("POST", "/api/orders", b"{\"order\":1}");
    let mut second_headers = keyed_headers("authority-key", "other.example", 11);

    assert_reused_key_for_different_request_conflicts(
        &mut first_ctx,
        &mut first_headers,
        &mut second_ctx,
        &mut second_headers,
    )
    .await;
}

#[tokio::test]
async fn test_reused_key_different_authority_case_returns_409() {
    let mut first_ctx = body_ctx("POST", "/api/orders", b"{\"order\":1}");
    let mut first_headers = keyed_headers("authority-case-key", "API.example", 11);
    let mut second_ctx = body_ctx("POST", "/api/orders", b"{\"order\":1}");
    let mut second_headers = keyed_headers("authority-case-key", "api.example", 11);

    assert_reused_key_for_different_request_conflicts(
        &mut first_ctx,
        &mut first_headers,
        &mut second_ctx,
        &mut second_headers,
    )
    .await;
}

#[tokio::test]
async fn test_reused_key_different_raw_path_returns_409() {
    let mut first_ctx = body_ctx("POST", "/api/orders/1", b"{\"order\":1}");
    let mut first_headers = keyed_headers("path-key", "api.example", 11);
    let mut second_ctx = body_ctx("POST", "/api/orders/2", b"{\"order\":1}");
    let mut second_headers = keyed_headers("path-key", "api.example", 11);

    assert_reused_key_for_different_request_conflicts(
        &mut first_ctx,
        &mut first_headers,
        &mut second_ctx,
        &mut second_headers,
    )
    .await;
}

#[tokio::test]
async fn test_reused_key_different_raw_query_returns_409() {
    let mut first_ctx = body_ctx("POST", "/api/orders", b"{\"order\":1}");
    first_ctx.set_raw_query_string("a=1&a=2".to_string());
    let mut first_headers = keyed_headers("query-key", "api.example", 11);
    let mut second_ctx = body_ctx("POST", "/api/orders", b"{\"order\":1}");
    second_ctx.set_raw_query_string("a=2&a=1".to_string());
    let mut second_headers = keyed_headers("query-key", "api.example", 11);

    assert_reused_key_for_different_request_conflicts(
        &mut first_ctx,
        &mut first_headers,
        &mut second_ctx,
        &mut second_headers,
    )
    .await;
}

#[tokio::test]
async fn test_reused_key_different_outbound_query_returns_409() {
    let mut first_ctx = body_ctx("POST", "/api/orders", b"{\"order\":1}");
    first_ctx.set_raw_query_string("tenant=client".to_string());
    first_ctx.publish_transformed_query(
        "tenant=blue".to_string(),
        HashMap::from([("tenant".to_string(), "blue".to_string())]),
    );
    let mut first_headers = keyed_headers("outbound-query-key", "api.example", 11);

    let mut second_ctx = body_ctx("POST", "/api/orders", b"{\"order\":1}");
    second_ctx.set_raw_query_string("tenant=client".to_string());
    second_ctx.publish_transformed_query(
        "tenant=green".to_string(),
        HashMap::from([("tenant".to_string(), "green".to_string())]),
    );
    let mut second_headers = keyed_headers("outbound-query-key", "api.example", 11);

    assert_reused_key_for_different_request_conflicts(
        &mut first_ctx,
        &mut first_headers,
        &mut second_ctx,
        &mut second_headers,
    )
    .await;
}

#[tokio::test]
async fn test_reused_key_different_route_affecting_header_returns_409() {
    let mut first_ctx = body_ctx("POST", "/api/orders", b"{\"order\":1}");
    let mut first_headers = keyed_headers("route-header-key", "api.example", 11);
    first_headers.insert("x-canary".to_string(), "blue".to_string());
    let mut second_ctx = body_ctx("POST", "/api/orders", b"{\"order\":1}");
    let mut second_headers = keyed_headers("route-header-key", "api.example", 11);
    second_headers.insert("x-canary".to_string(), "green".to_string());

    assert_reused_key_for_different_request_conflicts(
        &mut first_ctx,
        &mut first_headers,
        &mut second_ctx,
        &mut second_headers,
    )
    .await;
}

#[tokio::test]
async fn test_reused_key_different_client_trace_headers_replays() {
    let plugin = make_plugin(json!({}));

    let mut first_ctx = body_ctx("POST", "/api/orders", b"{\"order\":1}");
    let mut first_headers = keyed_headers("synthetic-key", "api.example", 11);
    first_headers.insert(
        "traceparent".to_string(),
        "00-11111111111111111111111111111111-2222222222222222-01".to_string(),
    );
    first_headers.insert("x-request-id".to_string(), "request-a".to_string());
    first_headers.insert("tracestate".to_string(), "vendor=trace-a".to_string());
    first_headers.insert("X-Correlation-ID".to_string(), "correlation-a".to_string());
    first_headers.insert("correlation-id".to_string(), "legacy-a".to_string());
    first_headers.insert("X-Trace-ID".to_string(), "generic-a".to_string());
    first_headers.insert(
        "X-Amzn-Trace-Id".to_string(),
        "Root=1-11111111-111111111111111111111111".to_string(),
    );
    first_headers.insert(
        "B3".to_string(),
        "1111111111111111-2222222222222222-1".to_string(),
    );
    first_headers.insert("X-B3-TraceId".to_string(), "1111111111111111".to_string());
    first_headers.insert("x-b3-spanid".to_string(), "2222222222222222".to_string());
    assert!(matches!(
        plugin
            .before_proxy(&mut first_ctx, &mut first_headers)
            .await,
        PluginResult::Continue
    ));
    complete_response(&plugin, &mut first_ctx).await;

    let mut second_ctx = body_ctx("POST", "/api/orders", b"{\"order\":1}");
    let mut second_headers = keyed_headers("synthetic-key", "api.example", 11);
    second_headers.insert(
        "traceparent".to_string(),
        "00-33333333333333333333333333333333-4444444444444444-01".to_string(),
    );
    second_headers.insert("x-request-id".to_string(), "request-b".to_string());
    second_headers.insert("TraceState".to_string(), "vendor=trace-b".to_string());
    second_headers.insert("x-correlation-id".to_string(), "correlation-b".to_string());
    second_headers.insert("Correlation-Id".to_string(), "legacy-b".to_string());
    second_headers.insert("x-trace-id".to_string(), "generic-b".to_string());
    second_headers.insert(
        "x-amzn-trace-id".to_string(),
        "Root=1-33333333-333333333333333333333333".to_string(),
    );
    second_headers.insert(
        "b3".to_string(),
        "3333333333333333-4444444444444444-0".to_string(),
    );
    second_headers.insert("x-b3-traceid".to_string(), "3333333333333333".to_string());
    second_headers.insert("X-B3-SpanId".to_string(), "4444444444444444".to_string());

    let result = plugin
        .before_proxy(&mut second_ctx, &mut second_headers)
        .await;
    assert!(matches!(result, PluginResult::RejectBinary { .. }));
}

/// A rotated credential for one display subject is a *different authorization
/// context* and must not replay (GHSA-w27g-65rf-h7xm).
///
/// This previously replayed: credential headers were excluded from the
/// fingerprint whenever `scope_by_consumer` had resolved an identity, so two
/// tokens that render as one `sub` — with different scopes, audiences, or
/// tenancy claims — produced an identical fingerprint. Credential material is
/// now bound as digests in *both* the mandatory caller partition of the logical
/// key and the request fingerprint, while the raw secret still never enters a
/// key. The caller partition is the outer boundary, so the rotated credential
/// claims its own operation rather than conflicting with the stored one — which
/// is the stronger outcome: it neither replays nor reports another caller's key
/// as taken.
#[tokio::test]
async fn test_scoped_credential_rotation_cannot_replay() {
    let plugin = make_plugin(json!({}));

    let mut first_ctx = body_ctx("POST", "/api/orders", b"{\"order\":1}");
    first_ctx.authenticated_identity = Some("consumer-1".to_string());
    let mut first_headers = keyed_headers("credential-rotation-key", "api.example", 11);
    first_headers.insert("authorization".to_string(), "Bearer old-token".to_string());
    first_headers.insert("cookie".to_string(), "session=old".to_string());
    first_headers.insert("x-api-key".to_string(), "old-api-key".to_string());
    assert!(matches!(
        plugin
            .before_proxy(&mut first_ctx, &mut first_headers)
            .await,
        PluginResult::Continue
    ));
    complete_response(&plugin, &mut first_ctx).await;

    let mut second_ctx = body_ctx("POST", "/api/orders", b"{\"order\":1}");
    second_ctx.authenticated_identity = Some("consumer-1".to_string());
    let mut second_headers = keyed_headers("credential-rotation-key", "api.example", 11);
    second_headers.insert("authorization".to_string(), "Bearer new-token".to_string());
    second_headers.insert("cookie".to_string(), "session=new".to_string());
    second_headers.insert("x-api-key".to_string(), "new-api-key".to_string());

    let result = plugin
        .before_proxy(&mut second_ctx, &mut second_headers)
        .await;
    assert!(
        matches!(result, PluginResult::Continue),
        "a rotated credential must not replay the stored response"
    );

    // The unchanged credential context still replays.
    let mut same_ctx = body_ctx("POST", "/api/orders", b"{\"order\":1}");
    same_ctx.authenticated_identity = Some("consumer-1".to_string());
    let mut same_headers = keyed_headers("credential-rotation-key", "api.example", 11);
    same_headers.insert("authorization".to_string(), "Bearer old-token".to_string());
    same_headers.insert("cookie".to_string(), "session=old".to_string());
    same_headers.insert("x-api-key".to_string(), "old-api-key".to_string());
    assert!(matches!(
        plugin.before_proxy(&mut same_ctx, &mut same_headers).await,
        PluginResult::RejectBinary { .. }
    ));
}

/// Same boundary with `scope_by_consumer` disabled: the display identity leaves
/// the key, but the credential digests in the caller partition remain.
#[tokio::test]
async fn test_unscoped_credential_rotation_cannot_replay() {
    let plugin = make_plugin(json!({
        "scope_by_consumer": false
    }));

    let mut first_ctx = body_ctx("POST", "/api/orders", b"{\"order\":1}");
    first_ctx.authenticated_identity = Some("consumer-1".to_string());
    let mut first_headers = keyed_headers("unscoped-credential-key", "api.example", 11);
    first_headers.insert("authorization".to_string(), "Bearer old-token".to_string());
    assert!(matches!(
        plugin
            .before_proxy(&mut first_ctx, &mut first_headers)
            .await,
        PluginResult::Continue
    ));
    complete_response(&plugin, &mut first_ctx).await;

    let mut second_ctx = body_ctx("POST", "/api/orders", b"{\"order\":1}");
    second_ctx.authenticated_identity = Some("consumer-1".to_string());
    let mut second_headers = keyed_headers("unscoped-credential-key", "api.example", 11);
    second_headers.insert("authorization".to_string(), "Bearer new-token".to_string());

    let result = plugin
        .before_proxy(&mut second_ctx, &mut second_headers)
        .await;
    assert!(
        matches!(result, PluginResult::Continue),
        "a rotated credential must not replay the stored response"
    );
}

/// Same boundary for a caller Ferrum never authenticated: the presented
/// credential headers are still the caller's authorization context.
#[tokio::test]
async fn test_anonymous_credential_rotation_cannot_replay() {
    let plugin = make_plugin(json!({}));

    let mut first_ctx = body_ctx("POST", "/api/orders", b"{\"order\":1}");
    let mut first_headers = keyed_headers("anonymous-credential-key", "api.example", 11);
    first_headers.insert("authorization".to_string(), "Bearer old-token".to_string());
    first_headers.insert("cookie".to_string(), "session=old".to_string());
    assert!(matches!(
        plugin
            .before_proxy(&mut first_ctx, &mut first_headers)
            .await,
        PluginResult::Continue
    ));
    complete_response(&plugin, &mut first_ctx).await;

    let mut second_ctx = body_ctx("POST", "/api/orders", b"{\"order\":1}");
    let mut second_headers = keyed_headers("anonymous-credential-key", "api.example", 11);
    second_headers.insert("authorization".to_string(), "Bearer new-token".to_string());
    second_headers.insert("cookie".to_string(), "session=new".to_string());

    let result = plugin
        .before_proxy(&mut second_ctx, &mut second_headers)
        .await;
    assert!(
        matches!(result, PluginResult::Continue),
        "a rotated credential must not replay the stored response"
    );
}

#[tokio::test]
async fn test_reused_key_different_connection_listed_header_returns_409() {
    let plugin = make_plugin(json!({}));

    let mut first_ctx = body_ctx("POST", "/api/orders", b"{\"order\":1}");
    let mut first_headers = keyed_headers("connection-key", "api.example", 11);
    first_headers.insert("connection".to_string(), "x-debug-route".to_string());
    first_headers.insert("x-debug-route".to_string(), "blue".to_string());
    assert!(matches!(
        plugin
            .before_proxy(&mut first_ctx, &mut first_headers)
            .await,
        PluginResult::Continue
    ));
    complete_response(&plugin, &mut first_ctx).await;

    let mut second_ctx = body_ctx("POST", "/api/orders", b"{\"order\":1}");
    let mut second_headers = keyed_headers("connection-key", "api.example", 11);
    second_headers.insert("connection".to_string(), "x-debug-route".to_string());
    second_headers.insert("x-debug-route".to_string(), "green".to_string());

    let result = plugin
        .before_proxy(&mut second_ctx, &mut second_headers)
        .await;
    assert_fingerprint_conflict(result);
}

#[tokio::test]
async fn test_reused_key_different_content_length_replays() {
    let plugin = make_plugin(json!({}));

    let mut first_ctx = body_ctx("POST", "/api/orders", b"{\"order\":1}");
    let mut first_headers = keyed_headers("content-length-key", "api.example", 11);
    assert!(matches!(
        plugin
            .before_proxy(&mut first_ctx, &mut first_headers)
            .await,
        PluginResult::Continue
    ));
    complete_response(&plugin, &mut first_ctx).await;

    let mut second_ctx = body_ctx("POST", "/api/orders", b"{\"order\":1}");
    let mut second_headers = keyed_headers("content-length-key", "api.example", 11);
    second_headers.insert("content-length".to_string(), "999".to_string());

    let result = plugin
        .before_proxy(&mut second_ctx, &mut second_headers)
        .await;
    assert!(matches!(result, PluginResult::RejectBinary { .. }));
}

#[tokio::test]
async fn test_reused_key_equivalent_gzip_body_replays() {
    let plugin = make_plugin(json!({}));
    let logical_body = br#"{"order":1}"#;
    let compressed_body = gzip_body(logical_body);

    let mut first_ctx = new_ctx("POST", "/api/orders");
    first_ctx.request_body_bytes = Some(Bytes::from(compressed_body.clone()));
    let mut first_headers = keyed_headers("gzip-body-key", "api.example", compressed_body.len());
    first_headers.insert("content-encoding".to_string(), "gzip".to_string());
    assert!(matches!(
        plugin
            .before_proxy(&mut first_ctx, &mut first_headers)
            .await,
        PluginResult::Continue
    ));
    complete_response(&plugin, &mut first_ctx).await;

    let mut second_ctx = body_ctx("POST", "/api/orders", logical_body);
    let mut second_headers = keyed_headers("gzip-body-key", "api.example", logical_body.len());

    let result = plugin
        .before_proxy(&mut second_ctx, &mut second_headers)
        .await;
    assert!(matches!(result, PluginResult::RejectBinary { .. }));
}

#[tokio::test]
async fn test_large_gzip_body_uses_wire_fingerprint_fallback() {
    let plugin = make_plugin(json!({}));
    let logical_body = vec![b'a'; 1024 * 1024 + 1];
    let compressed_body = gzip_body(&logical_body);

    let mut first_ctx = new_ctx("POST", "/api/orders");
    first_ctx.request_body_bytes = Some(Bytes::from(compressed_body.clone()));
    let mut first_headers =
        keyed_headers("large-gzip-body-key", "api.example", compressed_body.len());
    first_headers.insert("content-encoding".to_string(), "gzip".to_string());
    assert!(matches!(
        plugin
            .before_proxy(&mut first_ctx, &mut first_headers)
            .await,
        PluginResult::Continue
    ));
    complete_response(&plugin, &mut first_ctx).await;

    let mut second_ctx = new_ctx("POST", "/api/orders");
    second_ctx.request_body_bytes = Some(Bytes::from(logical_body));
    let mut second_headers = keyed_headers("large-gzip-body-key", "api.example", 1024 * 1024 + 1);

    let result = plugin
        .before_proxy(&mut second_ctx, &mut second_headers)
        .await;
    assert_fingerprint_conflict(result);
}

#[tokio::test]
async fn test_unsupported_content_encoding_stays_in_fingerprint() {
    let plugin = make_plugin(json!({}));
    let body = b"same wire bytes";

    let mut first_ctx = body_ctx("POST", "/api/orders", body);
    let mut first_headers = keyed_headers("unsupported-encoding-key", "api.example", body.len());
    first_headers.insert("content-encoding".to_string(), "deflate".to_string());
    assert!(matches!(
        plugin
            .before_proxy(&mut first_ctx, &mut first_headers)
            .await,
        PluginResult::Continue
    ));
    complete_response(&plugin, &mut first_ctx).await;

    let mut second_ctx = body_ctx("POST", "/api/orders", body);
    let mut second_headers = keyed_headers("unsupported-encoding-key", "api.example", body.len());
    let result = plugin
        .before_proxy(&mut second_ctx, &mut second_headers)
        .await;
    assert_fingerprint_conflict(result);
}

#[tokio::test]
async fn test_malformed_supported_content_encoding_stays_in_fingerprint() {
    let plugin = make_plugin(json!({}));
    let body = b"not actually gzip";

    let mut first_ctx = body_ctx("POST", "/api/orders", body);
    let mut first_headers = keyed_headers("malformed-encoding-key", "api.example", body.len());
    first_headers.insert("content-encoding".to_string(), "gzip".to_string());
    assert!(matches!(
        plugin
            .before_proxy(&mut first_ctx, &mut first_headers)
            .await,
        PluginResult::Continue
    ));
    complete_response(&plugin, &mut first_ctx).await;

    let mut second_ctx = body_ctx("POST", "/api/orders", body);
    let mut second_headers = keyed_headers("malformed-encoding-key", "api.example", body.len());
    let result = plugin
        .before_proxy(&mut second_ctx, &mut second_headers)
        .await;
    assert_fingerprint_conflict(result);
}

#[tokio::test]
async fn test_reused_key_different_body_returns_409() {
    let mut first_ctx = body_ctx("POST", "/api/orders", b"{\"order\":1}");
    let mut first_headers = keyed_headers("body-key", "api.example", 11);
    let mut second_ctx = body_ctx("POST", "/api/orders", b"{\"order\":2}");
    let mut second_headers = keyed_headers("body-key", "api.example", 11);

    assert_reused_key_for_different_request_conflicts(
        &mut first_ctx,
        &mut first_headers,
        &mut second_ctx,
        &mut second_headers,
    )
    .await;
}

#[tokio::test]
async fn test_declared_body_unavailable_rejects_fingerprinting() {
    let plugin = make_plugin(json!({}));
    let mut ctx = new_ctx("POST", "/api/orders");
    let mut headers = keyed_headers("missing-body", "api.example", 12);

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    match result {
        PluginResult::Reject {
            status_code, body, ..
        } => {
            assert_eq!(status_code, 400);
            assert!(body.contains("Request body unavailable"));
        }
        other => panic!("Expected body-unavailable reject, got {other:?}"),
    }
}

#[test]
fn test_legacy_redis_cached_response_without_fingerprint_is_rejected() {
    let legacy = br#"{"status_code":201,"headers":{},"body":[]}"#;

    assert!(!request_deduplication_redis_cached_response_payload_is_valid(legacy));
}

/// A record written before replay provenance existed carries no policy binding
/// at all, so it can never be shown compatible with the live presentation
/// policy. It must be refused, not defaulted into a match.
#[test]
fn test_redis_cached_response_without_policy_provenance_is_rejected() {
    let legacy = br#"{"fingerprint":"sha256-test","status_code":201,"headers":{},"body":[123,34,111,107,34,58,116,114,117,101,125]}"#;

    assert!(!request_deduplication_redis_cached_response_payload_is_valid(legacy));
}

/// Provenance that is present but not a decodable pair of 32-byte digests is
/// equally unusable and fails closed the same way.
#[test]
fn test_redis_cached_response_with_malformed_policy_provenance_is_rejected() {
    let short_gate = br#"{"fingerprint":"sha256-test","response_policy":{"gate":"abcd","presentation":"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"},"status_code":201,"headers":{},"body":"e30="}"#;
    assert!(!request_deduplication_redis_cached_response_payload_is_valid(short_gate));

    let non_hex_presentation = br#"{"fingerprint":"sha256-test","response_policy":{"gate":"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff","presentation":"zzzz2233445566778899aabbccddeeff00112233445566778899aabbccddeeff"},"status_code":201,"headers":{},"body":"e30="}"#;
    assert!(!request_deduplication_redis_cached_response_payload_is_valid(non_hex_presentation));

    let half_present = br#"{"fingerprint":"sha256-test","response_policy":{"gate":"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"},"status_code":201,"headers":{},"body":"e30="}"#;
    assert!(!request_deduplication_redis_cached_response_payload_is_valid(half_present));
}

/// The body field accepts a JSON byte array as well as the base64 string the
/// current serializer emits, so a peer on a different serializer version stays
/// readable. Complete provenance is what admits the record; the body encoding
/// is orthogonal and must not have been narrowed by the provenance guard.
#[test]
fn test_redis_cached_response_byte_array_body_with_provenance_is_accepted() {
    let byte_array_body = br#"{"fingerprint":"sha256-test","response_policy":{"gate":"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff","presentation":"ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100"},"status_code":201,"headers":{},"body":[123,34,111,107,34,58,116,114,117,101,125]}"#;

    assert!(request_deduplication_redis_cached_response_payload_is_valid(byte_array_body));
}

/// Current-version operation records have a strict state-dependent shape.
/// Missing fences, impossible field combinations, and a replay whose inner
/// fingerprint disagrees with its owning record are unknown writer state and
/// must fail closed rather than being interpreted optimistically.
#[test]
fn redis_operation_record_rejects_malformed_current_version_shapes() {
    let fingerprint = "sha256-request-a";
    let valid_replay = json!({
        "fingerprint": fingerprint,
        "response_policy": {
            "gate": "00".repeat(32),
            "presentation": "11".repeat(32)
        },
        "status_code": 201,
        "headers": {},
        "body": "e30="
    });

    for valid in [
        json!({
            "record_version": 1,
            "state": "inflight",
            "fingerprint": fingerprint,
            "owner_token": "owner-a"
        }),
        json!({
            "record_version": 1,
            "state": "completed",
            "fingerprint": fingerprint
        }),
        json!({
            "record_version": 1,
            "state": "completed",
            "fingerprint": fingerprint,
            "replay": valid_replay.clone()
        }),
    ] {
        let bytes = serde_json::to_vec(&valid).expect("record JSON");
        assert!(
            request_deduplication_redis_record_payload_is_valid(&bytes),
            "valid current record rejected: {valid}"
        );
    }

    for malformed in [
        json!({
            "record_version": 1,
            "state": "inflight",
            "fingerprint": fingerprint
        }),
        json!({
            "record_version": 1,
            "state": "inflight",
            "fingerprint": fingerprint,
            "owner_token": ""
        }),
        json!({
            "record_version": 1,
            "state": "inflight",
            "fingerprint": fingerprint,
            "owner_token": "owner-a",
            "replay": valid_replay.clone()
        }),
        json!({
            "record_version": 1,
            "state": "completed",
            "fingerprint": fingerprint,
            "owner_token": "stale-owner"
        }),
        json!({
            "record_version": 1,
            "state": "completed",
            "fingerprint": fingerprint,
            "replay": {
                "fingerprint": "sha256-request-b",
                "response_policy": {
                    "gate": "00".repeat(32),
                    "presentation": "11".repeat(32)
                },
                "status_code": 201,
                "headers": {},
                "body": "e30="
            }
        }),
    ] {
        let bytes = serde_json::to_vec(&malformed).expect("record JSON");
        assert!(
            !request_deduplication_redis_record_payload_is_valid(&bytes),
            "malformed current record accepted: {malformed}"
        );
    }
}

#[test]
fn test_redis_payload_admission_respects_entry_size_limit() {
    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/json".to_string());

    let plugin = make_plugin(json!({
        "max_entry_size_bytes": 2048
    }));
    let payload = request_deduplication_redis_payload_for_test(
        &plugin,
        201,
        headers.clone(),
        b"{\"ok\":true}",
        TEST_PRESENTATION_DIGEST,
    )
    .expect("small Redis payload should be admitted");
    assert!(request_deduplication_redis_cached_response_payload_is_valid(&payload));

    let plugin = make_plugin(json!({
        "max_entry_size_bytes": 1
    }));
    assert!(
        request_deduplication_redis_payload_for_test(
            &plugin,
            201,
            headers,
            b"{\"ok\":true}",
            TEST_PRESENTATION_DIGEST,
        )
        .is_none(),
        "oversized responses must not be serialized for Redis storage"
    );
}

#[test]
fn test_redis_payload_uses_compact_body_encoding_before_size_check() {
    let mut headers = HashMap::new();
    headers.insert(
        "content-type".to_string(),
        "application/octet-stream".to_string(),
    );

    let max_entry_size_bytes = 256 * 1024;
    let plugin = make_plugin(json!({
        "max_entry_size_bytes": max_entry_size_bytes
    }));
    let body = vec![0xab; 160 * 1024];
    let payload = request_deduplication_redis_payload_for_test(
        &plugin,
        201,
        headers,
        &body,
        TEST_PRESENTATION_DIGEST,
    )
    .expect("compact Redis payload should be admitted under the entry limit");
    let payload_json: serde_json::Value =
        serde_json::from_slice(&payload).expect("payload should be JSON");

    assert!(
        payload_json
            .get("body")
            .is_some_and(serde_json::Value::is_string),
        "Redis response bodies must serialize as compact base64 strings"
    );
    assert!(
        payload.len() <= max_entry_size_bytes,
        "compact Redis payload should remain under the configured entry cap"
    );
    assert!(request_deduplication_redis_cached_response_payload_is_valid(&payload));
}

#[test]
fn test_redis_payload_admission_rejects_serialized_payload_over_entry_limit() {
    let mut headers = HashMap::new();
    headers.insert(
        "content-type".to_string(),
        "application/octet-stream".to_string(),
    );

    let plugin = make_plugin(json!({
        "max_entry_size_bytes": 1024 * 1024
    }));
    let body = vec![0xab; 800 * 1024];
    assert!(
        request_deduplication_redis_payload_for_test(
            &plugin,
            201,
            headers,
            &body,
            TEST_PRESENTATION_DIGEST,
        )
        .is_none(),
        "Redis payloads must be rejected when serialized storage exceeds the entry cap"
    );
}

#[tokio::test]
async fn test_delimiter_containing_identities_and_keys_do_not_collide() {
    let plugin = make_plugin(json!({
        "scope_by_consumer": true
    }));

    let mut ctx1 = body_ctx("POST", "/api/orders", b"{}");
    ctx1.authenticated_identity = Some("alice:tenant".to_string());
    let mut headers1 = keyed_headers("key", "api.example", 2);
    let result = plugin.before_proxy(&mut ctx1, &mut headers1).await;
    assert!(matches!(result, PluginResult::Continue));

    let mut ctx2 = body_ctx("POST", "/api/orders", b"{}");
    ctx2.authenticated_identity = Some("alice".to_string());
    let mut headers2 = keyed_headers("tenant:key", "api.example", 2);
    let result = plugin.before_proxy(&mut ctx2, &mut headers2).await;
    assert!(matches!(result, PluginResult::Continue));

    let (key1, _) = request_identity(&plugin, &ctx1).unwrap();
    let (key2, _) = request_identity(&plugin, &ctx2).unwrap();
    assert_ne!(key1, key2);
    assert!(!key1.contains("alice"));
    assert!(!key1.contains("key"));
    assert!(!key2.contains("tenant"));
}

#[tokio::test]
async fn test_peer_spiffe_id_scopes_logical_key() {
    let plugin = make_plugin(json!({}));

    let mut ctx1 = body_ctx("POST", "/api/orders", b"{}");
    ctx1.peer_spiffe_id = Some(
        ferrum_edge::identity::SpiffeId::new("spiffe://mesh.local/ns/blue/sa/default")
            .expect("valid SPIFFE ID"),
    );
    let mut headers1 = keyed_headers("mesh-key", "api.example", 2);
    let result = plugin.before_proxy(&mut ctx1, &mut headers1).await;
    assert!(matches!(result, PluginResult::Continue));

    let mut ctx2 = body_ctx("POST", "/api/orders", b"{}");
    ctx2.peer_spiffe_id = Some(
        ferrum_edge::identity::SpiffeId::new("spiffe://mesh.local/ns/green/sa/default")
            .expect("valid SPIFFE ID"),
    );
    let mut headers2 = keyed_headers("mesh-key", "api.example", 2);
    let result = plugin.before_proxy(&mut ctx2, &mut headers2).await;
    assert!(matches!(result, PluginResult::Continue));

    let (key1, _) = request_identity(&plugin, &ctx1).unwrap();
    let (key2, _) = request_identity(&plugin, &ctx2).unwrap();
    assert_ne!(key1, key2);
    assert!(!key1.contains("blue"));
    assert!(!key2.contains("green"));
}

#[tokio::test]
async fn test_fingerprints_and_logical_keys_do_not_expose_secrets() {
    let plugin = make_plugin(json!({}));
    let mut ctx = body_ctx("POST", "/api/orders", b"super-secret-body");
    ctx.authenticated_identity = Some("identity-secret".to_string());
    let mut headers = keyed_headers("secret-idempotency-key", "api.example", 17);
    headers.insert(
        "authorization".to_string(),
        "Bearer request-secret-token".to_string(),
    );
    headers.insert("cookie".to_string(), "session=request-secret".to_string());

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));

    let (logical_key, fingerprint) = request_identity(&plugin, &ctx).unwrap();
    assert!(logical_key.starts_with("v6:"));
    assert!(fingerprint.starts_with("sha256-"));
    for secret in [
        "super-secret-body",
        "secret-idempotency-key",
        "identity-secret",
        "request-secret-token",
        "request-secret",
    ] {
        assert!(!logical_key.contains(secret));
        assert!(!fingerprint.contains(secret));
    }
}

#[tokio::test]
async fn stable_plugin_config_identity_partitions_distributed_logical_keys() {
    let config = json!({});
    // Same stable plugin-config id on two gateways must share Redis identity
    // (cross-gateway companion contract). Distinct ids — including across
    // scopes that happen to share a proxy association — must stay partitioned.
    let first_gateway = request_deduplication_with_instance_id_for_test(
        &config,
        PluginHttpClient::default(),
        "dedup-primary",
    )
    .unwrap();
    let second_gateway = request_deduplication_with_instance_id_for_test(
        &config,
        PluginHttpClient::default(),
        "dedup-primary",
    )
    .unwrap();
    let sibling_instance = request_deduplication_with_instance_id_for_test(
        &config,
        PluginHttpClient::default(),
        "dedup-secondary",
    )
    .unwrap();
    let proxy_group_sibling = request_deduplication_with_instance_id_for_test(
        &config,
        PluginHttpClient::default(),
        "dedup-proxy-group",
    )
    .unwrap();
    let global_sibling = request_deduplication_with_instance_id_for_test(
        &config,
        PluginHttpClient::default(),
        "dedup-global",
    )
    .unwrap();

    let mut identities = Vec::new();
    for plugin in [
        &first_gateway,
        &second_gateway,
        &sibling_instance,
        &proxy_group_sibling,
        &global_sibling,
    ] {
        let mut ctx = body_ctx("POST", "/api/orders", b"{}");
        let mut headers = keyed_headers("shared-key", "api.example", 2);
        assert!(matches!(
            plugin.before_proxy(&mut ctx, &mut headers).await,
            PluginResult::Continue
        ));
        identities.push(request_identity(plugin, &ctx).unwrap());
    }

    assert_eq!(
        identities[0], identities[1],
        "the same plugin_config_id must share Redis identity across gateways"
    );
    assert_ne!(
        identities[0].0, identities[2].0,
        "sibling plugin instances must not share completed or in-flight Redis keys"
    );
    assert_ne!(
        identities[0].0, identities[3].0,
        "proxy_group-scoped config identity must remain isolated from peer instances"
    );
    assert_ne!(
        identities[0].0, identities[4].0,
        "global-scoped config identity must remain isolated from peer instances"
    );
    assert_eq!(
        identities[0].1, identities[2].1,
        "plugin instance partitioning must not alter request fingerprints"
    );
}

#[tokio::test]
async fn test_local_and_redis_modes_compute_identical_request_identity() {
    let local_plugin = make_plugin(json!({}));
    let redis_plugin = make_plugin(json!({
        "sync_mode": "redis",
        "redis_url": "redis://127.0.0.1:1/0",
        "redis_connect_timeout_seconds": 1,
        "on_redis_unavailable": "local_only"
    }));

    let mut local_ctx = body_ctx("POST", "/api/orders", b"{\"order\":1}");
    local_ctx.set_raw_query_string("expand=items".to_string());
    let mut local_headers = keyed_headers("shared-key", "api.example", 11);
    let local_result = local_plugin
        .before_proxy(&mut local_ctx, &mut local_headers)
        .await;
    assert!(matches!(local_result, PluginResult::Continue));

    let mut redis_ctx = body_ctx("POST", "/api/orders", b"{\"order\":1}");
    redis_ctx.set_raw_query_string("expand=items".to_string());
    let mut redis_headers = keyed_headers("shared-key", "api.example", 11);
    let redis_result = redis_plugin
        .before_proxy(&mut redis_ctx, &mut redis_headers)
        .await;
    assert!(matches!(redis_result, PluginResult::Continue));

    assert_eq!(
        request_identity(&local_plugin, &local_ctx).map(|identity| identity.0),
        request_identity(&redis_plugin, &redis_ctx).map(|identity| identity.0)
    );
    assert_eq!(
        request_identity(&local_plugin, &local_ctx).map(|identity| identity.1),
        request_identity(&redis_plugin, &redis_ctx).map(|identity| identity.1)
    );
}

// ---------------------------------------------------------------------------
// Replay-partition contract (GHSA-w27g-65rf-h7xm)
// ---------------------------------------------------------------------------

/// Drive one dedup lifecycle: `before_proxy` then store the completion.
async fn dedup_cycle(
    plugin: &RequestDeduplication,
    ctx: &mut RequestContext,
    body: &[u8],
) -> PluginResult {
    let mut headers = ctx.headers.clone();
    let result = plugin.before_proxy(ctx, &mut headers).await;
    if matches!(result, PluginResult::Continue) {
        plugin
            .on_final_response_body(ctx, 200, &HashMap::new(), body)
            .await;
    }
    result
}

fn dedup_ctx(client_ip: &str, key: &str) -> RequestContext {
    let mut ctx = new_ctx_from(client_ip, "POST", "/orders");
    ctx.headers
        .insert("idempotency-key".to_string(), key.to_string());
    ctx
}

#[tokio::test]
async fn dedup_isolates_same_subject_different_credential_scope() {
    let plugin = make_plugin(json!({ "ttl_seconds": 60 }));

    let mut narrow = dedup_ctx("127.0.0.1", "order-1");
    narrow.authenticated_identity = Some("alice@example.com".to_string());
    narrow.headers.insert(
        "authorization".to_string(),
        "Bearer scope-read-only".to_string(),
    );
    assert!(matches!(
        dedup_cycle(&plugin, &mut narrow, b"narrow-result").await,
        PluginResult::Continue
    ));

    // Same idempotency key, same display subject, different credential scope.
    let mut broad = dedup_ctx("127.0.0.1", "order-1");
    broad.authenticated_identity = Some("alice@example.com".to_string());
    broad.headers.insert(
        "authorization".to_string(),
        "Bearer scope-read-write-admin".to_string(),
    );
    let mut broad_headers = broad.headers.clone();
    assert!(
        matches!(
            plugin.before_proxy(&mut broad, &mut broad_headers).await,
            PluginResult::Continue
        ),
        "a different credential scope must not replay the earlier result"
    );
}

#[tokio::test]
async fn dedup_isolates_anonymous_callers_by_canonical_address() {
    let plugin = make_plugin(json!({ "ttl_seconds": 60 }));

    let mut first = dedup_ctx("203.0.113.7", "order-2");
    assert!(matches!(
        dedup_cycle(&plugin, &mut first, b"first-result").await,
        PluginResult::Continue
    ));

    let mut second = dedup_ctx("198.51.100.9", "order-2");
    let mut second_headers = second.headers.clone();
    assert!(
        matches!(
            plugin.before_proxy(&mut second, &mut second_headers).await,
            PluginResult::Continue
        ),
        "an anonymous caller at a different canonical address must not replay"
    );

    // The original caller still replays.
    let mut same = dedup_ctx("203.0.113.7", "order-2");
    let mut same_headers = same.headers.clone();
    let replay = plugin.before_proxy(&mut same, &mut same_headers).await;
    assert!(
        matches!(replay, PluginResult::RejectBinary { .. }),
        "the same canonical caller must still replay its own result"
    );
}

#[tokio::test]
async fn dedup_anonymous_caller_scope_shared_is_an_explicit_opt_out() {
    let plugin = make_plugin(json!({
        "ttl_seconds": 60,
        "anonymous_caller_scope": "shared"
    }));

    let mut first = dedup_ctx("203.0.113.7", "order-3");
    assert!(matches!(
        dedup_cycle(&plugin, &mut first, b"shared-result").await,
        PluginResult::Continue
    ));

    let mut second = dedup_ctx("198.51.100.9", "order-3");
    let mut second_headers = second.headers.clone();
    assert!(
        matches!(
            plugin.before_proxy(&mut second, &mut second_headers).await,
            PluginResult::RejectBinary { .. }
        ),
        "the explicit shared attestation must let anonymous callers share"
    );

    assert!(
        RequestDeduplication::new(
            &json!({ "anonymous_caller_scope": "everyone" }),
            PluginHttpClient::default()
        )
        .is_err(),
        "an unknown anonymous_caller_scope must fail closed"
    );
}

#[tokio::test]
async fn dedup_isolates_effective_route_destination() {
    let plugin = make_plugin(json!({ "ttl_seconds": 60 }));

    let mut tenant_a = dedup_ctx("127.0.0.1", "order-4");
    tenant_a.route_override_upstream_id = Some("tenant-a".to_string());
    assert!(matches!(
        dedup_cycle(&plugin, &mut tenant_a, b"tenant-a-result").await,
        PluginResult::Continue
    ));

    let mut tenant_b = dedup_ctx("127.0.0.1", "order-4");
    tenant_b.route_override_upstream_id = Some("tenant-b".to_string());
    let mut tenant_b_headers = tenant_b.headers.clone();
    assert!(
        matches!(
            plugin
                .before_proxy(&mut tenant_b, &mut tenant_b_headers)
                .await,
            PluginResult::Continue
        ),
        "a different effective destination must not replay"
    );
}

/// The origin receives Ferrum's regenerated forwarding identity for an
/// authenticated caller too, so an idempotent operation claimed from one
/// address must not be replayable from another.
#[tokio::test]
async fn dedup_isolates_authenticated_callers_by_canonical_address() {
    let plugin = make_plugin(json!({ "ttl_seconds": 60 }));

    let mut office = dedup_ctx("203.0.113.7", "order-addr-1");
    office.authenticated_identity = Some("alice@example.com".to_string());
    office.headers.insert(
        "authorization".to_string(),
        "Bearer alice-token".to_string(),
    );
    assert!(matches!(
        dedup_cycle(&plugin, &mut office, b"office-result").await,
        PluginResult::Continue
    ));

    let mut cafe = dedup_ctx("198.51.100.9", "order-addr-1");
    cafe.authenticated_identity = Some("alice@example.com".to_string());
    cafe.headers.insert(
        "authorization".to_string(),
        "Bearer alice-token".to_string(),
    );
    let mut cafe_headers = cafe.headers.clone();
    assert!(
        matches!(
            plugin.before_proxy(&mut cafe, &mut cafe_headers).await,
            PluginResult::Continue
        ),
        "one authenticated caller at two canonical addresses must not replay"
    );
}

/// `anonymous_caller_scope: shared` attests about anonymous callers only.
#[tokio::test]
async fn dedup_shared_anonymous_scope_does_not_relax_authenticated_callers() {
    let plugin = make_plugin(json!({
        "ttl_seconds": 60,
        "anonymous_caller_scope": "shared"
    }));

    let mut office = dedup_ctx("203.0.113.7", "order-addr-2");
    office.authenticated_identity = Some("alice@example.com".to_string());
    office.headers.insert(
        "authorization".to_string(),
        "Bearer alice-token".to_string(),
    );
    assert!(matches!(
        dedup_cycle(&plugin, &mut office, b"office-result").await,
        PluginResult::Continue
    ));

    let mut cafe = dedup_ctx("198.51.100.9", "order-addr-2");
    cafe.authenticated_identity = Some("alice@example.com".to_string());
    cafe.headers.insert(
        "authorization".to_string(),
        "Bearer alice-token".to_string(),
    );
    let mut cafe_headers = cafe.headers.clone();
    assert!(
        matches!(
            plugin.before_proxy(&mut cafe, &mut cafe_headers).await,
            PluginResult::Continue
        ),
        "the shared attestation covers anonymous callers only"
    );
}

#[tokio::test]
async fn dedup_config_admits_anonymous_caller_scope_key() {
    for value in ["caller_address", "caller-address", "shared", " SHARED "] {
        assert!(
            RequestDeduplication::new(
                &json!({ "anonymous_caller_scope": value }),
                PluginHttpClient::default()
            )
            .is_ok(),
            "anonymous_caller_scope must accept {value:?}"
        );
    }
}
