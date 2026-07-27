use super::plugin_utils::create_test_proxy;
use ferrum_edge::_test_support::{
    ai_semantic_cache_apply_redis_quarantine_delete_outcome_for_test,
    ai_semantic_cache_cache_budget_used_for_test,
    ai_semantic_cache_clear_redis_quarantine_for_test,
    ai_semantic_cache_clear_vector_index_dirty_for_test, ai_semantic_cache_embedding,
    ai_semantic_cache_expire_all_entries_for_test,
    ai_semantic_cache_expire_redis_quarantine_for_test, ai_semantic_cache_force_cleanup_for_test,
    ai_semantic_cache_force_vector_rebuild_budget_failure_for_test,
    ai_semantic_cache_instance_id_for_test, ai_semantic_cache_maintenance_committed_for_test,
    ai_semantic_cache_maintenance_handle_count_for_test,
    ai_semantic_cache_maintenance_staged_for_test, ai_semantic_cache_notify_cleanup_for_test,
    ai_semantic_cache_redis_quarantine_cap_for_test,
    ai_semantic_cache_redis_quarantine_delete_failures_for_test,
    ai_semantic_cache_redis_quarantine_fingerprint_content_for_test,
    ai_semantic_cache_redis_quarantine_fingerprint_empty_for_test,
    ai_semantic_cache_redis_quarantine_fingerprint_oversized_for_test,
    ai_semantic_cache_redis_quarantine_is_suppressed_for_test,
    ai_semantic_cache_redis_quarantine_len_for_test,
    ai_semantic_cache_redis_quarantine_matches_active_for_test,
    ai_semantic_cache_redis_quarantine_suppressed_for_test,
    ai_semantic_cache_redis_quarantine_suppressions_for_test,
    ai_semantic_cache_redis_quarantine_ttl_for_test, ai_semantic_cache_scope_key,
    ai_semantic_cache_set_singleflight_wait_override_for_test,
    ai_semantic_cache_set_store_post_admit_hook_for_test,
    ai_semantic_cache_set_vector_index_rebuild_blocked_for_test,
    ai_semantic_cache_size_accounting_snapshot_for_test,
    ai_semantic_cache_staging_metadata_key_for_test, ai_semantic_cache_vector_index_dirty_for_test,
    ai_semantic_cache_vector_snapshot_accounted_bytes_for_test,
    apply_buffered_request_body_normalization_before_before_proxy_for_test,
    rebuild_ai_semantic_cache_vector_index, set_ai_semantic_cache_embedding,
    set_ai_semantic_cache_scope_key,
};
use ferrum_edge::config::types::Consumer;
use ferrum_edge::config::{BackendAllowIps, PoolConfig};
use ferrum_edge::dns::{DnsCache, DnsConfig};
use ferrum_edge::plugins::ai_semantic_cache::AiSemanticCache;
use ferrum_edge::plugins::compression::CompressionPlugin;
use ferrum_edge::plugins::{
    HTTP_ONLY_PROTOCOLS, Plugin, PluginHttpClient, PluginResult, RequestContext, priority,
};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Barrier};
use std::time::Duration;
use wiremock::matchers::{body_string_contains, header, method, path};
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

// Marker set by the proxy on `ctx.metadata` while the response-body hooks run
// over a synthetic 2xx plugin short-circuit body (mirrors
// `crate::proxy::SYNTHETIC_SHORT_CIRCUIT_METADATA_KEY`, which is `pub(crate)` and
// therefore not reachable from this external test crate).
const SYNTHETIC_SHORT_CIRCUIT_METADATA_KEY: &str = "ferrum:synthetic_short_circuit";

struct SingleflightWaitOverrideGuard<'a> {
    plugin: &'a AiSemanticCache,
}

impl<'a> SingleflightWaitOverrideGuard<'a> {
    fn install(plugin: &'a AiSemanticCache, wait: Duration) -> Self {
        ai_semantic_cache_set_singleflight_wait_override_for_test(plugin, Some(wait));
        Self { plugin }
    }
}

impl Drop for SingleflightWaitOverrideGuard<'_> {
    fn drop(&mut self) {
        ai_semantic_cache_set_singleflight_wait_override_for_test(self.plugin, None);
    }
}

struct ConcurrencyTrackingEmbeddingResponder {
    active: Arc<AtomicUsize>,
    peak: Arc<AtomicUsize>,
    tracking_duration: Duration,
    response_delay: Duration,
}

impl Respond for ConcurrencyTrackingEmbeddingResponder {
    fn respond(&self, _request: &Request) -> ResponseTemplate {
        let active = self.active.fetch_add(1, Ordering::AcqRel) + 1;
        self.peak.fetch_max(active, Ordering::AcqRel);

        let active_counter = Arc::clone(&self.active);
        let tracking_duration = self.tracking_duration;
        tokio::spawn(async move {
            tokio::time::sleep(tracking_duration).await;
            active_counter.fetch_sub(1, Ordering::AcqRel);
        });

        ResponseTemplate::new(200)
            .set_delay(self.response_delay)
            .set_body_json(json!({
                "data": [{"embedding": [1.0, 0.0, 0.0]}]
            }))
    }
}

fn plugin_http_client_with_ip_policy(policy: BackendAllowIps) -> PluginHttpClient {
    let policy = ferrum_edge::config::BackendEgressPolicy::from_allow_ips(policy);
    let dns_cache = DnsCache::new(DnsConfig {
        backend_allow_ips: policy.clone(),
        ..DnsConfig::default()
    });

    PluginHttpClient::new(
        &PoolConfig::default(),
        dns_cache,
        1000,
        0,
        100,
        false,
        None,
        Arc::new(Vec::new()),
        ferrum_edge::config::types::DEFAULT_NAMESPACE,
        policy,
        Arc::new(Vec::new()),
        0,
    )
}

/// Build a synthetic Consumer for cross-consumer scoping tests. Only
/// `username` matters because that's what `effective_identity()` returns
/// when `identified_consumer` is set.
fn make_consumer(username: &str) -> Arc<Consumer> {
    Arc::new(Consumer {
        id: format!("consumer-{}", username),
        namespace: ferrum_edge::config::types::default_namespace(),
        username: username.to_string(),
        custom_id: None,
        credentials: HashMap::new(),
        acl_groups: Vec::new(),
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    })
}

/// Drive a request through `before_proxy` and report whether the call
/// returned a cache HIT (`RejectBinary`) or a MISS (`Continue`).
async fn run_before_proxy_get_status(
    plugin: &AiSemanticCache,
    body_str: &str,
    consumer: Option<Arc<Consumer>>,
) -> bool {
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/v1/chat/completions".to_string(),
    );
    ctx.metadata
        .insert("request_body".to_string(), body_str.to_string());
    if let Some(c) = consumer {
        ctx.identified_consumer = Some(c);
    }
    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/json".to_string());

    matches!(
        plugin.before_proxy(&mut ctx, &mut headers).await,
        PluginResult::RejectBinary { .. }
    )
}

async fn run_before_proxy(
    plugin: &AiSemanticCache,
    body_str: &str,
    consumer: Option<Arc<Consumer>>,
) -> (RequestContext, PluginResult) {
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/v1/chat/completions".to_string(),
    );
    ctx.metadata
        .insert("request_body".to_string(), body_str.to_string());
    if let Some(c) = consumer {
        ctx.identified_consumer = Some(c);
    }
    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/json".to_string());

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    (ctx, result)
}

/// MISS+store helper: send a request through `before_proxy` (cache MISS) and
/// then write a synthetic response into the cache via `on_final_response_body`.
async fn store_response(
    plugin: &AiSemanticCache,
    body_str: &str,
    consumer: Option<Arc<Consumer>>,
    response_body: &[u8],
) {
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/v1/chat/completions".to_string(),
    );
    ctx.metadata
        .insert("request_body".to_string(), body_str.to_string());
    if let Some(c) = consumer {
        ctx.identified_consumer = Some(c);
    }
    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/json".to_string());
    let _ = plugin.before_proxy(&mut ctx, &mut headers).await;

    let mut response_headers = HashMap::new();
    response_headers.insert("content-type".to_string(), "application/json".to_string());
    let _ = plugin
        .on_final_response_body(&mut ctx, 200, &response_headers, response_body)
        .await;
    rebuild_ai_semantic_cache_vector_index(plugin).await;
}

const REDIS_INTEGRITY_KEY_FOR_TESTS: &str = "0123456789abcdef0123456789abcdef";

fn make_plugin(config: serde_json::Value) -> AiSemanticCache {
    AiSemanticCache::new(&config, PluginHttpClient::default()).unwrap()
}

fn staging_key(plugin: &AiSemanticCache, suffix: &str) -> String {
    ai_semantic_cache_staging_metadata_key_for_test(plugin, suffix)
}

fn instance_id(plugin: &AiSemanticCache) -> u64 {
    ai_semantic_cache_instance_id_for_test(plugin)
}

fn staged_status<'a>(plugin: &AiSemanticCache, ctx: &'a RequestContext) -> Option<&'a str> {
    ctx.metadata
        .get(&staging_key(plugin, "cache_status"))
        .map(String::as_str)
}

fn staged_match<'a>(plugin: &AiSemanticCache, ctx: &'a RequestContext) -> Option<&'a str> {
    ctx.metadata
        .get(&staging_key(plugin, "cache_match"))
        .map(String::as_str)
}

fn has_staged_cache_key(plugin: &AiSemanticCache, ctx: &RequestContext) -> bool {
    ctx.metadata.contains_key(&staging_key(plugin, "cache_key"))
}

fn staged_cache_key_value<'a>(
    plugin: &AiSemanticCache,
    ctx: &'a RequestContext,
) -> Option<&'a str> {
    ctx.metadata
        .get(&staging_key(plugin, "cache_key"))
        .map(String::as_str)
}

fn compress_semantic_cache_request(encoding: &str, plaintext: &[u8]) -> Vec<u8> {
    match encoding {
        "gzip" => {
            use flate2::write::GzEncoder;
            use std::io::Write;

            let mut encoder = GzEncoder::new(Vec::new(), flate2::Compression::default());
            encoder.write_all(plaintext).unwrap();
            encoder.finish().unwrap()
        }
        "br" => {
            let params = brotli::enc::BrotliEncoderParams::default();
            let mut compressed = Vec::new();
            brotli::BrotliCompress(&mut &plaintext[..], &mut compressed, &params).unwrap();
            compressed
        }
        other => panic!("unsupported test encoding {other}"),
    }
}

async fn normalize_semantic_cache_request(
    compression: &Arc<CompressionPlugin>,
    encoding: &str,
    plaintext: &[u8],
) -> (RequestContext, HashMap<String, String>, Vec<u8>) {
    let mut body = compress_semantic_cache_request(encoding, plaintext);
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/v1/chat/completions".to_string(),
    );
    ctx.headers
        .insert("content-type".to_string(), "application/json".to_string());
    ctx.headers
        .insert("content-encoding".to_string(), encoding.to_string());
    ctx.request_body_bytes = Some(bytes::Bytes::copy_from_slice(&body));
    let mut headers = ctx.headers.clone();
    headers.insert("content-length".to_string(), body.len().to_string());
    let plugins: Vec<Arc<dyn Plugin>> = vec![Arc::clone(compression) as Arc<dyn Plugin>];

    let result = apply_buffered_request_body_normalization_before_before_proxy_for_test(
        &plugins,
        &mut ctx,
        &mut headers,
        &mut body,
    )
    .await;
    ctx.headers = headers.clone();
    assert!(matches!(result, PluginResult::Continue));
    assert_eq!(body, plaintext);
    assert_eq!(
        ctx.metadata.get("request_body").map(String::as_bytes),
        Some(plaintext)
    );
    assert!(!headers.contains_key("content-encoding"));
    assert!(!headers.contains_key("content-length"));
    (ctx, headers, body)
}

async fn mount_embedding_mock(server: &MockServer, expected_calls: u64) {
    Mock::given(method("POST"))
        .and(path("/embeddings"))
        .and(header("authorization", "Bearer test-key"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": [
                {"embedding": [1.0, 0.0, 0.0]}
            ]
        })))
        .expect(expected_calls)
        .mount(server)
        .await;
}

async fn mount_embedding_mock_for_input(
    server: &MockServer,
    input_fragment: &str,
    embedding: [f32; 3],
    expected_calls: u64,
) {
    Mock::given(method("POST"))
        .and(path("/embeddings"))
        .and(header("authorization", "Bearer test-key"))
        .and(body_string_contains(input_fragment))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": [
                {"embedding": embedding}
            ]
        })))
        .expect(expected_calls)
        .mount(server)
        .await;
}

async fn mount_embedding_failure_mock(server: &MockServer, expected_calls: u64) {
    Mock::given(method("POST"))
        .and(path("/embeddings"))
        .and(header("authorization", "Bearer test-key"))
        .respond_with(ResponseTemplate::new(503).set_body_string("unavailable"))
        .expect(expected_calls)
        .mount(server)
        .await;
}

async fn mount_google_gemini_embedding_mock(server: &MockServer, expected_calls: u64) {
    Mock::given(method("POST"))
        .and(path("/embeddings"))
        .and(header("x-goog-api-key", "test-key"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "embedding": {
                "values": [1.0, 0.0, 0.0]
            }
        })))
        .expect(expected_calls)
        .mount(server)
        .await;
}

async fn mount_large_embedding_mock(server: &MockServer, expected_calls: u64) {
    let mut embedding = vec![0.0; 128];
    embedding[0] = 1.0;
    Mock::given(method("POST"))
        .and(path("/embeddings"))
        .and(header("authorization", "Bearer test-key"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": [
                {"embedding": embedding}
            ]
        })))
        .expect(expected_calls)
        .mount(server)
        .await;
}

fn semantic_config(server: &MockServer) -> serde_json::Value {
    json!({
        "semantic_similarity_enabled": true,
        "semantic_embedding_endpoint": format!("{}/embeddings", server.uri()),
        "semantic_embedding_model": "test-embedding-model",
        "semantic_embedding_api_key": "test-key",
        "semantic_similarity_threshold": 0.95
    })
}

fn multimodal_body(part: Value) -> Value {
    json!({
        "model": "gpt-4o",
        "messages": [{
            "role": "user",
            "content": [
                {"type": "text", "text": "What is in this image?"},
                part
            ]
        }]
    })
}

fn multimodal_image_url_body(url: &str) -> Value {
    multimodal_body(json!({
        "type": "image_url",
        "image_url": {
            "url": url,
            "detail": "high"
        }
    }))
}

#[test]
fn test_new_default_config() {
    let config = json!({});
    let plugin = make_plugin(config);
    assert_eq!(plugin.name(), "ai_semantic_cache");
    assert_eq!(plugin.priority(), priority::AI_SEMANTIC_CACHE);
    assert_eq!(plugin.supported_protocols(), HTTP_ONLY_PROTOCOLS);
    assert!(plugin.requires_request_body_before_before_proxy());
    assert!(plugin.requires_response_body_buffering());
    assert!(!plugin.modifies_request_headers());
    assert!(!plugin.modifies_request_body());
    assert!(!plugin.is_auth_plugin());
}

#[test]
fn test_new_custom_config() {
    let config = json!({
        "ttl_seconds": 600,
        "max_entries": 5000,
        "max_entry_size_bytes": 524288,
        "max_total_size_bytes": 52428800,
        "include_model_in_key": true,
        "include_params_in_key": true,
        "scope_by_consumer": true
    });
    let plugin = make_plugin(config);
    assert_eq!(plugin.name(), "ai_semantic_cache");
}

#[test]
fn test_new_zero_ttl_fails() {
    let config = json!({"ttl_seconds": 0});
    let result = AiSemanticCache::new(&config, PluginHttpClient::default());
    assert!(result.is_err());
    assert!(result.err().unwrap().contains("ttl_seconds"));
}

#[test]
fn test_new_invalid_config_shapes_fail() {
    for config in [
        json!("bad"),
        json!({"ttl_seconds": "300"}),
        json!({"max_entries": 0}),
        json!({"max_entries": "100"}),
        json!({"max_entry_size_bytes": 0}),
        json!({"max_total_size_bytes": "1000"}),
        json!({"include_model_in_key": "true"}),
        json!({"include_params_in_key": "true"}),
        json!({"scope_by_consumer": "false"}),
        json!({"cache_multimodal": true}),
        json!({"cache_multimodal": ""}),
        json!({"cache_multimodal": "bad"}),
        json!({"semantic_similarity_enabled": "true"}),
        json!({"semantic_similarity_enabled": true}),
        json!({"semantic_similarity_enabled": true, "semantic_embedding_endpoint": "not a url"}),
        json!({"semantic_similarity_enabled": true, "semantic_embedding_endpoint": "file:///tmp/embed"}),
        json!({"semantic_similarity_threshold": 0.0}),
        json!({"semantic_similarity_threshold": 1.1}),
        json!({"semantic_vector_max_candidates": 0}),
        json!({"semantic_vector_max_candidates": 1025}),
        json!({"semantic_embedding_timeout_ms": 0}),
        json!({"semantic_embedding_auth_header": "bad header"}),
        json!({"semantic_embedding_provider": "bogus"}),
        json!({"semantic_embedding_provider": ""}),
        json!({"semantic_embedding_input_type": ""}),
        json!({"semantic_embedding_output_dimension": 0}),
        json!({"semantic_embedding_output_dimension": "1024"}),
    ] {
        let result = AiSemanticCache::new(&config, PluginHttpClient::default());
        assert!(result.is_err(), "config should be rejected: {config:?}");
    }
}

#[test]
fn test_semantic_endpoint_rejects_literal_ips_denied_by_backend_policy() {
    let http_client = plugin_http_client_with_ip_policy(BackendAllowIps::Public);

    for endpoint in [
        "http://127.0.0.1:12345/embeddings",
        "http://169.254.169.254/latest/meta-data/",
        "http://[::1]:12345/embeddings",
    ] {
        let result = AiSemanticCache::new(
            &json!({
                "semantic_similarity_enabled": true,
                "semantic_embedding_endpoint": endpoint,
            }),
            http_client.clone(),
        );

        let Err(error) = result else {
            panic!("literal internal endpoint should be rejected: {endpoint}");
        };
        assert!(
            error.contains("denied by backend egress policy"),
            "unexpected error for {endpoint}: {error}"
        );
    }
}

#[test]
fn test_semantic_endpoint_allows_literal_ips_permitted_by_backend_policy() {
    let public_client = plugin_http_client_with_ip_policy(BackendAllowIps::Public);
    let public_endpoint = json!({
        "semantic_similarity_enabled": true,
        "semantic_embedding_endpoint": "http://8.8.8.8/embeddings",
    });
    assert!(AiSemanticCache::new(&public_endpoint, public_client).is_ok());

    let private_client = plugin_http_client_with_ip_policy(BackendAllowIps::Private);
    let private_endpoint = json!({
        "semantic_similarity_enabled": true,
        "semantic_embedding_endpoint": "http://127.0.0.1:12345/embeddings",
    });
    assert!(AiSemanticCache::new(&private_endpoint, private_client).is_ok());
}

#[test]
fn semantic_and_redis_hostnames_participate_in_dns_warmup() {
    let embedding_only = make_plugin(json!({
        "semantic_similarity_enabled": true,
        "semantic_embedding_endpoint": "https://Embeddings.Example.COM/v1/embeddings",
    }));
    assert_eq!(
        embedding_only.warmup_hostnames(),
        vec!["embeddings.example.com".to_string()]
    );

    let redis_only = make_plugin(json!({
        "sync_mode": "redis",
        "redis_url": "redis://Cache.Example.COM:6379/0",
        "redis_integrity_key": REDIS_INTEGRITY_KEY_FOR_TESTS,
    }));
    assert_eq!(
        redis_only.warmup_hostnames(),
        vec!["cache.example.com".to_string()]
    );

    let both = make_plugin(json!({
        "semantic_similarity_enabled": true,
        "semantic_embedding_endpoint": "https://Embeddings.Example.COM/v1/embeddings",
        "sync_mode": "redis",
        "redis_url": "redis://Cache.Example.COM:6379/0",
        "redis_integrity_key": REDIS_INTEGRITY_KEY_FOR_TESTS,
    }));
    assert_eq!(
        both.warmup_hostnames(),
        vec![
            "embeddings.example.com".to_string(),
            "cache.example.com".to_string(),
        ]
    );

    let duplicate = make_plugin(json!({
        "semantic_similarity_enabled": true,
        "semantic_embedding_endpoint": "https://Shared.Example.COM/v1/embeddings",
        "sync_mode": "redis",
        "redis_url": "redis://shared.example.com:6379/0",
        "redis_integrity_key": REDIS_INTEGRITY_KEY_FOR_TESTS,
    }));
    assert_eq!(
        duplicate.warmup_hostnames(),
        vec!["shared.example.com".to_string()]
    );

    let literal_ip = make_plugin(json!({
        "semantic_similarity_enabled": true,
        "semantic_embedding_endpoint": "http://127.0.0.1:12345/embeddings",
    }));
    assert!(literal_ip.warmup_hostnames().is_empty());
}

#[test]
fn test_semantic_config_is_optional_and_valid_when_enabled() {
    let exact_only = make_plugin(json!({}));
    assert_eq!(exact_only.name(), "ai_semantic_cache");

    let semantic = make_plugin(json!({
        "semantic_similarity_enabled": true,
        "semantic_embedding_endpoint": "http://127.0.0.1:12345/embeddings",
        "semantic_embedding_model": "text-embedding-test",
        "semantic_embedding_provider": "claude",
        "semantic_embedding_input_type": "document",
        "semantic_embedding_output_dimension": 1024,
        "semantic_similarity_threshold": 0.90,
        "semantic_vector_max_candidates": 8,
        "semantic_embedding_timeout_ms": 2500
    }));
    assert_eq!(semantic.name(), "ai_semantic_cache");
}

#[test]
fn test_new_with_redis_config() {
    let config = json!({
        "sync_mode": "redis",
        "redis_url": "redis://localhost:6379/0",
        "redis_integrity_key": REDIS_INTEGRITY_KEY_FOR_TESTS,
    });
    let plugin = make_plugin(config);
    assert_eq!(plugin.name(), "ai_semantic_cache");
}

#[test]
fn validate_plugin_config_with_policy_screens_denied_redis_endpoint() {
    use ferrum_edge::config::BackendEgressPolicy;
    use ferrum_edge::plugins::validate_plugin_config_with_policy;

    // Production default policy (mode `both` + dangerous-range baseline) — the
    // file/db config-load path. A Redis-backed semantic cache pointed at the
    // cloud-metadata address must be rejected at config-load: the Redis client
    // builds from `redis_url` WITHOUT the policy and skips IP literals, so the
    // literal endpoint must be caught here.
    let default_policy =
        BackendEgressPolicy::from_env(BackendAllowIps::Both, "", "", true).expect("valid");

    let denied = json!({
        "sync_mode": "redis",
        "redis_url": "redis://169.254.169.254:6379/0",
        "redis_integrity_key": REDIS_INTEGRITY_KEY_FOR_TESTS,
    });
    assert!(
        validate_plugin_config_with_policy("ai_semantic_cache", &denied, &default_policy).is_err(),
        "metadata Redis endpoint must be rejected under the default policy"
    );

    // A loopback Redis (local cache) still validates by default.
    let loopback = json!({
        "sync_mode": "redis",
        "redis_url": "redis://127.0.0.1:6379/0",
        "redis_integrity_key": REDIS_INTEGRITY_KEY_FOR_TESTS,
    });
    assert!(
        validate_plugin_config_with_policy("ai_semantic_cache", &loopback, &default_policy).is_ok(),
        "loopback Redis must remain valid by default"
    );

    // The fully-unrestricted policy accepts the metadata endpoint (legacy posture).
    assert!(
        validate_plugin_config_with_policy(
            "ai_semantic_cache",
            &denied,
            &BackendEgressPolicy::unrestricted()
        )
        .is_ok()
    );
}

// `#[tokio::test]` because kafka_logging's constructor spawns a background
// batching-flush task, which requires a Tokio reactor.
#[tokio::test]
async fn validate_plugin_config_with_policy_screens_denied_direct_client_endpoints() {
    use ferrum_edge::config::BackendEgressPolicy;
    use ferrum_edge::plugins::validate_plugin_config_with_policy;

    // ldap_auth (ldap3 crate) and kafka_logging (librdkafka) dial their OWN
    // resolver, outside the shared PluginHttpClient + DnsCache — so a literal
    // metadata endpoint that constructs fine must still be rejected at config
    // load under the default policy (mode `both` + dangerous-range baseline).
    let default_policy =
        BackendEgressPolicy::from_env(BackendAllowIps::Both, "", "", true).expect("valid");

    let ldap_denied = json!({
        "ldap_url": "ldap://169.254.169.254:389",
        "bind_dn_template": "uid={username},dc=example,dc=com",
        "allow_plaintext": true
    });
    assert!(
        validate_plugin_config_with_policy("ldap_auth", &ldap_denied, &default_policy).is_err(),
        "metadata ldap_url must be rejected under the default policy"
    );

    let ldap_loopback = json!({
        "ldap_url": "ldap://127.0.0.1:389",
        "bind_dn_template": "uid={username},dc=example,dc=com"
    });
    assert!(
        validate_plugin_config_with_policy("ldap_auth", &ldap_loopback, &default_policy).is_ok(),
        "loopback ldap_url must remain valid by default"
    );

    // A comma-separated broker_list with a denied broker (alongside an allowed
    // RFC1918 one) is rejected — the screen checks every entry.
    let kafka_denied = json!({
        "broker_list": "10.0.0.1:9092,169.254.169.254:9092",
        "topic": "logs"
    });
    assert!(
        validate_plugin_config_with_policy("kafka_logging", &kafka_denied, &default_policy)
            .is_err(),
        "a metadata broker in broker_list must be rejected under the default policy"
    );

    let kafka_loopback = json!({
        "broker_list": "127.0.0.1:9092",
        "topic": "logs"
    });
    assert!(
        validate_plugin_config_with_policy("kafka_logging", &kafka_loopback, &default_policy)
            .is_err(),
        "kafka_logging must be refused under policies that can deny any address because \
         librdkafka cannot enforce metadata-advertised broker dials"
    );

    // ws_logging dials its endpoint_url via tungstenite (outside the shared
    // client); a literal metadata endpoint must be rejected before the flush
    // loop spawns.
    let ws_denied = json!({ "endpoint_url": "ws://169.254.169.254/logs" });
    assert!(
        validate_plugin_config_with_policy("ws_logging", &ws_denied, &default_policy).is_err(),
        "metadata ws_logging endpoint_url must be rejected under the default policy"
    );
    let ws_loopback = json!({ "endpoint_url": "ws://127.0.0.1:9000/logs" });
    assert!(
        validate_plugin_config_with_policy("ws_logging", &ws_loopback, &default_policy).is_ok(),
        "loopback ws_logging endpoint must remain valid by default"
    );

    // The fully-unrestricted policy accepts all (legacy posture).
    assert!(
        validate_plugin_config_with_policy(
            "ws_logging",
            &ws_denied,
            &BackendEgressPolicy::unrestricted()
        )
        .is_ok()
    );
    assert!(
        validate_plugin_config_with_policy(
            "ldap_auth",
            &ldap_denied,
            &BackendEgressPolicy::unrestricted()
        )
        .is_ok()
    );
    assert!(
        validate_plugin_config_with_policy(
            "kafka_logging",
            &kafka_denied,
            &BackendEgressPolicy::unrestricted()
        )
        .is_ok()
    );
}

#[test]
fn test_requires_response_body_buffering() {
    let config = json!({});
    let plugin = make_plugin(config);
    assert!(plugin.requires_response_body_buffering());
}

#[tokio::test]
async fn test_response_buffering_only_for_cache_misses() {
    let config = json!({});
    let plugin = make_plugin(config);

    let mut get_ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/v1/chat/completions".to_string(),
    );
    let mut get_headers = HashMap::new();
    get_headers.insert("content-type".to_string(), "application/json".to_string());
    let result = plugin.before_proxy(&mut get_ctx, &mut get_headers).await;
    assert!(matches!(result, PluginResult::Continue));
    assert!(!plugin.should_buffer_response_body(&get_ctx));

    let mut json_post_ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/v1/chat/completions".to_string(),
    );
    json_post_ctx.metadata.insert(
        "request_body".to_string(),
        json!({
            "model": "gpt-4o",
            "messages": [{"role": "user", "content": "hello"}]
        })
        .to_string(),
    );
    let mut json_post_headers = HashMap::new();
    json_post_headers.insert("content-type".to_string(), "application/json".to_string());
    let result = plugin
        .before_proxy(&mut json_post_ctx, &mut json_post_headers)
        .await;
    assert!(matches!(result, PluginResult::Continue));
    assert!(plugin.should_buffer_response_body(&json_post_ctx));
}

#[tokio::test]
async fn test_response_buffering_releases_streaming_ai_responses() {
    let config = json!({});
    let plugin = make_plugin(config);

    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/v1/chat/completions".to_string(),
    );
    ctx.metadata.insert(
        "request_body".to_string(),
        json!({
            "model": "gpt-4o",
            "stream": true,
            "messages": [{"role": "user", "content": "hello"}]
        })
        .to_string(),
    );
    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/json".to_string());
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

#[test]
fn test_requires_request_body() {
    let config = json!({});
    let plugin = make_plugin(config);
    assert!(plugin.requires_request_body_before_before_proxy());
}

#[tokio::test]
async fn test_cache_miss_then_hit() {
    let config = json!({"ttl_seconds": 300});
    let plugin = make_plugin(config);

    let body_json = json!({
        "model": "gpt-4o",
        "messages": [
            {"role": "user", "content": "What is the capital of France?"}
        ]
    });
    let body_str = serde_json::to_string(&body_json).unwrap();

    // First request — cache MISS
    let mut ctx1 = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/v1/chat/completions".to_string(),
    );
    ctx1.metadata
        .insert("request_body".to_string(), body_str.clone());
    let mut headers1 = HashMap::new();
    headers1.insert("content-type".to_string(), "application/json".to_string());

    let result = plugin.before_proxy(&mut ctx1, &mut headers1).await;
    assert!(matches!(result, PluginResult::Continue));
    assert_eq!(staged_status(&plugin, &ctx1).unwrap(), "MISS");
    assert!(has_staged_cache_key(&plugin, &ctx1));

    // Simulate caching the response
    let response_body = br#"{"choices":[{"message":{"content":"Paris"}}],"usage":{"prompt_tokens":10,"completion_tokens":5}}"#;
    let mut response_headers = HashMap::new();
    response_headers.insert("content-type".to_string(), "application/json".to_string());

    let _ = plugin
        .on_final_response_body(&mut ctx1, 200, &response_headers, response_body)
        .await;

    // Second request with same prompt — cache HIT
    let mut ctx2 = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/v1/chat/completions".to_string(),
    );
    ctx2.metadata
        .insert("request_body".to_string(), body_str.clone());
    let mut headers2 = HashMap::new();
    headers2.insert("content-type".to_string(), "application/json".to_string());

    let result = plugin.before_proxy(&mut ctx2, &mut headers2).await;
    match result {
        PluginResult::RejectBinary {
            status_code,
            headers,
            body,
            ..
        } => {
            assert_eq!(status_code, 200);
            assert_eq!(headers.get("x-ai-cache-status").unwrap(), "HIT");
            assert_eq!(&body[..], response_body);
        }
        _ => panic!("Expected cache HIT (RejectBinary), got {:?}", result),
    }
}

#[tokio::test]
async fn configured_decompression_preserves_semantic_cache_miss_store_hit_lifecycle() {
    let body = serde_json::to_vec(&json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "compressed cache identity"}]
    }))
    .unwrap();
    let response_body = br#"{"choices":[{"message":{"content":"cached"}}]}"#;

    for encoding in ["gzip", "br"] {
        let cache = make_plugin(json!({"ttl_seconds": 300}));
        let compression =
            Arc::new(CompressionPlugin::new(&json!({"decompress_request": true})).unwrap());

        let (mut first_ctx, mut first_headers, first_body) =
            normalize_semantic_cache_request(&compression, encoding, &body).await;
        assert_eq!(first_body, body);
        let first = cache.before_proxy(&mut first_ctx, &mut first_headers).await;
        assert!(matches!(first, PluginResult::Continue));
        assert_eq!(staged_status(&cache, &first_ctx), Some("MISS"));

        let response_headers =
            HashMap::from([("content-type".to_string(), "application/json".to_string())]);
        let stored = cache
            .on_final_response_body(&mut first_ctx, 200, &response_headers, response_body)
            .await;
        assert!(matches!(stored, PluginResult::Continue));

        let (mut retry_ctx, mut retry_headers, retry_body) =
            normalize_semantic_cache_request(&compression, encoding, &body).await;
        assert_eq!(retry_body, body);
        match cache.before_proxy(&mut retry_ctx, &mut retry_headers).await {
            PluginResult::RejectBinary {
                status_code,
                headers,
                body: cached_body,
                ..
            } => {
                assert_eq!(status_code, 200);
                assert_eq!(
                    headers.get("x-ai-cache-status").map(String::as_str),
                    Some("HIT")
                );
                assert_eq!(cached_body.as_ref(), response_body);
            }
            other => panic!("expected {encoding} cache HIT after normalization, got {other:?}"),
        }
    }
}

// Regression: a synthetic short-circuit 2xx body (produced by a LATER
// before_proxy plugin such as `ai_federation` / `mesh_route_dispatch` /
// `response_mock` / `serverless_function`, all of which run AFTER this plugin)
// must NOT be stored under the cache key that this plugin set on its own MISS.
// Storing it would replay a locally-generated body — that never reached the
// upstream model — to every future semantically-similar request (cache
// poisoning). The proxy marks the context with the synthetic short-circuit key
// for the duration of the response-body-hook phase; emulate that here.
#[tokio::test]
async fn synthetic_short_circuit_2xx_is_not_stored_in_semantic_cache() {
    let config = json!({"ttl_seconds": 300});
    let plugin = make_plugin(config);

    let body_json = json!({
        "model": "gpt-4o",
        "messages": [
            {"role": "user", "content": "What is the capital of France?"}
        ]
    });
    let body_str = serde_json::to_string(&body_json).unwrap();

    // First request — cache MISS. This stages the instance cache_key, which is exactly
    // what would still be set when a later plugin's synthetic 2xx flows back
    // through `on_final_response_body`.
    let mut ctx1 = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/v1/chat/completions".to_string(),
    );
    ctx1.metadata
        .insert("request_body".to_string(), body_str.clone());
    let mut headers1 = HashMap::new();
    headers1.insert("content-type".to_string(), "application/json".to_string());

    let result = plugin.before_proxy(&mut ctx1, &mut headers1).await;
    assert!(matches!(result, PluginResult::Continue));
    assert_eq!(staged_status(&plugin, &ctx1).unwrap(), "MISS");
    assert!(has_staged_cache_key(&plugin, &ctx1));

    // A later before_proxy plugin short-circuits with a synthetic 2xx body. The
    // proxy sets the synthetic marker before running the response-body hooks.
    ctx1.metadata.insert(
        SYNTHETIC_SHORT_CIRCUIT_METADATA_KEY.to_string(),
        "true".to_string(),
    );
    let synthetic_body = br#"{"choices":[{"message":{"content":"SYNTHETIC"}}],"usage":{"prompt_tokens":10,"completion_tokens":5}}"#;
    let mut response_headers = HashMap::new();
    response_headers.insert("content-type".to_string(), "application/json".to_string());

    let result = plugin
        .on_final_response_body(&mut ctx1, 200, &response_headers, synthetic_body)
        .await;
    assert!(
        matches!(result, PluginResult::Continue),
        "synthetic body hook must Continue, got {result:?}"
    );

    // Nothing was stored — the cache is still empty.
    assert_eq!(
        plugin.tracked_keys_count(),
        Some(0),
        "synthetic short-circuit body must not be written to the semantic cache"
    );

    // A second, IDENTICAL request must therefore be a MISS (Continue), not a HIT
    // replaying the synthetic body. (No synthetic marker this time — a genuine
    // fresh request.)
    let mut ctx2 = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/v1/chat/completions".to_string(),
    );
    ctx2.metadata
        .insert("request_body".to_string(), body_str.clone());
    let mut headers2 = HashMap::new();
    headers2.insert("content-type".to_string(), "application/json".to_string());

    let result = plugin.before_proxy(&mut ctx2, &mut headers2).await;
    assert!(
        matches!(result, PluginResult::Continue),
        "request matching a synthetic short-circuit must MISS, not replay a poisoned cache entry; got {result:?}"
    );
    assert_eq!(staged_status(&plugin, &ctx2), Some("MISS"));
}

// Control: a GENUINE backend response (no synthetic marker) on a MISS IS stored
// and replayed on the next identical request. Guards against the synthetic skip
// accidentally disabling normal caching.
#[tokio::test]
async fn genuine_backend_response_is_still_stored_without_synthetic_marker() {
    let config = json!({"ttl_seconds": 300});
    let plugin = make_plugin(config);

    let body_json = json!({
        "model": "gpt-4o",
        "messages": [
            {"role": "user", "content": "What is the capital of Spain?"}
        ]
    });
    let body_str = serde_json::to_string(&body_json).unwrap();

    let mut ctx1 = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/v1/chat/completions".to_string(),
    );
    ctx1.metadata
        .insert("request_body".to_string(), body_str.clone());
    let mut headers1 = HashMap::new();
    headers1.insert("content-type".to_string(), "application/json".to_string());

    let result = plugin.before_proxy(&mut ctx1, &mut headers1).await;
    assert!(matches!(result, PluginResult::Continue));
    assert!(has_staged_cache_key(&plugin, &ctx1));

    // No synthetic marker: a real backend 2xx.
    let backend_body = br#"{"choices":[{"message":{"content":"Madrid"}}]}"#;
    let mut response_headers = HashMap::new();
    response_headers.insert("content-type".to_string(), "application/json".to_string());
    let _ = plugin
        .on_final_response_body(&mut ctx1, 200, &response_headers, backend_body)
        .await;

    assert_eq!(
        plugin.tracked_keys_count(),
        Some(1),
        "a genuine backend response must be cached normally"
    );

    let mut ctx2 = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/v1/chat/completions".to_string(),
    );
    ctx2.metadata
        .insert("request_body".to_string(), body_str.clone());
    let mut headers2 = HashMap::new();
    headers2.insert("content-type".to_string(), "application/json".to_string());

    let result = plugin.before_proxy(&mut ctx2, &mut headers2).await;
    match result {
        PluginResult::RejectBinary {
            status_code, body, ..
        } => {
            assert_eq!(status_code, 200);
            assert_eq!(&body[..], backend_body);
        }
        _ => panic!("Expected cache HIT for genuine backend response, got {result:?}"),
    }
}

#[tokio::test]
async fn exact_cache_key_differs_for_different_image_url() {
    let plugin = make_plugin(json!({"ttl_seconds": 300}));

    let body_a = multimodal_image_url_body("https://example.com/a.png");
    let body_b = multimodal_image_url_body("https://example.com/b.png");

    store_response(
        &plugin,
        &serde_json::to_string(&body_a).unwrap(),
        None,
        br#""A""#,
    )
    .await;

    let body_b_str = serde_json::to_string(&body_b).unwrap();
    let (mut ctx_b, result) = run_before_proxy(&plugin, &body_b_str, None).await;
    assert!(
        matches!(result, PluginResult::Continue),
        "different image_url must exact-miss instead of replaying cached response A"
    );
    assert_eq!(staged_status(&plugin, &ctx_b), Some("MISS"));

    let mut response_headers = HashMap::new();
    response_headers.insert("content-type".to_string(), "application/json".to_string());
    let _ = plugin
        .on_final_response_body(&mut ctx_b, 200, &response_headers, br#""B""#)
        .await;

    let (_, result) = run_before_proxy(&plugin, &body_b_str, None).await;
    match result {
        PluginResult::RejectBinary { body, .. } => {
            assert_eq!(&body[..], br#""B""#);
        }
        other => panic!("Expected exact cache HIT for request B, got {other:?}"),
    }
}

#[tokio::test]
async fn exact_cache_key_differs_for_base64_audio_and_file_parts() {
    let cases = [
        (
            "base64 image_url",
            multimodal_body(json!({
                "type": "image_url",
                "image_url": {
                    "url": "data:image/png;base64,QUFB",
                    "detail": "high"
                }
            })),
            multimodal_body(json!({
                "type": "image_url",
                "image_url": {
                    "url": "data:image/png;base64,QkJC",
                    "detail": "high"
                }
            })),
        ),
        (
            "input_audio",
            multimodal_body(json!({
                "type": "input_audio",
                "input_audio": {
                    "data": "QUFB",
                    "format": "wav"
                }
            })),
            multimodal_body(json!({
                "type": "input_audio",
                "input_audio": {
                    "data": "QkJC",
                    "format": "wav"
                }
            })),
        ),
        (
            "file_id",
            multimodal_body(json!({
                "type": "file",
                "file": {
                    "file_id": "file-a"
                }
            })),
            multimodal_body(json!({
                "type": "file",
                "file": {
                    "file_id": "file-b"
                }
            })),
        ),
    ];

    for (name, body_a, body_b) in cases {
        let plugin = make_plugin(json!({"ttl_seconds": 300}));
        store_response(
            &plugin,
            &serde_json::to_string(&body_a).unwrap(),
            None,
            br#""A""#,
        )
        .await;

        let (_, result) =
            run_before_proxy(&plugin, &serde_json::to_string(&body_b).unwrap(), None).await;
        assert!(
            matches!(result, PluginResult::Continue),
            "{name} content must exact-miss instead of replaying cached response A"
        );
    }
}

#[tokio::test]
async fn exact_cache_key_treats_mixed_case_text_type_as_non_text() {
    // A content part typed lowercase "text" is folded into the message text and
    // is NOT fingerprinted; a part typed mixed-case "Text" must be treated as a
    // non-text part (case-sensitive, matching extract_message_content /
    // normalize_system_value), so it IS fingerprinted and CHANGES the exact key.
    let plugin = make_plugin(json!({"ttl_seconds": 300}));

    let lowercase_body = json!({
        "model": "gpt-4o",
        "messages": [{
            "role": "user",
            "content": [
                {"type": "text", "text": "What is in this image?"},
                {"type": "text", "text": "describe it"}
            ]
        }]
    });
    let mixed_case_body = json!({
        "model": "gpt-4o",
        "messages": [{
            "role": "user",
            "content": [
                {"type": "text", "text": "What is in this image?"},
                {"type": "Text", "text": "describe it"}
            ]
        }]
    });

    store_response(
        &plugin,
        &serde_json::to_string(&lowercase_body).unwrap(),
        None,
        br#""A""#,
    )
    .await;

    let (ctx_mixed, result) = run_before_proxy(
        &plugin,
        &serde_json::to_string(&mixed_case_body).unwrap(),
        None,
    )
    .await;
    assert!(
        matches!(result, PluginResult::Continue),
        "mixed-case \"Text\" part must be fingerprinted (non-text) and exact-miss vs lowercase \"text\""
    );
    assert_eq!(staged_status(&plugin, &ctx_mixed), Some("MISS"));
}

#[tokio::test]
async fn exact_cache_key_treats_text_type_without_string_text_as_non_text() {
    // A part typed "text" but lacking a usable string `text` field (e.g.
    // `{"type": "text", "text": 123}`) is NOT folded into the message text by
    // `extract_message_content`, so it must also be treated as non-text by the
    // fingerprint and folded into the exact key. Otherwise such parts land in a
    // seam (skipped by both halves) and two requests differing only in that
    // part would collide. Here the two bodies differ ONLY in the non-string
    // `text` value of that malformed part, so the difference can ONLY surface
    // through the multimodal fingerprint.
    let plugin = make_plugin(json!({"ttl_seconds": 300}));

    let body_a = json!({
        "model": "gpt-4o",
        "messages": [{
            "role": "user",
            "content": [
                {"type": "text", "text": "describe it"},
                {"type": "text", "text": 123}
            ]
        }]
    });
    let body_b = json!({
        "model": "gpt-4o",
        "messages": [{
            "role": "user",
            "content": [
                {"type": "text", "text": "describe it"},
                {"type": "text", "text": 456}
            ]
        }]
    });

    store_response(
        &plugin,
        &serde_json::to_string(&body_a).unwrap(),
        None,
        br#""A""#,
    )
    .await;

    let (ctx_b, result) =
        run_before_proxy(&plugin, &serde_json::to_string(&body_b).unwrap(), None).await;
    assert!(
        matches!(result, PluginResult::Continue),
        "a \"text\"-typed part without a string `text` must be fingerprinted, so a differing non-string value is an exact MISS"
    );
    assert_eq!(
        staged_status(&plugin, &ctx_b),
        Some("MISS"),
        "bodies differing only in a malformed text part's value must not collide"
    );
}

#[tokio::test]
async fn semantic_cache_scope_differs_for_different_image_url() {
    let mock_server = MockServer::start().await;
    mount_embedding_mock(&mock_server, 2).await;
    let mut config = semantic_config(&mock_server);
    config["cache_multimodal"] = json!("include_fingerprints");
    let plugin = make_plugin(config);

    let body_a = multimodal_image_url_body("https://example.com/a.png");
    let body_b = multimodal_image_url_body("https://example.com/b.png");

    store_response(
        &plugin,
        &serde_json::to_string(&body_a).unwrap(),
        None,
        br#""A""#,
    )
    .await;

    let (ctx_b, result) =
        run_before_proxy(&plugin, &serde_json::to_string(&body_b).unwrap(), None).await;
    assert!(
        matches!(result, PluginResult::Continue),
        "semantic scope must include image fingerprint and miss different image_url"
    );
    assert_eq!(staged_status(&plugin, &ctx_b), Some("MISS"));
}

#[tokio::test]
async fn cache_does_not_store_raw_multimodal_url_in_metadata() {
    let mock_server = MockServer::start().await;
    mount_embedding_mock(&mock_server, 1).await;
    let mut config = semantic_config(&mock_server);
    config["cache_multimodal"] = json!("include_fingerprints");
    let plugin = make_plugin(config);

    let url = "https://example.com/private-image.png?token=secret";
    let body = multimodal_image_url_body(url);
    let (ctx, result) =
        run_before_proxy(&plugin, &serde_json::to_string(&body).unwrap(), None).await;
    assert!(matches!(result, PluginResult::Continue));

    for key in [
        staging_key(&plugin, "cache_key"),
        staging_key(&plugin, "cache_status"),
        staging_key(&plugin, "cache_match"),
    ] {
        if let Some(value) = ctx.metadata.get(&key) {
            assert!(
                !value.contains(url),
                "plugin metadata key {key} must not contain raw multimodal URL"
            );
            assert!(
                !value.contains("private-image.png"),
                "plugin metadata key {key} must not contain raw multimodal URL path"
            );
        }
    }
    if let Some(scope_key) = ai_semantic_cache_scope_key(&ctx, instance_id(&plugin)) {
        assert!(!scope_key.contains(url));
        assert!(!scope_key.contains("private-image.png"));
    }
}

#[tokio::test]
async fn scope_by_consumer_false_still_does_not_cross_replay_multimodal() {
    let mock_server = MockServer::start().await;
    mount_embedding_mock(&mock_server, 2).await;
    let mut config = semantic_config(&mock_server);
    config["scope_by_consumer"] = json!(false);
    config["cache_multimodal"] = json!("include_fingerprints");
    let plugin = make_plugin(config);
    let alice = make_consumer("alice");
    let bob = make_consumer("bob");

    let body_a = multimodal_image_url_body("https://example.com/a.png");
    let body_b = multimodal_image_url_body("https://example.com/b.png");

    store_response(
        &plugin,
        &serde_json::to_string(&body_a).unwrap(),
        Some(alice),
        br#""alice-image-answer""#,
    )
    .await;

    let (ctx_b, result) =
        run_before_proxy(&plugin, &serde_json::to_string(&body_b).unwrap(), Some(bob)).await;
    assert!(
        matches!(result, PluginResult::Continue),
        "multimodal fingerprint must prevent cross-replay even when consumer scoping is disabled"
    );
    assert_eq!(staged_status(&plugin, &ctx_b), Some("MISS"));
}

#[tokio::test]
async fn cache_multimodal_reject_bypasses_multimodal_and_text_only_still_caches() {
    let plugin = make_plugin(json!({
        "ttl_seconds": 300,
        "cache_multimodal": "reject"
    }));

    let body = multimodal_image_url_body("https://example.com/a.png");
    let body_str = serde_json::to_string(&body).unwrap();
    let (mut ctx, result) = run_before_proxy(&plugin, &body_str, None).await;
    assert!(matches!(result, PluginResult::Continue));
    assert_eq!(staged_status(&plugin, &ctx), Some("BYPASS"));
    assert!(
        !has_staged_cache_key(&plugin, &ctx),
        "reject-mode multimodal bypass must not mark the response for storage"
    );

    let mut response_headers = HashMap::new();
    response_headers.insert("content-type".to_string(), "application/json".to_string());
    let _ = plugin
        .on_final_response_body(&mut ctx, 200, &response_headers, br#""A""#)
        .await;
    assert_eq!(plugin.tracked_keys_count(), Some(0));

    let (ctx, result) = run_before_proxy(&plugin, &body_str, None).await;
    assert!(matches!(result, PluginResult::Continue));
    assert_eq!(staged_status(&plugin, &ctx), Some("BYPASS"));
    assert_eq!(
        plugin.tracked_keys_count(),
        Some(0),
        "second identical multimodal request must still bypass instead of hitting stored data"
    );

    let text_body = json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "What is the capital of France?"}]
    });
    let text_body_str = serde_json::to_string(&text_body).unwrap();
    store_response(&plugin, &text_body_str, None, br#""Paris""#).await;

    let (_, result) = run_before_proxy(&plugin, &text_body_str, None).await;
    match result {
        PluginResult::RejectBinary { body, .. } => assert_eq!(&body[..], br#""Paris""#),
        other => panic!("Expected text-only exact cache HIT under reject mode, got {other:?}"),
    }
}

#[tokio::test]
async fn exact_only_multimodal_skips_semantic_embedding_call() {
    let mock_server = MockServer::start().await;
    mount_embedding_mock(&mock_server, 0).await;
    let plugin = make_plugin(semantic_config(&mock_server));

    let body = multimodal_image_url_body("https://example.com/a.png");
    let (ctx, result) =
        run_before_proxy(&plugin, &serde_json::to_string(&body).unwrap(), None).await;

    assert!(matches!(result, PluginResult::Continue));
    assert_eq!(staged_status(&plugin, &ctx), Some("MISS"));
    assert!(
        ai_semantic_cache_embedding(&ctx, instance_id(&plugin)).is_none(),
        "default exact_only mode must not compute text-only embeddings for multimodal requests"
    );
    assert!(
        ai_semantic_cache_scope_key(&ctx, instance_id(&plugin)).is_none(),
        "default exact_only mode must not store semantic scope for multimodal requests"
    );
}

#[tokio::test]
async fn test_semantic_similarity_hit_after_exact_miss() {
    let mock_server = MockServer::start().await;
    mount_embedding_mock(&mock_server, 2).await;
    let plugin = make_plugin(semantic_config(&mock_server));

    let body1 = json!({
        "model": "gpt-4o",
        "messages": [
            {"role": "user", "content": "What is the capital of France?"}
        ]
    });
    let body2 = json!({
        "model": "gpt-4o",
        "messages": [
            {"role": "user", "content": "Which city is France's capital?"}
        ]
    });

    store_response(
        &plugin,
        &serde_json::to_string(&body1).unwrap(),
        None,
        br#""Paris""#,
    )
    .await;

    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/v1/chat/completions".to_string(),
    );
    ctx.metadata.insert(
        "request_body".to_string(),
        serde_json::to_string(&body2).unwrap(),
    );
    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/json".to_string());

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    match result {
        PluginResult::RejectBinary { headers, body, .. } => {
            assert_eq!(
                headers.get("x-ai-cache-status").map(String::as_str),
                Some("HIT")
            );
            assert_eq!(
                headers.get("x-ai-cache-match").map(String::as_str),
                Some("semantic")
            );
            assert_eq!(&body[..], br#""Paris""#);
            assert_eq!(staged_match(&plugin, &ctx), Some("semantic"));
        }
        _ => panic!(
            "Expected semantic cache HIT (RejectBinary), got {:?}",
            result
        ),
    }
}

#[tokio::test]
async fn test_semantic_similarity_miss_below_threshold() {
    let mock_server = MockServer::start().await;
    mount_embedding_mock_for_input(&mock_server, "vector seed one", [1.0, 0.0, 0.0], 1).await;
    mount_embedding_mock_for_input(&mock_server, "vector seed two", [0.0, 1.0, 0.0], 1).await;
    let plugin = make_plugin(semantic_config(&mock_server));

    let body1 = json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "Vector seed one"}]
    });
    let body2 = json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "Vector seed two"}]
    });

    store_response(
        &plugin,
        &serde_json::to_string(&body1).unwrap(),
        None,
        br#""first""#,
    )
    .await;

    let hit =
        run_before_proxy_get_status(&plugin, &serde_json::to_string(&body2).unwrap(), None).await;
    assert!(
        !hit,
        "orthogonal embeddings should miss when below semantic_similarity_threshold"
    );
}

#[tokio::test]
async fn test_semantic_embedding_failure_falls_back_to_miss() {
    let mock_server = MockServer::start().await;
    mount_embedding_failure_mock(&mock_server, 1).await;
    let plugin = make_plugin(semantic_config(&mock_server));

    let body = json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "Will the embedding endpoint fail?"}]
    });
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/v1/chat/completions".to_string(),
    );
    ctx.metadata.insert(
        "request_body".to_string(),
        serde_json::to_string(&body).unwrap(),
    );
    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/json".to_string());

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
    assert_eq!(staged_status(&plugin, &ctx), Some("MISS"));

    let mut response_headers = HashMap::new();
    response_headers.insert("content-type".to_string(), "application/json".to_string());
    let _ = plugin
        .on_final_response_body(&mut ctx, 200, &response_headers, br#""backend""#)
        .await;
    assert_eq!(plugin.tracked_keys_count(), Some(1));
}

#[tokio::test]
async fn test_semantic_similarity_respects_response_shaping_scope() {
    let mock_server = MockServer::start().await;
    mount_embedding_mock(&mock_server, 2).await;
    let plugin = make_plugin(semantic_config(&mock_server));

    let body1 = json!({
        "model": "gpt-4o",
        "n": 1,
        "stop": ["END"],
        "messages": [{"role": "user", "content": "Summarize this response-shape case."}]
    });
    let body2 = json!({
        "model": "gpt-4o",
        "n": 2,
        "stop": ["DONE"],
        "messages": [{"role": "user", "content": "Summarize that response-shape case."}]
    });

    store_response(
        &plugin,
        &serde_json::to_string(&body1).unwrap(),
        None,
        br#""one-choice""#,
    )
    .await;

    let hit =
        run_before_proxy_get_status(&plugin, &serde_json::to_string(&body2).unwrap(), None).await;
    assert!(
        !hit,
        "semantic hit must not cross response-shaping parameters"
    );
}

#[tokio::test]
async fn test_semantic_similarity_respects_system_message_scope() {
    let mock_server = MockServer::start().await;
    mount_embedding_mock(&mock_server, 2).await;
    let plugin = make_plugin(semantic_config(&mock_server));

    let body1 = json!({
        "model": "gpt-4o",
        "messages": [
            {"role": "system", "content": "Return JSON only."},
            {"role": "user", "content": "What is the capital of France?"}
        ]
    });
    let body2 = json!({
        "model": "gpt-4o",
        "messages": [
            {"role": "system", "content": "Return plain text only."},
            {"role": "user", "content": "Which city is France's capital?"}
        ]
    });

    store_response(
        &plugin,
        &serde_json::to_string(&body1).unwrap(),
        None,
        br#"{"answer":"Paris"}"#,
    )
    .await;

    let hit =
        run_before_proxy_get_status(&plugin, &serde_json::to_string(&body2).unwrap(), None).await;
    assert!(
        !hit,
        "semantic cache must not cross system/developer instruction scopes"
    );
}

#[tokio::test]
async fn test_google_gemini_semantic_provider_uses_provider_response_shape() {
    let mock_server = MockServer::start().await;
    mount_google_gemini_embedding_mock(&mock_server, 2).await;
    let plugin = make_plugin(json!({
        "semantic_similarity_enabled": true,
        "semantic_embedding_provider": "google_gemini",
        "semantic_embedding_endpoint": format!("{}/embeddings", mock_server.uri()),
        "semantic_embedding_api_key": "test-key",
        "semantic_similarity_threshold": 0.95
    }));

    let body1 = json!({
        "model": "gemini-embedding-test",
        "messages": [{"role": "user", "content": "What is the capital of France?"}]
    });
    let body2 = json!({
        "model": "gemini-embedding-test",
        "messages": [{"role": "user", "content": "Which city is France's capital?"}]
    });

    store_response(
        &plugin,
        &serde_json::to_string(&body1).unwrap(),
        None,
        br#""Paris""#,
    )
    .await;

    let hit =
        run_before_proxy_get_status(&plugin, &serde_json::to_string(&body2).unwrap(), None).await;
    assert!(
        hit,
        "Gemini embedding.values responses should support semantic hits"
    );
}

#[tokio::test]
async fn test_semantic_embedding_size_counts_against_total_cache_limit() {
    let mock_server = MockServer::start().await;
    mount_large_embedding_mock(&mock_server, 1).await;
    let plugin = make_plugin(json!({
        "semantic_similarity_enabled": true,
        "semantic_embedding_endpoint": format!("{}/embeddings", mock_server.uri()),
        "semantic_embedding_api_key": "test-key",
        "max_entry_size_bytes": 512,
        "max_total_size_bytes": 512
    }));

    let body = json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "What is the capital of France?"}]
    });

    store_response(
        &plugin,
        &serde_json::to_string(&body).unwrap(),
        None,
        br#""Paris""#,
    )
    .await;

    assert_eq!(
        plugin.tracked_keys_count(),
        Some(0),
        "entry should be rejected when body plus semantic vector exceeds max_total_size_bytes"
    );
}

#[tokio::test]
async fn test_semantic_similarity_respects_consumer_scope() {
    let mock_server = MockServer::start().await;
    mount_embedding_mock(&mock_server, 2).await;
    let plugin = make_plugin(semantic_config(&mock_server));
    let alice = make_consumer("alice");
    let bob = make_consumer("bob");

    let body1 = json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "What is my account balance?"}]
    });
    let body2 = json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "How much money is in my account?"}]
    });

    store_response(
        &plugin,
        &serde_json::to_string(&body1).unwrap(),
        Some(alice),
        br#""alice-account-data""#,
    )
    .await;

    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/v1/chat/completions".to_string(),
    );
    ctx.metadata.insert(
        "request_body".to_string(),
        serde_json::to_string(&body2).unwrap(),
    );
    ctx.identified_consumer = Some(bob);
    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/json".to_string());

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(
        matches!(result, PluginResult::Continue),
        "semantic match must not cross consumer scope"
    );
    assert_eq!(staged_status(&plugin, &ctx), Some("MISS"));
}

#[tokio::test]
async fn test_different_prompts_no_cache_hit() {
    let config = json!({"ttl_seconds": 300});
    let plugin = make_plugin(config);

    // First request
    let body1 = json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "What is the capital of France?"}]
    });
    let mut ctx1 = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/chat".to_string(),
    );
    ctx1.metadata.insert(
        "request_body".to_string(),
        serde_json::to_string(&body1).unwrap(),
    );
    let mut headers1 = HashMap::new();
    headers1.insert("content-type".to_string(), "application/json".to_string());

    let _ = plugin.before_proxy(&mut ctx1, &mut headers1).await;
    let response_headers =
        HashMap::from([("content-type".to_string(), "application/json".to_string())]);
    let _ = plugin
        .on_final_response_body(&mut ctx1, 200, &response_headers, br#""cached""#)
        .await;

    // Different prompt — should MISS
    let body2 = json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "What is the capital of Germany?"}]
    });
    let mut ctx2 = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/chat".to_string(),
    );
    ctx2.metadata.insert(
        "request_body".to_string(),
        serde_json::to_string(&body2).unwrap(),
    );
    let mut headers2 = HashMap::new();
    headers2.insert("content-type".to_string(), "application/json".to_string());

    let result = plugin.before_proxy(&mut ctx2, &mut headers2).await;
    assert!(matches!(result, PluginResult::Continue));
    assert_eq!(staged_status(&plugin, &ctx2).unwrap(), "MISS");
}

#[tokio::test]
async fn test_exact_key_preserves_case_and_whitespace() {
    let config = json!({"ttl_seconds": 300});
    let plugin = make_plugin(config);

    // First request with normal spacing
    let body1 = json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "What is the capital of France?"}]
    });
    let mut ctx1 = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/chat".to_string(),
    );
    ctx1.metadata.insert(
        "request_body".to_string(),
        serde_json::to_string(&body1).unwrap(),
    );
    let mut headers1 = HashMap::new();
    headers1.insert("content-type".to_string(), "application/json".to_string());

    let _ = plugin.before_proxy(&mut ctx1, &mut headers1).await;
    let response_headers =
        HashMap::from([("content-type".to_string(), "application/json".to_string())]);
    let _ = plugin
        .on_final_response_body(&mut ctx1, 200, &response_headers, br#""Paris""#)
        .await;

    // Same words with extra whitespace and case differences — must MISS.
    let body2 = json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "  What  is  the  Capital  of  France?  "}]
    });
    let mut ctx2 = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/chat".to_string(),
    );
    ctx2.metadata.insert(
        "request_body".to_string(),
        serde_json::to_string(&body2).unwrap(),
    );
    let mut headers2 = HashMap::new();
    headers2.insert("content-type".to_string(), "application/json".to_string());

    let result = plugin.before_proxy(&mut ctx2, &mut headers2).await;
    assert!(
        matches!(result, PluginResult::Continue),
        "exact keys must preserve LLM-significant case and whitespace"
    );
    assert_eq!(staged_status(&plugin, &ctx2).unwrap(), "MISS");
}

#[tokio::test]
async fn exact_key_length_frames_user_controlled_instruction_fields() {
    let embedded_separator = json!({
        "model": "claude-3-5-sonnet",
        "system": "guard\npreamble:evil",
        "messages": [{"role": "user", "content": "Say hi."}]
    });
    let separate_field = json!({
        "model": "claude-3-5-sonnet",
        "system": "guard",
        "preamble": "evil",
        "messages": [{"role": "user", "content": "Say hi."}]
    });
    assert_exact_miss_for_variant(embedded_separator, separate_field, br#""safe""#).await;

    let model_with_separator = json!({
        "model": "model\nt:0",
        "messages": [{"role": "user", "content": "Say hi."}]
    });
    let model_and_temperature = json!({
        "model": "model",
        "temperature": 0,
        "messages": [{"role": "user", "content": "Say hi."}]
    });
    assert_exact_miss_for_variant(model_with_separator, model_and_temperature, br#""safe""#).await;

    let two_text_parts = json!({
        "model": "gpt-4o",
        "messages": [{
            "role": "user",
            "content": [
                {"type": "text", "text": "hello"},
                {"type": "text", "text": "world"}
            ]
        }]
    });
    let one_text_part = json!({
        "model": "gpt-4o",
        "messages": [{
            "role": "user",
            "content": [{"type": "text", "text": "hello world"}]
        }]
    });
    assert_exact_miss_for_variant(two_text_parts, one_text_part, br#""safe""#).await;
}

#[tokio::test]
async fn exact_key_recursively_canonicalizes_json_object_order() {
    let plugin = make_plugin(json!({"ttl_seconds": 300, "scope_by_consumer": false}));
    let first = r#"{
        "model":"gpt-4o",
        "messages":[{
            "role":"user",
            "content":[{"type":"text","text":"same","metadata":{"z":2,"a":1}}]
        }],
        "response_format":{"type":"json_schema","json_schema":{"schema":{
            "type":"object","properties":{"z":{"type":"string"},"a":{"type":"number"}}
        }}}
    }"#;
    let reordered = r#"{
        "response_format":{"json_schema":{"schema":{
            "properties":{"a":{"type":"number"},"z":{"type":"string"}},"type":"object"
        }},"type":"json_schema"},
        "messages":[{
            "content":[{"metadata":{"a":1,"z":2},"text":"same","type":"text"}],
            "role":"user"
        }],
        "model":"gpt-4o"
    }"#;

    store_response(&plugin, first, None, br#""canonical""#).await;
    let hit = run_before_proxy_get_status(&plugin, reordered, None).await;
    assert!(
        hit,
        "object insertion order at every nesting level must not change the exact key"
    );
}

#[tokio::test]
async fn test_exact_key_distinguishes_code_case_and_indentation() {
    let plugin = make_plugin(json!({"ttl_seconds": 300, "scope_by_consumer": false}));

    let body_print_a = json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "print(\"A\")"}]
    });
    store_response(
        &plugin,
        &serde_json::to_string(&body_print_a).unwrap(),
        None,
        br#""uppercase-A""#,
    )
    .await;

    let body_print_a_lower = json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "print(\"a\")"}]
    });
    let miss = run_before_proxy_get_status(
        &plugin,
        &serde_json::to_string(&body_print_a_lower).unwrap(),
        None,
    )
    .await;
    assert!(
        !miss,
        "case-sensitive string literals must not collide on exact keys"
    );

    let body_indent_two = json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "def f():\n  return 1"}]
    });
    store_response(
        &plugin,
        &serde_json::to_string(&body_indent_two).unwrap(),
        None,
        br#""indent-2""#,
    )
    .await;
    let body_indent_four = json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "def f():\n    return 1"}]
    });
    let miss_indent = run_before_proxy_get_status(
        &plugin,
        &serde_json::to_string(&body_indent_four).unwrap(),
        None,
    )
    .await;
    assert!(
        !miss_indent,
        "Python/Markdown indentation must not collapse on exact keys"
    );
}

#[tokio::test]
async fn test_different_model_no_cache_hit() {
    let config = json!({"ttl_seconds": 300, "include_model_in_key": true});
    let plugin = make_plugin(config);

    // Cache with gpt-4o
    let body1 = json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "hello"}]
    });
    let mut ctx1 = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/chat".to_string(),
    );
    ctx1.metadata.insert(
        "request_body".to_string(),
        serde_json::to_string(&body1).unwrap(),
    );
    let mut headers1 = HashMap::new();
    headers1.insert("content-type".to_string(), "application/json".to_string());

    let _ = plugin.before_proxy(&mut ctx1, &mut headers1).await;
    let response_headers =
        HashMap::from([("content-type".to_string(), "application/json".to_string())]);
    let _ = plugin
        .on_final_response_body(&mut ctx1, 200, &response_headers, br#""hi""#)
        .await;

    // Same prompt but different model — should MISS
    let body2 = json!({
        "model": "gpt-3.5-turbo",
        "messages": [{"role": "user", "content": "hello"}]
    });
    let mut ctx2 = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/chat".to_string(),
    );
    ctx2.metadata.insert(
        "request_body".to_string(),
        serde_json::to_string(&body2).unwrap(),
    );
    let mut headers2 = HashMap::new();
    headers2.insert("content-type".to_string(), "application/json".to_string());

    let result = plugin.before_proxy(&mut ctx2, &mut headers2).await;
    assert!(matches!(result, PluginResult::Continue));

    // Provider model identifiers may differ only by case.
    let body3 = json!({
        "model": "GPT-4O",
        "messages": [{"role": "user", "content": "hello"}]
    });
    let mut ctx3 = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/chat".to_string(),
    );
    ctx3.metadata.insert(
        "request_body".to_string(),
        serde_json::to_string(&body3).unwrap(),
    );
    let mut headers3 = HashMap::new();
    headers3.insert("content-type".to_string(), "application/json".to_string());

    let result = plugin.before_proxy(&mut ctx3, &mut headers3).await;
    assert!(
        matches!(result, PluginResult::Continue),
        "case-distinct model identifiers must not share exact cache entries"
    );
}

#[tokio::test]
async fn test_get_request_skipped() {
    let config = json!({});
    let plugin = make_plugin(config);

    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/chat".to_string(),
    );
    let mut headers = HashMap::new();

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
    assert!(staged_status(&plugin, &ctx).is_none());
}

#[tokio::test]
async fn test_non_json_skipped() {
    let config = json!({});
    let plugin = make_plugin(config);

    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/chat".to_string(),
    );
    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "text/plain".to_string());

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
}

#[tokio::test]
async fn test_error_response_not_cached() {
    let config = json!({"ttl_seconds": 300});
    let plugin = make_plugin(config);

    let body = json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "hello"}]
    });
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/chat".to_string(),
    );
    ctx.metadata.insert(
        "request_body".to_string(),
        serde_json::to_string(&body).unwrap(),
    );
    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/json".to_string());

    let _ = plugin.before_proxy(&mut ctx, &mut headers).await;

    // 500 response should not be cached
    let response_headers =
        HashMap::from([("content-type".to_string(), "application/json".to_string())]);
    let _ = plugin
        .on_final_response_body(&mut ctx, 500, &response_headers, b"error")
        .await;

    assert_eq!(plugin.tracked_keys_count(), Some(0));
}

#[tokio::test]
async fn response_admission_requires_valid_json_media_type_and_body() {
    struct Case {
        name: &'static str,
        status: u16,
        content_type: Option<&'static str>,
        body: &'static [u8],
        cached: bool,
    }

    let cases = [
        Case {
            name: "application/json",
            status: 200,
            content_type: Some("application/json; charset=utf-8"),
            body: br#"{"choices":[]}"#,
            cached: true,
        },
        Case {
            name: "mixed-case +json",
            status: 200,
            content_type: Some("Application/Vnd.Acme+Json; version=2"),
            body: br#"["ok"]"#,
            cached: true,
        },
        Case {
            name: "missing content type",
            status: 200,
            content_type: None,
            body: br#"{"ok":true}"#,
            cached: false,
        },
        Case {
            name: "HTML maintenance response",
            status: 200,
            content_type: Some("text/html"),
            body: b"<html>maintenance</html>",
            cached: false,
        },
        Case {
            name: "plain text response",
            status: 200,
            content_type: Some("text/plain"),
            body: b"temporarily unavailable",
            cached: false,
        },
        Case {
            name: "malformed JSON",
            status: 200,
            content_type: Some("application/json"),
            body: br#"{"choices": [}"#,
            cached: false,
        },
        Case {
            name: "empty JSON body",
            status: 200,
            content_type: Some("application/json"),
            body: b"",
            cached: false,
        },
        Case {
            name: "empty 204",
            status: 204,
            content_type: Some("application/json"),
            body: b"",
            cached: false,
        },
        Case {
            name: "empty 205",
            status: 205,
            content_type: Some("application/json"),
            body: b"",
            cached: false,
        },
        Case {
            name: "SSE",
            status: 200,
            content_type: Some("text/event-stream"),
            body: b"data: {\"ok\":true}\n\n",
            cached: false,
        },
    ];

    for case in cases {
        let plugin = make_plugin(json!({"ttl_seconds": 300}));
        let request = json!({
            "model": "gpt-4o",
            "messages": [{"role": "user", "content": case.name}]
        });
        let (mut ctx, result) =
            run_before_proxy(&plugin, &serde_json::to_string(&request).unwrap(), None).await;
        assert!(matches!(result, PluginResult::Continue));

        let mut response_headers = HashMap::new();
        if let Some(content_type) = case.content_type {
            response_headers.insert("Content-Type".to_string(), content_type.to_string());
        }
        let result = plugin
            .on_final_response_body(&mut ctx, case.status, &response_headers, case.body)
            .await;

        assert!(
            matches!(result, PluginResult::Continue),
            "{} must pass through unchanged",
            case.name
        );
        assert_eq!(
            plugin.tracked_keys_count(),
            Some(usize::from(case.cached)),
            "unexpected cache admission for {}",
            case.name
        );
    }
}

#[test]
fn test_tracked_keys_count() {
    let config = json!({});
    let plugin = make_plugin(config);
    assert_eq!(plugin.tracked_keys_count(), Some(0));
}

#[tokio::test]
async fn test_sensitive_response_headers_not_replayed_on_cache_hit() {
    // SECURITY: Cached responses must not replay per-response identity
    // (cookies, auth tokens) or per-request rate-limit/trace headers to a
    // different consumer. Without this, a cache hit would leak the original
    // user's session cookie to the next user that asks the same question.
    let config = json!({"ttl_seconds": 300});
    let plugin = make_plugin(config);

    let body_json = json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "Hello"}]
    });
    let body_str = serde_json::to_string(&body_json).unwrap();

    // First request — cache MISS, store response with a Set-Cookie / Auth header.
    let mut ctx1 = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/v1/chat/completions".to_string(),
    );
    ctx1.metadata
        .insert("request_body".to_string(), body_str.clone());
    let mut headers1 = HashMap::new();
    headers1.insert("content-type".to_string(), "application/json".to_string());
    let _ = plugin.before_proxy(&mut ctx1, &mut headers1).await;

    let mut response_headers = HashMap::new();
    response_headers.insert("content-type".to_string(), "application/json".to_string());
    response_headers.insert(
        "Set-Cookie".to_string(),
        "session=user-A-secret".to_string(),
    );
    response_headers.insert(
        "authorization".to_string(),
        "Bearer user-A-token".to_string(),
    );
    response_headers.insert(
        "X-Request-Id".to_string(),
        "request-id-from-user-A".to_string(),
    );
    response_headers.insert("x-ai-ratelimit-remaining".to_string(), "999".to_string());

    let _ = plugin
        .on_final_response_body(&mut ctx1, 200, &response_headers, br#""Hello back""#)
        .await;

    // Second request from a different consumer (different IP) hits the cache.
    let mut ctx2 = RequestContext::new(
        "203.0.113.99".to_string(),
        "POST".to_string(),
        "/v1/chat/completions".to_string(),
    );
    ctx2.metadata
        .insert("request_body".to_string(), body_str.clone());
    let mut headers2 = HashMap::new();
    headers2.insert("content-type".to_string(), "application/json".to_string());

    let result = plugin.before_proxy(&mut ctx2, &mut headers2).await;
    match result {
        PluginResult::RejectBinary { headers, .. } => {
            assert!(
                !headers.contains_key("Set-Cookie"),
                "cache MUST NOT replay Set-Cookie to a different consumer"
            );
            assert!(
                !headers.contains_key("authorization"),
                "cache MUST NOT replay Authorization to a different consumer"
            );
            assert!(
                !headers.contains_key("X-Request-Id"),
                "cache MUST NOT replay X-Request-Id to a different consumer"
            );
            assert!(
                !headers.contains_key("x-ai-ratelimit-remaining"),
                "cache MUST NOT replay rate-limit counters from the original request"
            );
            // The cache-status indicator and content-type must still be present.
            assert_eq!(headers.get("x-ai-cache-status").unwrap(), "HIT");
            assert_eq!(
                headers.get("content-type").map(String::as_str),
                Some("application/json")
            );
        }
        _ => panic!("Expected cache HIT (RejectBinary), got {:?}", result),
    }
}

// -------------------------------------------------------------------------
// Cross-prompt / param-collapse / consumer-leak hardening tests.
//
// These guard against four distinct correctness/security gaps:
//   1. Anthropic top-level `system` prompt collapsing into the messages key.
//   2. Sampling-parameter differences (temperature) collapsing under the old
//      `include_params_in_key=false` default.
//   3. Cross-consumer cache replay under the old `scope_by_consumer=false`
//      default.
//   4. `stream:true` vs `stream:false` collapsing into the same entry, which
//      would let a non-streaming MISS-then-store replay JSON to a streaming
//      caller (and vice versa).
// -------------------------------------------------------------------------

#[tokio::test]
async fn test_different_system_prompt_no_cache_hit() {
    // SECURITY: Anthropic Messages API uses a top-level `system` field, not
    // an in-`messages` system role. Without including it in the key, two
    // requests with identical messages but different system prompts would
    // collapse to the same cache entry — a cross-prompt poisoning vector.
    let plugin = make_plugin(json!({"ttl_seconds": 300}));

    let body1 = json!({
        "model": "claude-3-5-sonnet-20241022",
        "system": "You are a helpful assistant.",
        "messages": [{"role": "user", "content": "Say hi."}]
    });
    let body2 = json!({
        "model": "claude-3-5-sonnet-20241022",
        "system": "You are a pirate. Speak in pirate dialect.",
        "messages": [{"role": "user", "content": "Say hi."}]
    });

    store_response(
        &plugin,
        &serde_json::to_string(&body1).unwrap(),
        None,
        br#""Hello!""#,
    )
    .await;

    let hit =
        run_before_proxy_get_status(&plugin, &serde_json::to_string(&body2).unwrap(), None).await;
    assert!(
        !hit,
        "different `system` prompts must NOT collapse to the same cache key"
    );
}

#[tokio::test]
async fn test_different_system_array_form_no_cache_hit() {
    // Anthropic also accepts `system` as an array of content blocks; the
    // array form must produce different keys for different system text.
    let plugin = make_plugin(json!({"ttl_seconds": 300}));

    let body1 = json!({
        "model": "claude-3-5-sonnet-20241022",
        "system": [{"type": "text", "text": "Be terse."}],
        "messages": [{"role": "user", "content": "ping"}]
    });
    let body2 = json!({
        "model": "claude-3-5-sonnet-20241022",
        "system": [{"type": "text", "text": "Be verbose."}],
        "messages": [{"role": "user", "content": "ping"}]
    });

    store_response(
        &plugin,
        &serde_json::to_string(&body1).unwrap(),
        None,
        br#""pong""#,
    )
    .await;

    let hit =
        run_before_proxy_get_status(&plugin, &serde_json::to_string(&body2).unwrap(), None).await;
    assert!(
        !hit,
        "different array-form `system` prompts must NOT collapse to the same cache key"
    );
}

#[tokio::test]
async fn test_different_temperature_no_cache_hit_with_default_config() {
    // SECURITY: With the new `include_params_in_key=true` default, two
    // requests differing only in `temperature` must produce different cache
    // keys. The old default (`false`) silently served a temperature=0
    // response to a temperature=1.5 request.
    let plugin = make_plugin(json!({"ttl_seconds": 300}));

    let body1 = json!({
        "model": "gpt-4o",
        "temperature": 0.0,
        "messages": [{"role": "user", "content": "draft a poem"}]
    });
    let body2 = json!({
        "model": "gpt-4o",
        "temperature": 1.5,
        "messages": [{"role": "user", "content": "draft a poem"}]
    });

    store_response(
        &plugin,
        &serde_json::to_string(&body1).unwrap(),
        None,
        br#""poem-from-temp-0""#,
    )
    .await;

    let hit =
        run_before_proxy_get_status(&plugin, &serde_json::to_string(&body2).unwrap(), None).await;
    assert!(
        !hit,
        "different `temperature` must NOT collapse with `include_params_in_key=true` default"
    );
}

#[tokio::test]
async fn test_sub_cent_sampling_params_do_not_collapse() {
    // Regression: cache-key hardening used to format `temperature` and
    // `top_p` with two decimal places, so 0.001 and 0.004 both became 0.00.
    let temperature_plugin = make_plugin(json!({"ttl_seconds": 300}));
    let low_temperature = json!({
        "model": "gpt-4o",
        "temperature": 0.001,
        "messages": [{"role": "user", "content": "draft a poem"}]
    });
    let nearby_temperature = json!({
        "model": "gpt-4o",
        "temperature": 0.004,
        "messages": [{"role": "user", "content": "draft a poem"}]
    });

    store_response(
        &temperature_plugin,
        &serde_json::to_string(&low_temperature).unwrap(),
        None,
        br#""poem-from-temp-0.001""#,
    )
    .await;

    let temperature_hit = run_before_proxy_get_status(
        &temperature_plugin,
        &serde_json::to_string(&nearby_temperature).unwrap(),
        None,
    )
    .await;
    assert!(
        !temperature_hit,
        "sub-cent `temperature` values must not collapse to the same cache key"
    );

    let top_p_plugin = make_plugin(json!({"ttl_seconds": 300}));
    let low_top_p = json!({
        "model": "gpt-4o",
        "top_p": 0.001,
        "messages": [{"role": "user", "content": "draft a poem"}]
    });
    let nearby_top_p = json!({
        "model": "gpt-4o",
        "top_p": 0.004,
        "messages": [{"role": "user", "content": "draft a poem"}]
    });

    store_response(
        &top_p_plugin,
        &serde_json::to_string(&low_top_p).unwrap(),
        None,
        br#""poem-from-top-p-0.001""#,
    )
    .await;

    let top_p_hit = run_before_proxy_get_status(
        &top_p_plugin,
        &serde_json::to_string(&nearby_top_p).unwrap(),
        None,
    )
    .await;
    assert!(
        !top_p_hit,
        "sub-cent `top_p` values must not collapse to the same cache key"
    );
}

#[tokio::test]
async fn test_numerically_equivalent_sampling_params_collapse() {
    // #55: semantically identical sampling-parameter encodings must canonicalize
    // to the same cache key. Integer vs float (`1` vs `1.0`) and trailing-zero
    // (`0.5` vs `0.50`) forms previously produced different key fragments
    // ("1" vs "1.0", "0.5" vs "0.50") and missed the cache; canonicalizing
    // through the f64 form collapses them.
    let plugin = make_plugin(json!({"ttl_seconds": 300}));

    let stored = json!({
        "model": "gpt-4o",
        "temperature": 1,
        "top_p": 0.5,
        "messages": [{"role": "user", "content": "draft a poem"}]
    });
    let equivalent = json!({
        "model": "gpt-4o",
        "temperature": 1.0,
        "top_p": 0.50,
        "messages": [{"role": "user", "content": "draft a poem"}]
    });

    store_response(
        &plugin,
        &serde_json::to_string(&stored).unwrap(),
        None,
        br#""poem-from-temp-1""#,
    )
    .await;

    let hit =
        run_before_proxy_get_status(&plugin, &serde_json::to_string(&equivalent).unwrap(), None)
            .await;
    assert!(
        hit,
        "numerically equivalent sampling params (1 vs 1.0, 0.5 vs 0.50) must hit the same entry"
    );
}

#[tokio::test]
async fn test_same_request_different_consumer_no_cache_hit_with_default_config() {
    // SECURITY: With the new `scope_by_consumer=true` default, two requests
    // from different authenticated consumers must NOT share a cache entry.
    // The old default (`false`) leaked one consumer's response to the next.
    let plugin = make_plugin(json!({"ttl_seconds": 300}));

    let body = json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "what's my last invoice"}]
    });
    let body_str = serde_json::to_string(&body).unwrap();

    let alice = make_consumer("alice");
    let bob = make_consumer("bob");

    store_response(
        &plugin,
        &body_str,
        Some(alice.clone()),
        br#""alice-only-data""#,
    )
    .await;

    let hit = run_before_proxy_get_status(&plugin, &body_str, Some(bob.clone())).await;
    assert!(
        !hit,
        "consumer `bob` MUST NOT receive a cache hit on `alice`'s entry under default config"
    );

    // Sanity check: alice's repeat hits her own entry.
    let alice_hit = run_before_proxy_get_status(&plugin, &body_str, Some(alice.clone())).await;
    assert!(
        alice_hit,
        "consumer `alice` SHOULD see her own cache entry on repeat"
    );
}

#[tokio::test]
async fn test_same_request_same_consumer_same_params_cache_hit_positive() {
    // POSITIVE control: when *every* key field matches (messages, model,
    // params, system, stream, consumer), the second call must HIT. Confirms
    // the harder-to-collide key composition is not over-broken.
    let plugin = make_plugin(json!({"ttl_seconds": 300}));
    let consumer = make_consumer("carol");

    let body = json!({
        "model": "gpt-4o",
        "temperature": 0.7,
        "max_tokens": 256,
        "stream": false,
        "system": "You are concise.",
        "messages": [{"role": "user", "content": "hi"}]
    });
    let body_str = serde_json::to_string(&body).unwrap();

    store_response(
        &plugin,
        &body_str,
        Some(consumer.clone()),
        br#""hello-back""#,
    )
    .await;

    let hit = run_before_proxy_get_status(&plugin, &body_str, Some(consumer)).await;
    assert!(
        hit,
        "fully-identical request from the same consumer MUST hit the cache (positive control)"
    );
}

#[tokio::test]
async fn test_stream_true_vs_false_no_cache_hit() {
    // SECURITY: `stream:true` produces SSE; `stream:false` produces a single
    // JSON response. They must not share a cache entry. Note that we cache
    // the `stream:false` response (since SSE is filtered out at store time)
    // — without `stream` in the key, a `stream:true` follow-up would receive
    // the buffered JSON in a `RejectBinary` reply and the client SDK would
    // fail to parse SSE.
    let plugin = make_plugin(json!({"ttl_seconds": 300}));

    let body_nostream = json!({
        "model": "gpt-4o",
        "stream": false,
        "messages": [{"role": "user", "content": "hello"}]
    });
    let body_stream = json!({
        "model": "gpt-4o",
        "stream": true,
        "messages": [{"role": "user", "content": "hello"}]
    });

    store_response(
        &plugin,
        &serde_json::to_string(&body_nostream).unwrap(),
        None,
        b"{\"choices\":[{\"message\":{\"content\":\"hi\"}}]}",
    )
    .await;

    let hit =
        run_before_proxy_get_status(&plugin, &serde_json::to_string(&body_stream).unwrap(), None)
            .await;
    assert!(
        !hit,
        "`stream:true` request MUST NOT receive the `stream:false` cached entry"
    );
}

#[tokio::test]
async fn test_different_tools_no_cache_hit() {
    // SECURITY: Two requests with identical messages but different tool
    // schemas should produce different responses (model may invoke a tool in
    // one and not the other). Must not collapse to the same key.
    let plugin = make_plugin(json!({"ttl_seconds": 300}));

    let body1 = json!({
        "model": "gpt-4o",
        "tools": [{"type": "function", "function": {"name": "get_weather"}}],
        "messages": [{"role": "user", "content": "weather in NYC?"}]
    });
    let body2 = json!({
        "model": "gpt-4o",
        "tools": [{"type": "function", "function": {"name": "get_news"}}],
        "messages": [{"role": "user", "content": "weather in NYC?"}]
    });

    store_response(
        &plugin,
        &serde_json::to_string(&body1).unwrap(),
        None,
        br#""weather-tool-call""#,
    )
    .await;

    let hit =
        run_before_proxy_get_status(&plugin, &serde_json::to_string(&body2).unwrap(), None).await;
    assert!(
        !hit,
        "different `tools` definitions must NOT collapse to the same cache key"
    );
}

#[tokio::test]
async fn test_different_response_format_no_cache_hit() {
    // OpenAI: `response_format: {"type":"json_object"}` vs `text` produces
    // structurally different responses; must not collide.
    let plugin = make_plugin(json!({"ttl_seconds": 300}));

    let body1 = json!({
        "model": "gpt-4o",
        "response_format": {"type": "json_object"},
        "messages": [{"role": "user", "content": "give me a fruit"}]
    });
    let body2 = json!({
        "model": "gpt-4o",
        "response_format": {"type": "text"},
        "messages": [{"role": "user", "content": "give me a fruit"}]
    });

    store_response(
        &plugin,
        &serde_json::to_string(&body1).unwrap(),
        None,
        b"{\"fruit\":\"apple\"}",
    )
    .await;

    let hit =
        run_before_proxy_get_status(&plugin, &serde_json::to_string(&body2).unwrap(), None).await;
    assert!(
        !hit,
        "different `response_format` must NOT collapse to the same cache key"
    );
}

#[tokio::test]
async fn test_different_seed_no_cache_hit() {
    // OpenAI's `seed` controls reproducibility; different seeds can produce
    // different completions and should not collide.
    let plugin = make_plugin(json!({"ttl_seconds": 300}));

    let body1 = json!({
        "model": "gpt-4o",
        "seed": 42,
        "messages": [{"role": "user", "content": "tell a joke"}]
    });
    let body2 = json!({
        "model": "gpt-4o",
        "seed": 99,
        "messages": [{"role": "user", "content": "tell a joke"}]
    });

    store_response(
        &plugin,
        &serde_json::to_string(&body1).unwrap(),
        None,
        br#""joke-seed-42""#,
    )
    .await;

    let hit =
        run_before_proxy_get_status(&plugin, &serde_json::to_string(&body2).unwrap(), None).await;
    assert!(!hit, "different `seed` must NOT collapse cache keys");
}

#[test]
fn unknown_retention_multimodal_isolation_size_semantic_and_redis_typos_are_rejected() {
    for (typo, suggestion) in [
        ("ttl_second", "ttl_seconds"),
        ("cache_multimoda", "cache_multimodal"),
        ("scope_by_consumr", "scope_by_consumer"),
        ("max_entrie", "max_entries"),
        ("max_entry_size_byte", "max_entry_size_bytes"),
        ("semantic_similarity_enable", "semantic_similarity_enabled"),
        ("sync_mod", "sync_mode"),
        ("redis_ur", "redis_url"),
    ] {
        let err = AiSemanticCache::new(&json!({(typo): true}), PluginHttpClient::default())
            .err()
            .unwrap_or_else(|| panic!("unknown key {typo} must fail closed"));
        assert!(
            err.contains(&format!("'config.{typo}'")),
            "path-qualified diagnostic missing for {typo}: {err}"
        );
        assert!(
            err.contains(&format!("did you mean '{suggestion}'?")),
            "spelling suggestion missing for {typo}: {err}"
        );
        assert!(
            err.starts_with("ai_semantic_cache: unknown configuration key(s):"),
            "unexpected prefix for {typo}: {err}"
        );
    }
}

#[test]
fn multiple_unknown_keys_are_reported_deterministically_with_suggestions() {
    let err = AiSemanticCache::new(
        &json!({
            "ttl_second": 30,
            "cache_multimoda": "reject",
            "sync_mod": "redis",
        }),
        PluginHttpClient::default(),
    )
    .err()
    .expect("multiple typos must fail closed");
    assert_eq!(
        err,
        "ai_semantic_cache: unknown configuration key(s): \
         'config.cache_multimoda' (did you mean 'cache_multimodal'?), \
         'config.sync_mod' (did you mean 'sync_mode'?), \
         'config.ttl_second' (did you mean 'ttl_seconds'?)"
    );
}

#[test]
fn every_documented_config_key_is_accepted_together() {
    let plugin = AiSemanticCache::new(
        &json!({
            "ttl_seconds": 120,
            "max_entries": 100,
            "max_entry_size_bytes": 4096,
            "max_total_size_bytes": 8192,
            "include_model_in_key": true,
            "include_params_in_key": true,
            "scope_by_consumer": true,
            "cache_multimodal": "reject",
            "semantic_similarity_enabled": false,
            "semantic_embedding_provider": "openai",
            "semantic_embedding_endpoint": "https://api.openai.com/v1/embeddings",
            "semantic_embedding_model": "text-embedding-3-small",
            "semantic_embedding_input_type": "query",
            "semantic_embedding_output_dimension": 512,
            "semantic_embedding_api_key": "test-key",
            "semantic_embedding_auth_header": "Authorization",
            "semantic_embedding_auth_scheme": "Bearer",
            "semantic_similarity_threshold": 0.9,
            "semantic_vector_max_candidates": 8,
            "semantic_embedding_timeout_ms": 1000,
            "sync_mode": "local",
            "redis_url": "redis://127.0.0.1:6379/0",
            "redis_tls": false,
            "redis_key_prefix": "test:ai_cache",
            "redis_pool_size": 2,
            "redis_connect_timeout_seconds": 3,
            "redis_health_check_interval_seconds": 4,
            "redis_username": "cache-user",
            "redis_password": "cache-pass",
            "redis_integrity_key": REDIS_INTEGRITY_KEY_FOR_TESTS,
        }),
        PluginHttpClient::default(),
    )
    .expect("every known key must remain admissible together");
    assert_eq!(plugin.name(), "ai_semantic_cache");
}

#[test]
fn shared_admission_rejects_unknown_keys_with_keep_last_known_good_policy() {
    use ferrum_edge::plugins::{
        PluginFailurePolicy, plugin_failure_policy, validate_plugin_config,
    };

    assert_eq!(
        plugin_failure_policy("ai_semantic_cache"),
        Some(PluginFailurePolicy::KeepLastKnownGood)
    );

    let err = validate_plugin_config(
        "ai_semantic_cache",
        &json!({"cache_multimoda": "reject", "ttl_seconds": 60}),
    )
    .expect_err("shared admission must reject multimodal typos");
    assert!(
        err.contains("'config.cache_multimoda'"),
        "unexpected admission error: {err}"
    );
    assert!(
        err.contains("did you mean 'cache_multimodal'?"),
        "unexpected admission error: {err}"
    );
}

// === Concurrent same-key size accounting (#2273) ===

fn assert_size_accounting_exact(plugin: &AiSemanticCache) -> usize {
    let (tracked, actual) = ai_semantic_cache_size_accounting_snapshot_for_test(plugin);
    assert_eq!(
        tracked,
        actual,
        "tracked cache_budget.used() must equal retained entry approx_size \
         + published HNSW generation + in-flight rebuild reservation \
         (tracked={tracked}, actual={actual}, keys={:?})",
        plugin.tracked_keys_count()
    );
    tracked
}

fn json_pad_body(tag: &str, pad_bytes: usize) -> Vec<u8> {
    // Valid JSON string large enough to exercise distinct approx_size values.
    let mut body = format!(r#""{tag}-"#).into_bytes();
    body.extend(std::iter::repeat_n(b'x', pad_bytes));
    body.push(b'"');
    body
}

async fn miss_cache_key(plugin: &AiSemanticCache, request_body: &str) -> String {
    let (ctx, result) = run_before_proxy(plugin, request_body, None).await;
    assert!(
        matches!(result, PluginResult::Continue),
        "expected cache MISS so the store path is exercised"
    );
    staged_cache_key_value(plugin, &ctx)
        .map(str::to_string)
        .expect("MISS must stage cache_key")
}

async fn store_with_cache_key(
    plugin: &AiSemanticCache,
    cache_key: &str,
    response_body: &[u8],
    embedding: Option<Vec<f32>>,
    scope_key: Option<String>,
) {
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/v1/chat/completions".to_string(),
    );
    ctx.metadata
        .insert(staging_key(plugin, "cache_key"), cache_key.to_string());
    set_ai_semantic_cache_embedding(&mut ctx, instance_id(plugin), embedding);
    set_ai_semantic_cache_scope_key(&mut ctx, instance_id(plugin), scope_key);
    let mut response_headers = HashMap::new();
    response_headers.insert("content-type".to_string(), "application/json".to_string());
    let _ = plugin
        .on_final_response_body(&mut ctx, 200, &response_headers, response_body)
        .await;
}

fn install_post_admit_barrier(plugin: &AiSemanticCache, workers: usize) -> Arc<Barrier> {
    let barrier = Arc::new(Barrier::new(workers));
    ai_semantic_cache_set_store_post_admit_hook_for_test(
        plugin,
        Some(Arc::new({
            let barrier = Arc::clone(&barrier);
            move || {
                let _ = barrier.wait();
            }
        })),
    );
    barrier
}

fn clear_post_admit_hook(plugin: &AiSemanticCache) {
    ai_semantic_cache_set_store_post_admit_hook_for_test(plugin, None);
}

/// Concurrent empty same-key inserts must leave one retained entry whose size
/// equals the tracked counter (no phantom bytes from ignored DashMap overwrites).
#[tokio::test]
async fn test_concurrent_empty_same_key_inserts_reconcile_size() {
    let plugin = Arc::new(make_plugin(json!({
        "ttl_seconds": 600,
        "scope_by_consumer": false,
        "max_total_size_bytes": 1_048_576
    })));
    let request = json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "same-key concurrent insert"}]
    });
    let request_body = serde_json::to_string(&request).unwrap();
    let cache_key = miss_cache_key(&plugin, &request_body).await;
    let response_body = json_pad_body("insert", 256);

    const WORKERS: usize = 16;
    let _barrier = install_post_admit_barrier(&plugin, WORKERS);
    let mut tasks = Vec::with_capacity(WORKERS);
    for _ in 0..WORKERS {
        let plugin = Arc::clone(&plugin);
        let cache_key = cache_key.clone();
        let response_body = response_body.clone();
        // Blocking pool so the sync post-admit barrier does not stall tokio workers.
        tasks.push(tokio::task::spawn_blocking(move || {
            tokio::runtime::Handle::current().block_on(store_with_cache_key(
                &plugin,
                &cache_key,
                &response_body,
                None,
                None,
            ));
        }));
    }
    for task in tasks {
        task.await.expect("same-key insert task panicked");
    }
    clear_post_admit_hook(&plugin);

    assert_eq!(plugin.tracked_keys_count(), Some(1));
    assert_size_accounting_exact(&plugin);
}

/// Concurrent same-key replacements with different body sizes must keep the
/// counter equal to the single retained winner's approx_size.
#[tokio::test]
async fn test_concurrent_same_key_replacement_different_sizes_reconcile() {
    let plugin = Arc::new(make_plugin(json!({
        "ttl_seconds": 600,
        "scope_by_consumer": false,
        "max_total_size_bytes": 1_048_576
    })));
    let request = json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "same-key size replacement"}]
    });
    let request_body = serde_json::to_string(&request).unwrap();
    let cache_key = miss_cache_key(&plugin, &request_body).await;

    // Seed an existing entry so replacements displace a non-empty value.
    store_with_cache_key(&plugin, &cache_key, &json_pad_body("seed", 64), None, None).await;
    assert_eq!(plugin.tracked_keys_count(), Some(1));
    let seed_total = assert_size_accounting_exact(&plugin);
    assert!(seed_total > 0);

    const WORKERS: usize = 12;
    let _barrier = install_post_admit_barrier(&plugin, WORKERS);
    let mut tasks = Vec::with_capacity(WORKERS);
    for i in 0..WORKERS {
        let plugin = Arc::clone(&plugin);
        let cache_key = cache_key.clone();
        let response_body = json_pad_body(&format!("repl-{i}"), 128 + i * 97);
        tasks.push(tokio::task::spawn_blocking(move || {
            tokio::runtime::Handle::current().block_on(store_with_cache_key(
                &plugin,
                &cache_key,
                &response_body,
                None,
                None,
            ));
        }));
    }
    for task in tasks {
        task.await.expect("same-key replacement task panicked");
    }
    clear_post_admit_hook(&plugin);

    assert_eq!(plugin.tracked_keys_count(), Some(1));
    assert_size_accounting_exact(&plugin);
}

/// After a same-key race settles, expiry must subtract exactly the retained
/// entry — no leftover phantom bytes that would poison later admits.
#[tokio::test]
async fn test_expiry_after_same_key_race_reconciles_to_zero() {
    let plugin = Arc::new(make_plugin(json!({
        "ttl_seconds": 600,
        "scope_by_consumer": false,
        "max_total_size_bytes": 1_048_576
    })));
    let request = json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "same-key expiry after race"}]
    });
    let request_body = serde_json::to_string(&request).unwrap();
    let cache_key = miss_cache_key(&plugin, &request_body).await;

    const WORKERS: usize = 16;
    let _barrier = install_post_admit_barrier(&plugin, WORKERS);
    let mut tasks = Vec::with_capacity(WORKERS);
    for i in 0..WORKERS {
        let plugin = Arc::clone(&plugin);
        let cache_key = cache_key.clone();
        let response_body = json_pad_body(&format!("expire-{i}"), 160 + i * 17);
        tasks.push(tokio::task::spawn_blocking(move || {
            tokio::runtime::Handle::current().block_on(store_with_cache_key(
                &plugin,
                &cache_key,
                &response_body,
                None,
                None,
            ));
        }));
    }
    for task in tasks {
        task.await.expect("expiry-race store task panicked");
    }
    clear_post_admit_hook(&plugin);

    assert_eq!(plugin.tracked_keys_count(), Some(1));
    assert_size_accounting_exact(&plugin);

    ai_semantic_cache_expire_all_entries_for_test(&plugin);
    ai_semantic_cache_force_cleanup_for_test(&plugin);

    assert_eq!(plugin.tracked_keys_count(), Some(0));
    assert_eq!(assert_size_accounting_exact(&plugin), 0);
}

/// Different-key admits that cannot both fit under `max_total_size_bytes` are
/// hard-capped by lock-free byte leases: at most one of two concurrent stores
/// retains when each alone fits but together they would exceed the budget.
#[tokio::test]
async fn test_concurrent_different_key_budget_rejects_overshoot() {
    // Each ~4 KiB body plus structural overhead fits under 6 KiB alone; two
    // concurrent admits cannot both reserve against the shared budget.
    let max_total = 6_000usize;
    let plugin = Arc::new(make_plugin(json!({
        "ttl_seconds": 600,
        "scope_by_consumer": false,
        "max_total_size_bytes": max_total,
        "max_entry_size_bytes": max_total
    })));

    let request_a = json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "soft-cap key A"}]
    });
    let request_b = json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "soft-cap key B"}]
    });
    let key_a = miss_cache_key(&plugin, &serde_json::to_string(&request_a).unwrap()).await;
    let key_b = miss_cache_key(&plugin, &serde_json::to_string(&request_b).unwrap()).await;
    assert_ne!(key_a, key_b);

    let body_a = json_pad_body("soft-a", 4_096);
    let body_b = json_pad_body("soft-b", 4_096);
    // Do not use the post-admit barrier here: the losing admit fails inside
    // try_acquire before the hook and would otherwise leave the winner parked.
    let mut tasks = Vec::with_capacity(2);
    for (cache_key, response_body) in [(key_a, body_a), (key_b, body_b)] {
        let plugin = Arc::clone(&plugin);
        tasks.push(tokio::task::spawn_blocking(move || {
            tokio::runtime::Handle::current().block_on(store_with_cache_key(
                &plugin,
                &cache_key,
                &response_body,
                None,
                None,
            ));
        }));
    }
    for task in tasks {
        task.await.expect("budget race task panicked");
    }

    assert_eq!(
        plugin.tracked_keys_count(),
        Some(1),
        "hard byte budget must admit only one of two concurrent oversize-together stores"
    );
    let total = assert_size_accounting_exact(&plugin);
    assert!(
        total <= max_total,
        "retained bytes must stay within max_total_size_bytes (total={total}, max={max_total})"
    );
}

/// Same-key replacement that gains or loses an embedding must still dirty the
/// semantic vector index (accounting fix must not drop that side effect).
#[tokio::test]
async fn test_same_key_replacement_dirties_vector_index_on_embedding_change() {
    // Semantic mode is required so `mark_vector_index_dirty` is armed; the
    // embedding itself is staged directly so we do not depend on a live
    // embedding HTTP round-trip for this dirtying side-effect check.
    let plugin = make_plugin(json!({
        "ttl_seconds": 600,
        "scope_by_consumer": false,
        "semantic_similarity_enabled": true,
        "semantic_embedding_endpoint": "http://127.0.0.1:9/embeddings",
        "semantic_embedding_api_key": "test-key",
        "semantic_similarity_threshold": 0.95
    }));

    let request = json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "embedding dirty on replace"}]
    });
    let request_body = serde_json::to_string(&request).unwrap();
    // Force an exact-path cache key without calling the (unreachable) embedding
    // endpoint: stage cache_key via a miss that fails closed to exact.
    let cache_key = {
        let (ctx, result) = run_before_proxy(&plugin, &request_body, None).await;
        assert!(matches!(result, PluginResult::Continue));
        ctx.metadata
            .get(&staging_key(&plugin, "cache_key"))
            .cloned()
            .expect("embedding failure still stages an exact-cache key")
    };

    // Exact-only seed (no embedding) then a replace that gains an embedding.
    store_with_cache_key(&plugin, &cache_key, br#""seed""#, None, None).await;
    ai_semantic_cache_clear_vector_index_dirty_for_test(&plugin);
    assert!(!ai_semantic_cache_vector_index_dirty_for_test(&plugin));
    ai_semantic_cache_set_vector_index_rebuild_blocked_for_test(&plugin, true);

    store_with_cache_key(
        &plugin,
        &cache_key,
        br#""with-embedding""#,
        Some(vec![1.0, 0.0, 0.0]),
        Some("scope:embedding-dirty".to_string()),
    )
    .await;
    assert!(
        ai_semantic_cache_vector_index_dirty_for_test(&plugin),
        "gaining an embedding on same-key replace must dirty the vector index"
    );
    ai_semantic_cache_set_vector_index_rebuild_blocked_for_test(&plugin, false);
    assert_eq!(plugin.tracked_keys_count(), Some(1));
    assert_size_accounting_exact(&plugin);

    // Losing the embedding on a later replace must also dirty.
    ai_semantic_cache_clear_vector_index_dirty_for_test(&plugin);
    ai_semantic_cache_set_vector_index_rebuild_blocked_for_test(&plugin, true);
    store_with_cache_key(&plugin, &cache_key, br#""no-embedding""#, None, None).await;
    assert!(
        ai_semantic_cache_vector_index_dirty_for_test(&plugin),
        "losing an embedding on same-key replace must dirty the vector index"
    );
    ai_semantic_cache_set_vector_index_rebuild_blocked_for_test(&plugin, false);
    assert_eq!(plugin.tracked_keys_count(), Some(1));
    assert_size_accounting_exact(&plugin);
}

// -------------------------------------------------------------------------
// Provider-native request-family coverage (#2286).
//
// Exact hit/miss, semantic hit/isolation, multimodal/native tool blocks, and
// deliberate unknown/ambiguous-shape bypass for every family Ferrum caches.
// -------------------------------------------------------------------------

async fn assert_exact_hit_roundtrip(body: serde_json::Value, response_body: &[u8]) {
    let plugin = make_plugin(json!({"ttl_seconds": 300}));
    let body_str = serde_json::to_string(&body).unwrap();
    store_response(&plugin, &body_str, None, response_body).await;
    let (ctx, result) = run_before_proxy(&plugin, &body_str, None).await;
    match result {
        PluginResult::RejectBinary {
            status_code,
            headers,
            body,
            ..
        } => {
            assert_eq!(status_code, 200);
            assert_eq!(headers.get("x-ai-cache-status").unwrap(), "HIT");
            assert_eq!(&body[..], response_body);
            assert_eq!(staged_status(&plugin, &ctx).unwrap(), "HIT");
        }
        other => panic!("expected exact HIT, got {other:?}"),
    }
}

async fn assert_exact_miss_for_variant(
    body1: serde_json::Value,
    body2: serde_json::Value,
    response_body: &[u8],
) {
    let plugin = make_plugin(json!({"ttl_seconds": 300}));
    store_response(
        &plugin,
        &serde_json::to_string(&body1).unwrap(),
        None,
        response_body,
    )
    .await;
    let hit =
        run_before_proxy_get_status(&plugin, &serde_json::to_string(&body2).unwrap(), None).await;
    assert!(!hit, "variant must miss the exact cache");
}

#[tokio::test]
async fn openai_responses_exact_hit_and_instruction_isolation() {
    let body = json!({
        "model": "gpt-4.1",
        "instructions": "Answer briefly.",
        "input": "What is 2 + 2?"
    });
    assert_exact_hit_roundtrip(body.clone(), br#""4""#).await;

    let different_instructions = json!({
        "model": "gpt-4.1",
        "instructions": "Answer in Spanish.",
        "input": "What is 2 + 2?"
    });
    assert_exact_miss_for_variant(body, different_instructions, br#""4""#).await;
}

#[tokio::test]
async fn openai_responses_tools_and_previous_response_isolation() {
    let base = json!({
        "model": "gpt-4.1",
        "input": "Weather in NYC?",
        "tools": [{"type": "function", "name": "get_weather"}]
    });
    let other_tools = json!({
        "model": "gpt-4.1",
        "input": "Weather in NYC?",
        "tools": [{"type": "function", "name": "get_time"}]
    });
    assert_exact_miss_for_variant(base, other_tools, br#""sunny""#).await;

    let with_previous = json!({
        "model": "gpt-4.1",
        "input": "Continue.",
        "previous_response_id": "resp_1"
    });
    let other_previous = json!({
        "model": "gpt-4.1",
        "input": "Continue.",
        "previous_response_id": "resp_2"
    });
    assert_exact_miss_for_variant(with_previous, other_previous, br#""ok""#).await;
}

#[tokio::test]
async fn openai_responses_item_roles_isolate_identical_text() {
    let user_input = json!({
        "model": "gpt-4.1",
        "input": [{
            "role": "user",
            "content": [{"type": "input_text", "text": "Continue."}]
        }]
    });
    let assistant_input = json!({
        "model": "gpt-4.1",
        "input": [{
            "role": "assistant",
            "content": [{"type": "input_text", "text": "Continue."}]
        }]
    });
    assert_exact_miss_for_variant(user_input, assistant_input, br#""ok""#).await;
}

#[tokio::test]
async fn messages_native_tool_call_state_isolates_exact_keys() {
    let paris = json!({
        "model": "gpt-4.1",
        "messages": [{
            "role": "assistant",
            "content": "",
            "tool_calls": [{
                "id": "call_1",
                "type": "function",
                "function": {"name": "lookup", "arguments": "{\"city\":\"Paris\"}"}
            }]
        }]
    });
    let lyon = json!({
        "model": "gpt-4.1",
        "messages": [{
            "role": "assistant",
            "content": "",
            "tool_calls": [{
                "id": "call_1",
                "type": "function",
                "function": {"name": "lookup", "arguments": "{\"city\":\"Lyon\"}"}
            }]
        }]
    });
    assert_exact_miss_for_variant(paris, lyon, br#""ok""#).await;

    assert_exact_miss_for_variant(
        json!({"messages": [{"role": "tool", "name": "lookup_a", "tool_call_id": "call_1", "content": "done"}]}),
        json!({"messages": [{"role": "tool", "name": "lookup_b", "tool_call_id": "call_1", "content": "done"}]}),
        br#""ok""#,
    )
    .await;
    assert_exact_miss_for_variant(
        json!({"messages": [{"role": "tool", "name": "lookup", "tool_call_id": "call_1", "content": "done"}]}),
        json!({"messages": [{"role": "tool", "name": "lookup", "tool_call_id": "call_2", "content": "done"}]}),
        br#""ok""#,
    )
    .await;
}

#[tokio::test]
async fn gemini_contents_exact_hit_and_generation_config_isolation() {
    let body = json!({
        "model": "gemini-2.5-flash",
        "contents": [{"role": "user", "parts": [{"text": "What is 2 + 2?"}]}],
        "generationConfig": {"temperature": 0}
    });
    assert_exact_hit_roundtrip(body.clone(), br#""4""#).await;

    let other_temp = json!({
        "model": "gemini-2.5-flash",
        "contents": [{"role": "user", "parts": [{"text": "What is 2 + 2?"}]}],
        "generationConfig": {"temperature": 0.9}
    });
    assert_exact_miss_for_variant(body, other_temp, br#""4""#).await;
}

#[tokio::test]
async fn gemini_system_instruction_and_tool_isolation() {
    let body = json!({
        "model": "gemini-2.5-flash",
        "systemInstruction": {"parts": [{"text": "Be terse."}]},
        "contents": [{"role": "user", "parts": [{"text": "Capital of France?"}]}],
        "tools": [{"functionDeclarations": [{"name": "lookup"}]}]
    });
    let other_system = json!({
        "model": "gemini-2.5-flash",
        "systemInstruction": {"parts": [{"text": "Be verbose."}]},
        "contents": [{"role": "user", "parts": [{"text": "Capital of France?"}]}],
        "tools": [{"functionDeclarations": [{"name": "lookup"}]}]
    });
    assert_exact_miss_for_variant(body.clone(), other_system, br#""Paris""#).await;

    let other_tools = json!({
        "model": "gemini-2.5-flash",
        "systemInstruction": {"parts": [{"text": "Be terse."}]},
        "contents": [{"role": "user", "parts": [{"text": "Capital of France?"}]}],
        "tools": [{"functionDeclarations": [{"name": "search"}]}]
    });
    assert_exact_miss_for_variant(body, other_tools, br#""Paris""#).await;
}

#[tokio::test]
async fn cohere_chat_history_exact_hit_and_preamble_isolation() {
    let body = json!({
        "model": "command-r",
        "preamble": "You are helpful.",
        "chat_history": [{"role": "USER", "message": "Hi"}],
        "message": "What is 2 + 2?"
    });
    assert_exact_hit_roundtrip(body.clone(), br#""4""#).await;

    let other_preamble = json!({
        "model": "command-r",
        "preamble": "You are a pirate.",
        "chat_history": [{"role": "USER", "message": "Hi"}],
        "message": "What is 2 + 2?"
    });
    assert_exact_miss_for_variant(body.clone(), other_preamble, br#""4""#).await;

    let stateful = json!({
        "model": "command-r",
        "conversation_id": "victim",
        "message": "summarize this"
    });
    let other_conversation = json!({
        "model": "command-r",
        "conversation_id": "attacker",
        "message": "summarize this"
    });
    assert_exact_miss_for_variant(stateful, other_conversation, br#""victim summary""#).await;
}

#[tokio::test]
async fn legacy_prompt_tgi_inputs_and_titan_input_text_exact_hits() {
    assert_exact_hit_roundtrip(
        json!({
            "model": "gpt-3.5-turbo-instruct",
            "prompt": "What is 2 + 2?",
            "temperature": 0
        }),
        br#""4""#,
    )
    .await;

    assert_exact_hit_roundtrip(
        json!({
            "inputs": "What is 2 + 2?",
            "parameters": {"temperature": 0.0, "max_new_tokens": 16}
        }),
        br#""4""#,
    )
    .await;

    assert_exact_hit_roundtrip(
        json!({
            "inputText": "What is 2 + 2?",
            "textGenerationConfig": {"temperature": 0.0, "maxTokenCount": 32}
        }),
        br#""4""#,
    )
    .await;
}

#[tokio::test]
async fn legacy_tgi_titan_generation_control_misses() {
    assert_exact_miss_for_variant(
        json!({"prompt": "Hello", "temperature": 0.0}),
        json!({"prompt": "Hello", "temperature": 1.0}),
        br#""hi""#,
    )
    .await;
    assert_exact_miss_for_variant(
        json!({"inputs": "Hello", "parameters": {"temperature": 0.0}}),
        json!({"inputs": "Hello", "parameters": {"temperature": 1.0}}),
        br#""hi""#,
    )
    .await;
    assert_exact_miss_for_variant(
        json!({
            "inputText": "Hello",
            "textGenerationConfig": {"temperature": 0.0}
        }),
        json!({
            "inputText": "Hello",
            "textGenerationConfig": {"temperature": 1.0}
        }),
        br#""hi""#,
    )
    .await;
}

#[tokio::test]
async fn messages_provider_native_generation_controls_isolate_exact_keys() {
    assert_exact_miss_for_variant(
        json!({
            "messages": [{"role": "user", "content": "Write a report"}],
            "max_completion_tokens": 32
        }),
        json!({
            "messages": [{"role": "user", "content": "Write a report"}],
            "max_completion_tokens": 2048
        }),
        br#""short""#,
    )
    .await;
    assert_exact_miss_for_variant(
        json!({
            "messages": [{"role": "user", "content": "Write a report"}],
            "stop_sequences": ["END"]
        }),
        json!({
            "messages": [{"role": "user", "content": "Write a report"}],
            "stop_sequences": ["STOP"]
        }),
        br#""stopped""#,
    )
    .await;
}

#[tokio::test]
async fn anthropic_messages_system_still_exact_hits() {
    let body = json!({
        "model": "claude-3-5-sonnet-20241022",
        "system": "Be concise.",
        "messages": [{"role": "user", "content": "Say hi."}]
    });
    assert_exact_hit_roundtrip(body, br#""hi""#).await;
}

#[tokio::test]
async fn unknown_and_ambiguous_shapes_bypass_caching() {
    let plugin = make_plugin(json!({"ttl_seconds": 300}));

    for body in [
        json!({"model": "gpt-4o", "foo": "bar"}),
        json!({
            "model": "gpt-4o",
            "messages": [{"role": "user", "content": "hi"}],
            "contents": [{"role": "user", "parts": [{"text": "hi"}]}]
        }),
        json!({
            "model": "gpt-4o",
            "prompt": "hi",
            "inputText": "hi"
        }),
        json!({
            "model": "gpt-4o",
            "messages": [{"role": "user", "content": "hi"}],
            "input": "hi"
        }),
    ] {
        let body_str = serde_json::to_string(&body).unwrap();
        let (ctx, result) = run_before_proxy(&plugin, &body_str, None).await;
        assert!(matches!(result, PluginResult::Continue));
        assert_eq!(
            staged_status(&plugin, &ctx),
            Some("BYPASS"),
            "unknown/ambiguous body must bypass: {body}"
        );
        assert!(
            !has_staged_cache_key(&plugin, &ctx),
            "bypass must not stage a cache key"
        );
    }
}

#[tokio::test]
async fn gemini_and_responses_multimodal_fingerprints_isolate_exact_keys() {
    let gemini_a = json!({
        "model": "gemini-2.5-flash",
        "contents": [{
            "role": "user",
            "parts": [
                {"text": "Describe this"},
                {"inlineData": {"mimeType": "image/png", "data": "aaa"}}
            ]
        }]
    });
    let gemini_b = json!({
        "model": "gemini-2.5-flash",
        "contents": [{
            "role": "user",
            "parts": [
                {"text": "Describe this"},
                {"inlineData": {"mimeType": "image/png", "data": "bbb"}}
            ]
        }]
    });
    assert_exact_miss_for_variant(gemini_a, gemini_b, br#""img""#).await;

    let responses_a = json!({
        "model": "gpt-4.1",
        "input": [{
            "role": "user",
            "content": [
                {"type": "input_text", "text": "Describe this"},
                {"type": "input_image", "image_url": "https://example.com/a.png"}
            ]
        }]
    });
    let responses_b = json!({
        "model": "gpt-4.1",
        "input": [{
            "role": "user",
            "content": [
                {"type": "input_text", "text": "Describe this"},
                {"type": "input_image", "image_url": "https://example.com/b.png"}
            ]
        }]
    });
    assert_exact_miss_for_variant(responses_a, responses_b, br#""img""#).await;
}

#[tokio::test]
async fn gemini_native_function_call_blocks_are_fingerprinted() {
    let with_call = json!({
        "model": "gemini-2.5-flash",
        "contents": [{
            "role": "model",
            "parts": [{
                "functionCall": {"name": "lookup", "args": {"q": "paris"}}
            }]
        }, {
            "role": "user",
            "parts": [{"text": "thanks"}]
        }]
    });
    let other_call = json!({
        "model": "gemini-2.5-flash",
        "contents": [{
            "role": "model",
            "parts": [{
                "functionCall": {"name": "lookup", "args": {"q": "lyon"}}
            }]
        }, {
            "role": "user",
            "parts": [{"text": "thanks"}]
        }]
    });
    assert_exact_miss_for_variant(with_call, other_call, br#""ok""#).await;
}

#[tokio::test]
async fn provider_family_semantic_hit_and_instruction_isolation() {
    let mock_server = MockServer::start().await;
    mount_embedding_mock(&mock_server, 6).await;
    let plugin = make_plugin(semantic_config(&mock_server));

    let gemini1 = json!({
        "model": "gemini-2.5-flash",
        "systemInstruction": {"parts": [{"text": "JSON only."}]},
        "contents": [{"role": "user", "parts": [{"text": "Capital of France?"}]}],
        "generationConfig": {"temperature": 0}
    });
    let gemini2_same_scope = json!({
        "model": "gemini-2.5-flash",
        "systemInstruction": {"parts": [{"text": "JSON only."}]},
        "contents": [{"role": "user", "parts": [{"text": "What city is France's capital?"}]}],
        "generationConfig": {"temperature": 0}
    });
    store_response(
        &plugin,
        &serde_json::to_string(&gemini1).unwrap(),
        None,
        br#"{"city":"Paris"}"#,
    )
    .await;
    let (ctx, result) = run_before_proxy(
        &plugin,
        &serde_json::to_string(&gemini2_same_scope).unwrap(),
        None,
    )
    .await;
    match result {
        PluginResult::RejectBinary { headers, body, .. } => {
            assert_eq!(
                headers.get("x-ai-cache-match").map(String::as_str),
                Some("semantic")
            );
            assert_eq!(&body[..], br#"{"city":"Paris"}"#);
            assert_eq!(staged_match(&plugin, &ctx), Some("semantic"));
        }
        other => panic!("expected Gemini semantic HIT, got {other:?}"),
    }

    let gemini_other_instruction = json!({
        "model": "gemini-2.5-flash",
        "systemInstruction": {"parts": [{"text": "Plain text only."}]},
        "contents": [{"role": "user", "parts": [{"text": "What city is France's capital?"}]}],
        "generationConfig": {"temperature": 0}
    });
    let isolated = run_before_proxy_get_status(
        &plugin,
        &serde_json::to_string(&gemini_other_instruction).unwrap(),
        None,
    )
    .await;
    assert!(
        !isolated,
        "Gemini semantic hits must not cross systemInstruction scopes"
    );

    let responses1 = json!({
        "model": "gpt-4.1",
        "instructions": "JSON only.",
        "input": "Capital of France?"
    });
    let responses2 = json!({
        "model": "gpt-4.1",
        "instructions": "JSON only.",
        "input": "What city is France's capital?"
    });
    store_response(
        &plugin,
        &serde_json::to_string(&responses1).unwrap(),
        None,
        br#"{"city":"Paris"}"#,
    )
    .await;
    let hit =
        run_before_proxy_get_status(&plugin, &serde_json::to_string(&responses2).unwrap(), None)
            .await;
    assert!(
        hit,
        "Responses family should semantic-hit within one instruction scope"
    );

    let responses_isolated = json!({
        "model": "gpt-4.1",
        "instructions": "Plain text only.",
        "input": "What city is France's capital?"
    });
    let isolated = run_before_proxy_get_status(
        &plugin,
        &serde_json::to_string(&responses_isolated).unwrap(),
        None,
    )
    .await;
    assert!(
        !isolated,
        "Responses semantic hits must not cross instructions scopes"
    );
}

#[tokio::test]
async fn messages_semantic_scope_isolates_tool_state_and_native_controls() {
    let mock_server = MockServer::start().await;
    // One embedding for the staged base entry plus one for each of the seven
    // deliberately isolated variants below.
    mount_embedding_mock(&mock_server, 8).await;
    let plugin = make_plugin(semantic_config(&mock_server));

    let base = json!({
        "model": "gpt-4.1",
        "max_completion_tokens": 32,
        "top_k": 4,
        "stop_sequences": ["END"],
        "toolConfig": {"tools": [{"toolSpec": {"name": "lookup"}}]},
        "messages": [
            {
                "role": "assistant",
                "name": "planner",
                "content": "",
                "tool_calls": [{
                    "id": "call_1",
                    "type": "function",
                    "function": {"name": "lookup", "arguments": "{\"city\":\"Paris\"}"}
                }]
            },
            {"role": "tool", "tool_call_id": "call_1", "content": "sunny"},
            {"role": "user", "content": "What should I do next?"}
        ]
    });
    store_response(
        &plugin,
        &serde_json::to_string(&base).unwrap(),
        None,
        br#""walk""#,
    )
    .await;

    let mut variants = Vec::new();
    let mut changed_name = base.clone();
    changed_name["messages"][0]["name"] = json!("other_planner");
    variants.push(changed_name);
    let mut changed_tool_call = base.clone();
    changed_tool_call["messages"][0]["tool_calls"][0]["function"]["arguments"] =
        json!("{\"city\":\"Lyon\"}");
    variants.push(changed_tool_call);
    let mut changed_tool_call_id = base.clone();
    changed_tool_call_id["messages"][1]["tool_call_id"] = json!("call_2");
    variants.push(changed_tool_call_id);
    let mut changed_max = base.clone();
    changed_max["max_completion_tokens"] = json!(2048);
    variants.push(changed_max);
    let mut changed_stop = base.clone();
    changed_stop["stop_sequences"] = json!(["STOP"]);
    variants.push(changed_stop);
    let mut changed_top_k = base.clone();
    changed_top_k["top_k"] = json!(40);
    variants.push(changed_top_k);
    let mut changed_tool_config = base.clone();
    changed_tool_config["toolConfig"]["tools"][0]["toolSpec"]["name"] = json!("search");
    variants.push(changed_tool_config);

    for variant in variants {
        assert!(
            !run_before_proxy_get_status(&plugin, &serde_json::to_string(&variant).unwrap(), None)
                .await,
            "semantic lookup must not cross message tool state or provider-native controls"
        );
    }
}

#[tokio::test]
async fn cohere_titan_and_tgi_semantic_hits_respect_family_scope() {
    let mock_server = MockServer::start().await;
    // Three embedding requests per original provider family, plus the staged
    // and lookup requests for the cross-conversation Cohere isolation case.
    mount_embedding_mock(&mock_server, 11).await;
    let plugin = make_plugin(semantic_config(&mock_server));

    let cohere1 = json!({
        "model": "command-r",
        "preamble": "Be brief.",
        "message": "Capital of France?"
    });
    let cohere2 = json!({
        "model": "command-r",
        "preamble": "Be brief.",
        "message": "What city is France's capital?"
    });
    store_response(
        &plugin,
        &serde_json::to_string(&cohere1).unwrap(),
        None,
        br#""Paris""#,
    )
    .await;
    assert!(
        run_before_proxy_get_status(&plugin, &serde_json::to_string(&cohere2).unwrap(), None).await
    );
    let cohere_isolated = json!({
        "model": "command-r",
        "preamble": "Be poetic.",
        "message": "What city is France's capital?"
    });
    assert!(
        !run_before_proxy_get_status(
            &plugin,
            &serde_json::to_string(&cohere_isolated).unwrap(),
            None
        )
        .await
    );

    let cohere_stateful = json!({
        "model": "command-r",
        "conversation_id": "victim",
        "message": "summarize this"
    });
    let cohere_other_conversation = json!({
        "model": "command-r",
        "conversation_id": "attacker",
        "message": "summarize this another way"
    });
    store_response(
        &plugin,
        &serde_json::to_string(&cohere_stateful).unwrap(),
        None,
        br#""victim summary""#,
    )
    .await;
    assert!(
        !run_before_proxy_get_status(
            &plugin,
            &serde_json::to_string(&cohere_other_conversation).unwrap(),
            None
        )
        .await,
        "Cohere semantic cache must not cross conversation_id scopes"
    );

    let tgi1 = json!({
        "inputs": "Capital of France?",
        "parameters": {"temperature": 0.0}
    });
    let tgi2 = json!({
        "inputs": "What city is France's capital?",
        "parameters": {"temperature": 0.0}
    });
    store_response(
        &plugin,
        &serde_json::to_string(&tgi1).unwrap(),
        None,
        br#""Paris""#,
    )
    .await;
    assert!(
        run_before_proxy_get_status(&plugin, &serde_json::to_string(&tgi2).unwrap(), None).await
    );
    let tgi_isolated = json!({
        "inputs": "What city is France's capital?",
        "parameters": {"temperature": 1.0}
    });
    assert!(
        !run_before_proxy_get_status(
            &plugin,
            &serde_json::to_string(&tgi_isolated).unwrap(),
            None
        )
        .await
    );

    let titan1 = json!({
        "inputText": "Capital of France?",
        "textGenerationConfig": {"temperature": 0.0}
    });
    let titan2 = json!({
        "inputText": "What city is France's capital?",
        "textGenerationConfig": {"temperature": 0.0}
    });
    store_response(
        &plugin,
        &serde_json::to_string(&titan1).unwrap(),
        None,
        br#""Paris""#,
    )
    .await;
    assert!(
        run_before_proxy_get_status(&plugin, &serde_json::to_string(&titan2).unwrap(), None).await
    );
    let titan_isolated = json!({
        "inputText": "What city is France's capital?",
        "textGenerationConfig": {"temperature": 1.0}
    });
    assert!(
        !run_before_proxy_get_status(
            &plugin,
            &serde_json::to_string(&titan_isolated).unwrap(),
            None
        )
        .await
    );
}

#[tokio::test]
async fn complex_provider_native_inputs_build_semantic_keys_without_collisions() {
    let mock_server = MockServer::start().await;
    mount_embedding_mock(&mock_server, 6).await;
    let plugin = make_plugin(semantic_config(&mock_server));

    let responses_pairs = [
        (
            json!({
                "model": "gpt-4.1",
                "input": [
                    "Seed context",
                    {"role": "user", "content": "Capital of France?"},
                    {
                        "role": "assistant",
                        "content": [{"type": "output_text", "text": "Considering it"}]
                    },
                    {"type": "input_text", "text": "Answer briefly"}
                ]
            }),
            json!({
                "model": "gpt-4.1",
                "input": [
                    "Different seed",
                    {"role": "user", "content": "Which city is France's capital?"},
                    {
                        "role": "assistant",
                        "content": [{"type": "output_text", "text": "Working on it"}]
                    },
                    {"type": "input_text", "text": "Use one word"}
                ]
            }),
        ),
        (
            json!({
                "model": "command-r",
                "chat_history": [
                    {"role": "SYSTEM", "message": "Use facts."},
                    {"role": "USER", "message": "Capital of France?"},
                    {"role": "CHATBOT", "content": ""},
                    {"message": "Relevant context"}
                ],
                "message": "Answer briefly."
            }),
            json!({
                "model": "command-r",
                "chat_history": [
                    {"role": "SYSTEM", "message": "Use facts."},
                    {"role": "USER", "message": "Which city is France's capital?"},
                    {"role": "CHATBOT", "content": ""},
                    {"message": "Different context"}
                ],
                "message": "Use one word."
            }),
        ),
        (
            json!({
                "model": "legacy-model",
                "prompt": ["Capital", {"country": "France"}, 1, true, null]
            }),
            json!({
                "model": "legacy-model",
                "prompt": ["Largest city", {"country": "France"}, 2, false, null]
            }),
        ),
    ];

    for (stored, lookup) in responses_pairs {
        store_response(
            &plugin,
            &serde_json::to_string(&stored).unwrap(),
            None,
            br#""semantic""#,
        )
        .await;
        assert!(
            run_before_proxy_get_status(&plugin, &serde_json::to_string(&lookup).unwrap(), None,)
                .await,
            "same-family structured prompt variants should semantic-hit"
        );
    }
}

#[tokio::test]
async fn reject_mode_detects_provider_native_multimodal_shapes() {
    let plugin = make_plugin(json!({
        "ttl_seconds": 300,
        "cache_multimodal": "reject"
    }));

    let cases = [
        (json!({"input": "plain Responses text"}), false),
        (
            json!({"input": {"type": "input_text", "text": "plain text"}}),
            false,
        ),
        (json!({"input": {"text": "plain untyped text"}}), false),
        (json!({"input": 7}), true),
        (json!({"input": {"type": "input_text"}}), true),
        (
            json!({"input": {"type": "input_image", "image_url": "image.png"}}),
            true,
        ),
        (
            json!({
                "contents": [{"parts": [{"text": "plain Gemini text"}]}],
                "systemInstruction": "plain instruction"
            }),
            false,
        ),
        (
            json!({
                "contents": [{"parts": [{"functionCall": {"name": "lookup"}}]}]
            }),
            true,
        ),
        (
            json!({
                "contents": [{"parts": [{"text": "plain Gemini text"}]}],
                "systemInstruction": {
                    "parts": [{"inlineData": {"mimeType": "image/png", "data": "aaa"}}]
                }
            }),
            true,
        ),
        (
            json!({
                "contents": [{"parts": [{"text": "plain Gemini text"}]}],
                "systemInstruction": [{"text": "plain instruction"}]
            }),
            false,
        ),
        (
            json!({
                "messages": [{"role": "user", "content": null}],
                "system": null
            }),
            false,
        ),
        (
            json!({
                "messages": [{"role": "user", "content": "plain text"}],
                "system": {"type": "image", "image_url": "system.png"}
            }),
            true,
        ),
    ];

    for (body, multimodal) in cases {
        let body_str = serde_json::to_string(&body).unwrap();
        let (ctx, result) = run_before_proxy(&plugin, &body_str, None).await;
        assert!(matches!(result, PluginResult::Continue));
        assert_eq!(
            staged_status(&plugin, &ctx),
            Some(if multimodal { "BYPASS" } else { "MISS" }),
            "unexpected reject-mode classification for {body}"
        );
    }
}

#[tokio::test]
async fn distinct_families_do_not_exact_or_semantic_collide() {
    let mock_server = MockServer::start().await;
    mount_embedding_mock(&mock_server, 2).await;
    let plugin = make_plugin(semantic_config(&mock_server));

    let messages = json!({
        "model": "shared-model",
        "messages": [{"role": "user", "content": "What is 2 + 2?"}]
    });
    let gemini = json!({
        "model": "shared-model",
        "contents": [{"role": "user", "parts": [{"text": "What is 2 + 2?"}]}]
    });
    store_response(
        &plugin,
        &serde_json::to_string(&messages).unwrap(),
        None,
        br#""messages-family""#,
    )
    .await;

    let (ctx, result) =
        run_before_proxy(&plugin, &serde_json::to_string(&gemini).unwrap(), None).await;
    assert!(
        matches!(result, PluginResult::Continue),
        "Gemini body must not exact-hit a Messages-family entry"
    );
    assert_eq!(staged_status(&plugin, &ctx).unwrap(), "MISS");
    assert_ne!(
        staged_match(&plugin, &ctx),
        Some("semantic"),
        "Gemini body must not semantic-hit a Messages-family entry"
    );
}

/// REGRESSION (issue #2267): sibling `ai_semantic_cache` instances must stage,
/// consume, store, and clear only their own cache key / embedding / scope.
/// Covers both priority orders with differing key policies and a
/// non-semantic + semantic pairing.
async fn run_two_instance_miss_store_semantic_hit(exact_first: bool) {
    let mock_server = MockServer::start().await;
    // One embedding for the shared miss, one for the later semantic lookup.
    mount_embedding_mock(&mock_server, 2).await;

    let exact = make_plugin(json!({
        "ttl_seconds": 600,
        "scope_by_consumer": false,
        "include_params_in_key": false,
        "semantic_similarity_enabled": false
    }));
    let mut semantic_cfg = semantic_config(&mock_server);
    semantic_cfg["scope_by_consumer"] = json!(false);
    semantic_cfg["include_params_in_key"] = json!(true);
    let semantic = make_plugin(semantic_cfg);

    assert_ne!(
        instance_id(&exact),
        instance_id(&semantic),
        "each ai_semantic_cache constructor must mint a distinct staging id"
    );
    assert_ne!(
        staging_key(&exact, "cache_key"),
        staging_key(&semantic, "cache_key")
    );

    let (first, second) = if exact_first {
        (&exact, &semantic)
    } else {
        (&semantic, &exact)
    };

    let body1 = json!({
        "model": "gpt-4o",
        "temperature": 0.2,
        "messages": [{"role": "user", "content": "What is the capital of France?"}]
    });
    let body1_str = serde_json::to_string(&body1).unwrap();
    let response_body = br#""Paris""#;

    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/v1/chat/completions".to_string(),
    );
    ctx.metadata
        .insert("request_body".to_string(), body1_str.clone());
    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/json".to_string());

    assert!(matches!(
        first.before_proxy(&mut ctx, &mut headers).await,
        PluginResult::Continue
    ));
    assert!(matches!(
        second.before_proxy(&mut ctx, &mut headers).await,
        PluginResult::Continue
    ));

    assert_eq!(staged_status(first, &ctx), Some("MISS"));
    assert_eq!(staged_status(second, &ctx), Some("MISS"));

    let first_key = staged_cache_key_value(first, &ctx)
        .expect("first instance must stage its own cache key")
        .to_string();
    let second_key = staged_cache_key_value(second, &ctx)
        .expect("second instance must stage its own cache key")
        .to_string();
    assert_ne!(
        first_key, second_key,
        "differing include_params_in_key policies must stage independent keys"
    );

    assert!(
        ai_semantic_cache_embedding(&ctx, instance_id(&exact)).is_none(),
        "non-semantic instance must not stage an embedding"
    );
    assert!(
        ai_semantic_cache_embedding(&ctx, instance_id(&semantic)).is_some(),
        "semantic miss must stage an embedding under its own instance id"
    );
    assert!(
        ai_semantic_cache_scope_key(&ctx, instance_id(&semantic)).is_some(),
        "semantic miss must stage a scope key under its own instance id"
    );

    let response_headers =
        HashMap::from([("content-type".to_string(), "application/json".to_string())]);
    first
        .on_final_response_body(&mut ctx, 200, &response_headers, response_body)
        .await;
    if exact_first {
        assert!(
            ai_semantic_cache_embedding(&ctx, instance_id(&semantic)).is_some(),
            "earlier exact store must not consume the semantic instance's embedding"
        );
        assert!(
            has_staged_cache_key(&semantic, &ctx),
            "earlier exact store must leave the semantic instance's cache key intact"
        );
    }
    second
        .on_final_response_body(&mut ctx, 200, &response_headers, response_body)
        .await;

    assert!(
        ai_semantic_cache_embedding(&ctx, instance_id(&semantic)).is_none(),
        "semantic store must consume only its own embedding"
    );
    assert!(
        !has_staged_cache_key(&exact, &ctx) && !has_staged_cache_key(&semantic, &ctx),
        "both instances must clear their store staging after a successful admit"
    );

    rebuild_ai_semantic_cache_vector_index(&semantic).await;

    // Exact instance exact-hits the identical prompt from its own store.
    let (ctx_exact_hit, exact_hit) = run_before_proxy(&exact, &body1_str, None).await;
    match exact_hit {
        PluginResult::RejectBinary {
            status_code, body, ..
        } => {
            assert_eq!(status_code, 200);
            assert_eq!(&body[..], response_body);
        }
        other => panic!("exact instance should HIT its own entry, got {other:?}"),
    }
    assert_eq!(staged_status(&exact, &ctx_exact_hit), Some("HIT"));
    assert!(
        !has_staged_cache_key(&exact, &ctx_exact_hit),
        "HIT path must clear only the hitting instance's lookup staging"
    );

    // Semantic instance semantic-hits a similar but non-identical prompt.
    let body2 = json!({
        "model": "gpt-4o",
        "temperature": 0.2,
        "messages": [{"role": "user", "content": "Which city is France's capital?"}]
    });
    let body2_str = serde_json::to_string(&body2).unwrap();
    let (ctx_semantic_hit, semantic_hit) = run_before_proxy(&semantic, &body2_str, None).await;
    match semantic_hit {
        PluginResult::RejectBinary {
            status_code,
            headers,
            body,
            ..
        } => {
            assert_eq!(status_code, 200);
            assert_eq!(
                headers.get("x-ai-cache-match").map(String::as_str),
                Some("semantic")
            );
            assert_eq!(&body[..], response_body);
        }
        other => panic!("semantic instance should semantic-HIT, got {other:?}"),
    }
    assert_eq!(staged_status(&semantic, &ctx_semantic_hit), Some("HIT"));
    assert_eq!(staged_match(&semantic, &ctx_semantic_hit), Some("semantic"));

    // Exact instance must still miss the non-identical prompt (no stolen vector).
    let (ctx_exact_miss, exact_miss) = run_before_proxy(&exact, &body2_str, None).await;
    assert!(
        matches!(exact_miss, PluginResult::Continue),
        "non-semantic instance must not inherit a sibling semantic hit"
    );
    assert_eq!(staged_status(&exact, &ctx_exact_miss), Some("MISS"));
}

#[tokio::test]
async fn multiple_instances_isolate_staging_in_both_priority_orders() {
    run_two_instance_miss_store_semantic_hit(true).await;
    run_two_instance_miss_store_semantic_hit(false).await;
}

#[tokio::test]
async fn reject_bypass_clears_only_current_instance_staging() {
    let text_cache = make_plugin(json!({
        "ttl_seconds": 300,
        "cache_multimodal": "exact_only",
        "scope_by_consumer": false
    }));
    let reject_cache = make_plugin(json!({
        "ttl_seconds": 300,
        "cache_multimodal": "reject",
        "scope_by_consumer": false
    }));

    let body = multimodal_image_url_body("https://example.com/a.png");
    let body_str = serde_json::to_string(&body).unwrap();

    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/v1/chat/completions".to_string(),
    );
    ctx.metadata.insert("request_body".to_string(), body_str);
    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/json".to_string());

    assert!(matches!(
        text_cache.before_proxy(&mut ctx, &mut headers).await,
        PluginResult::Continue
    ));
    assert_eq!(staged_status(&text_cache, &ctx), Some("MISS"));
    assert!(has_staged_cache_key(&text_cache, &ctx));

    assert!(matches!(
        reject_cache.before_proxy(&mut ctx, &mut headers).await,
        PluginResult::Continue
    ));
    assert_eq!(staged_status(&reject_cache, &ctx), Some("BYPASS"));
    assert!(
        !has_staged_cache_key(&reject_cache, &ctx),
        "reject bypass must clear only the reject instance's staging"
    );
    assert!(
        has_staged_cache_key(&text_cache, &ctx),
        "reject bypass must not clear a sibling instance's staged cache key"
    );
    assert_eq!(staged_status(&text_cache, &ctx), Some("MISS"));
}

// === Semantic cache byte-budget / embedding bounds (#3061/#3062/#3063) ===

#[tokio::test]
async fn test_hnsw_rebuild_peak_charges_old_and_candidate_generations() {
    let plugin = make_plugin(json!({
        "ttl_seconds": 600,
        "scope_by_consumer": false,
        "max_total_size_bytes": 1_048_576,
        "semantic_similarity_enabled": true,
        "semantic_embedding_endpoint": "http://127.0.0.1:9/embeddings",
        "semantic_embedding_api_key": "test-key",
        "semantic_similarity_threshold": 0.95
    }));

    let request = json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "vector seed for budget peak"}]
    });
    let cache_key = miss_cache_key(&plugin, &serde_json::to_string(&request).unwrap()).await;
    store_with_cache_key(
        &plugin,
        &cache_key,
        br#""seed""#,
        Some(vec![1.0, 0.0, 0.0, 0.0]),
        Some("scope-peak".to_string()),
    )
    .await;

    let first_peak = rebuild_ai_semantic_cache_vector_index(&plugin).await;
    let after_first = assert_size_accounting_exact(&plugin);
    let first_snapshot = ai_semantic_cache_vector_snapshot_accounted_bytes_for_test(&plugin);
    assert!(
        first_snapshot > 0,
        "first rebuild must publish an HNSW generation"
    );
    assert!(
        after_first >= first_snapshot,
        "published HNSW bytes must be charged against the shared budget"
    );

    // Second rebuild overlaps the published generation with a candidate lease.
    let second_peak = rebuild_ai_semantic_cache_vector_index(&plugin).await;
    let after_second = assert_size_accounting_exact(&plugin);
    assert!(
        second_peak >= after_second.saturating_add(first_snapshot),
        "peak retained bytes during rebuild must cover old + candidate generations \
         (peak={second_peak}, after={after_second}, prior_snapshot={first_snapshot}, first_peak={first_peak})"
    );
    assert_eq!(
        ai_semantic_cache_cache_budget_used_for_test(&plugin),
        after_second
    );
}

#[tokio::test]
async fn test_hnsw_rebuild_budget_failure_releases_candidate_lease() {
    let plugin = make_plugin(json!({
        "ttl_seconds": 600,
        "scope_by_consumer": false,
        "max_entry_size_bytes": 65_536,
        "max_total_size_bytes": 65_536,
        "semantic_similarity_enabled": true,
        "semantic_embedding_endpoint": "http://127.0.0.1:9/embeddings",
        "semantic_embedding_api_key": "test-key",
        "semantic_similarity_threshold": 0.95
    }));

    let request = json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "vector seed for budget failure"}]
    });
    let cache_key = miss_cache_key(&plugin, &serde_json::to_string(&request).unwrap()).await;
    store_with_cache_key(
        &plugin,
        &cache_key,
        br#""seed""#,
        Some(vec![1.0, 0.0, 0.0]),
        Some("scope-fail".to_string()),
    )
    .await;
    let _ = rebuild_ai_semantic_cache_vector_index(&plugin).await;
    let before = assert_size_accounting_exact(&plugin);
    assert!(ai_semantic_cache_vector_snapshot_accounted_bytes_for_test(&plugin) > 0);

    let rejected = ai_semantic_cache_force_vector_rebuild_budget_failure_for_test(&plugin).await;
    assert!(
        rejected,
        "saturated budget must reject the candidate rebuild reservation"
    );
    assert_eq!(assert_size_accounting_exact(&plugin), before);
    assert!(
        ai_semantic_cache_vector_index_dirty_for_test(&plugin),
        "failed rebuild must leave the index dirty for retry"
    );
}

#[tokio::test]
async fn test_embedding_response_rejects_oversize_body() {
    let mock_server = MockServer::start().await;
    let huge = format!(r#"{{"embedding":[{}]}}"#, "0.0,".repeat(300_000) + "1.0");
    assert!(
        huge.len() > 1024 * 1024,
        "fixture must exceed the embedding response byte cap"
    );
    Mock::given(method("POST"))
        .and(path("/embeddings"))
        .respond_with(ResponseTemplate::new(200).set_body_string(huge))
        .expect(1)
        .mount(&mock_server)
        .await;

    let plugin = make_plugin(json!({
        "semantic_similarity_enabled": true,
        "semantic_embedding_endpoint": format!("{}/embeddings", mock_server.uri()),
        "semantic_embedding_api_key": "test-key",
        "scope_by_consumer": false
    }));
    let body = json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "oversize embedding body"}]
    });
    let (ctx, result) =
        run_before_proxy(&plugin, &serde_json::to_string(&body).unwrap(), None).await;
    assert!(matches!(result, PluginResult::Continue));
    assert_eq!(staged_status(&plugin, &ctx).unwrap(), "MISS");
    assert!(
        ai_semantic_cache_embedding(&ctx, instance_id(&plugin)).is_none(),
        "oversize embedding bodies must not stage a vector"
    );
}

#[tokio::test]
async fn test_embedding_response_rejects_oversize_dimension() {
    let mock_server = MockServer::start().await;
    let mut embedding = vec![0.0; 16_385];
    embedding[0] = 1.0;
    Mock::given(method("POST"))
        .and(path("/embeddings"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": [{"embedding": embedding}]
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let plugin = make_plugin(json!({
        "semantic_similarity_enabled": true,
        "semantic_embedding_endpoint": format!("{}/embeddings", mock_server.uri()),
        "semantic_embedding_api_key": "test-key",
        "scope_by_consumer": false
    }));
    let body = json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "oversize embedding dimension"}]
    });
    let (ctx, result) =
        run_before_proxy(&plugin, &serde_json::to_string(&body).unwrap(), None).await;
    assert!(matches!(result, PluginResult::Continue));
    assert_eq!(staged_status(&plugin, &ctx).unwrap(), "MISS");
    assert!(
        ai_semantic_cache_embedding(&ctx, instance_id(&plugin)).is_none(),
        "adversarial embedding dimensions must not stage a vector"
    );
}

#[tokio::test]
async fn large_finite_embedding_components_normalize_without_zero_collapse() {
    // Squaring ~3e38 in f32 overflows the norm to +inf and previously normalized
    // every component to 0, admitting an invalid zero vector. f64 reduction must
    // keep large finite provider values on a unit-length vector.
    let mock_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/embeddings"))
        .and(header("authorization", "Bearer test-key"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": [{"embedding": [3.0e38_f32, f32::from_bits(1), 0.0]}]
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let plugin = make_plugin(json!({
        "semantic_similarity_enabled": true,
        "semantic_embedding_endpoint": format!("{}/embeddings", mock_server.uri()),
        "semantic_embedding_api_key": "test-key",
        "scope_by_consumer": false
    }));
    let body = json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "large finite embedding components"}]
    });
    let (ctx, result) =
        run_before_proxy(&plugin, &serde_json::to_string(&body).unwrap(), None).await;
    assert!(matches!(result, PluginResult::Continue));
    assert_eq!(staged_status(&plugin, &ctx).unwrap(), "MISS");
    let embedding = ai_semantic_cache_embedding(&ctx, instance_id(&plugin))
        .expect("large finite embeddings must stage a normalized vector");
    assert_eq!(embedding.len(), 3);
    assert!(
        embedding.iter().all(|value| value.is_finite()),
        "normalized embedding must remain finite: {embedding:?}"
    );
    assert!(
        embedding.iter().any(|value| *value != 0.0),
        "large finite overflow must not collapse to an all-zero vector: {embedding:?}"
    );
    let unit_norm = embedding
        .iter()
        .fold(0.0_f64, |acc, value| {
            acc + f64::from(*value) * f64::from(*value)
        })
        .sqrt();
    assert!(
        (unit_norm - 1.0).abs() < 1.0e-4,
        "normalized embedding must have unit length, got {unit_norm}"
    );
}

#[tokio::test]
async fn invalid_first_embedding_does_not_pin_learned_dimension() {
    // An invalid first provider response must fail closed without initializing
    // embedding_dimension, so a later valid vector of a different length is
    // still admitted.
    let mock_server = MockServer::start().await;
    let calls = Arc::new(AtomicUsize::new(0));
    let responder_calls = Arc::clone(&calls);
    Mock::given(method("POST"))
        .and(path("/embeddings"))
        .and(header("authorization", "Bearer test-key"))
        .respond_with(move |_request: &Request| {
            let call = responder_calls.fetch_add(1, Ordering::AcqRel) + 1;
            if call == 1 {
                ResponseTemplate::new(200).set_body_json(json!({
                    "data": [{"embedding": [0.0, 0.0, 0.0]}]
                }))
            } else {
                ResponseTemplate::new(200).set_body_json(json!({
                    "data": [{"embedding": [0.0, 1.0, 0.0, 0.0]}]
                }))
            }
        })
        .expect(2)
        .mount(&mock_server)
        .await;

    let plugin = make_plugin(json!({
        "semantic_similarity_enabled": true,
        "semantic_embedding_endpoint": format!("{}/embeddings", mock_server.uri()),
        "semantic_embedding_api_key": "test-key",
        "scope_by_consumer": false
    }));

    let first_body = json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "invalid first embedding"}]
    });
    let (first_ctx, first_result) =
        run_before_proxy(&plugin, &serde_json::to_string(&first_body).unwrap(), None).await;
    assert!(matches!(first_result, PluginResult::Continue));
    assert_eq!(staged_status(&plugin, &first_ctx).unwrap(), "MISS");
    assert!(
        ai_semantic_cache_embedding(&first_ctx, instance_id(&plugin)).is_none(),
        "zero-length first embedding must not stage or pin a dimension"
    );

    let second_body = json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "valid second embedding different dim"}]
    });
    let (second_ctx, second_result) =
        run_before_proxy(&plugin, &serde_json::to_string(&second_body).unwrap(), None).await;
    assert!(matches!(second_result, PluginResult::Continue));
    assert_eq!(staged_status(&plugin, &second_ctx).unwrap(), "MISS");
    let embedding = ai_semantic_cache_embedding(&second_ctx, instance_id(&plugin))
        .expect("valid later embedding must be admitted after an invalid first response");
    assert_eq!(
        embedding.len(),
        4,
        "learned dimension must come from the first successfully admitted vector"
    );
    assert_eq!(calls.load(Ordering::Acquire), 2);
}

#[test]
fn semantic_vector_max_candidates_rejects_above_deployment_hard_cap() {
    let at_cap = AiSemanticCache::new(
        &json!({
            "semantic_similarity_enabled": true,
            "semantic_embedding_endpoint": "http://127.0.0.1:9/embeddings",
            "semantic_vector_max_candidates": 1024,
        }),
        PluginHttpClient::default(),
    );
    assert!(
        at_cap.is_ok(),
        "hard-cap boundary must be accepted: {:?}",
        at_cap.err()
    );

    let above = AiSemanticCache::new(
        &json!({
            "semantic_similarity_enabled": true,
            "semantic_embedding_endpoint": "http://127.0.0.1:9/embeddings",
            "semantic_vector_max_candidates": 1025,
        }),
        PluginHttpClient::default(),
    );
    let Err(error) = above else {
        panic!("semantic_vector_max_candidates above hard cap must be rejected");
    };
    assert!(
        error.contains("semantic_vector_max_candidates") && error.contains("1024"),
        "unexpected admission error: {error}"
    );
}

#[tokio::test]
async fn test_canonical_numeric_params_still_collapse_for_exact_keys() {
    // Intentionally preserved structural canonicalization: 1 / 1.0 / 1e0 must
    // still share an exact key when sampling params are included.
    let plugin = make_plugin(json!({
        "ttl_seconds": 300,
        "scope_by_consumer": false,
        "include_params_in_key": true
    }));
    let body_int = json!({
        "model": "gpt-4o",
        "temperature": 1,
        "messages": [{"role": "user", "content": "canonical params"}]
    });
    store_response(
        &plugin,
        &serde_json::to_string(&body_int).unwrap(),
        None,
        br#""ok""#,
    )
    .await;

    let body_float = json!({
        "model": "gpt-4o",
        "temperature": 1.0,
        "messages": [{"role": "user", "content": "canonical params"}]
    });
    let hit =
        run_before_proxy_get_status(&plugin, &serde_json::to_string(&body_float).unwrap(), None)
            .await;
    assert!(
        hit,
        "canonical numeric sampling-parameter forms remain exact-key equivalent"
    );
}

/// #3076: within one proxy, a cached response for request path A must not be
/// replayed to a distinct request path B carrying an identical body. The same
/// path + body must still hit.
#[tokio::test]
async fn distinct_request_paths_do_not_collide_within_one_proxy() {
    async fn drive(
        plugin: &AiSemanticCache,
        proxy: &Arc<ferrum_edge::config::types::Proxy>,
        path: &str,
        body_str: &str,
    ) -> (RequestContext, PluginResult) {
        let mut ctx = RequestContext::new(
            "127.0.0.1".to_string(),
            "POST".to_string(),
            path.to_string(),
        );
        ctx.matched_proxy = Some(Arc::clone(proxy));
        ctx.metadata
            .insert("request_body".to_string(), body_str.to_string());
        let mut headers = HashMap::new();
        headers.insert("content-type".to_string(), "application/json".to_string());
        let result = plugin.before_proxy(&mut ctx, &mut headers).await;
        (ctx, result)
    }

    let plugin = make_plugin(json!({
        "ttl_seconds": 600,
        "scope_by_consumer": false
    }));
    let proxy = Arc::new(create_test_proxy());
    let body = json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "same body, different route"}]
    });
    let body_str = serde_json::to_string(&body).unwrap();

    // Populate the cache under path A.
    let (mut ctx_a, miss_a) = drive(&plugin, &proxy, "/v1/chat/completions", &body_str).await;
    assert!(
        matches!(miss_a, PluginResult::Continue),
        "path A first request must miss"
    );
    let mut resp_headers = HashMap::new();
    resp_headers.insert("content-type".to_string(), "application/json".to_string());
    let _ = plugin
        .on_final_response_body(&mut ctx_a, 200, &resp_headers, br#"{"route":"A"}"#)
        .await;

    // Same proxy + path + body must now hit.
    let (_ctx_a2, hit_a) = drive(&plugin, &proxy, "/v1/chat/completions", &body_str).await;
    assert!(
        matches!(hit_a, PluginResult::RejectBinary { .. }),
        "identical path + body must hit the entry we just stored"
    );

    // A distinct path with the identical body/proxy must not replay A's response.
    let (_ctx_b, miss_b) = drive(&plugin, &proxy, "/v2/responses", &body_str).await;
    assert!(
        matches!(miss_b, PluginResult::Continue),
        "a distinct route within the same proxy must not receive another route's cached response"
    );
}

// === Correction-round coverage for #3073–#3076 / #3074 hard caps ===

#[test]
fn redis_mode_requires_integrity_key_and_rejects_over_hard_caps() {
    let missing = AiSemanticCache::new(
        &json!({
            "sync_mode": "redis",
            "redis_url": "redis://127.0.0.1:6379/0",
        }),
        PluginHttpClient::default(),
    );
    assert!(
        missing.is_err(),
        "redis mode without redis_integrity_key must fail closed"
    );

    let short = AiSemanticCache::new(
        &json!({
            "sync_mode": "redis",
            "redis_url": "redis://127.0.0.1:6379/0",
            "redis_integrity_key": "too-short",
        }),
        PluginHttpClient::default(),
    );
    assert!(short.is_err(), "short integrity keys must be rejected");

    assert!(
        AiSemanticCache::new(
            &json!({"max_entry_size_bytes": 16 * 1024 * 1024 + 1}),
            PluginHttpClient::default(),
        )
        .is_err(),
        "max_entry_size_bytes above the deployment hard cap must be rejected"
    );
    assert!(
        AiSemanticCache::new(
            &json!({
                "max_entry_size_bytes": 2 * 1024 * 1024,
                "max_total_size_bytes": 1024 * 1024,
            }),
            PluginHttpClient::default(),
        )
        .is_err(),
        "max_entry_size_bytes > max_total_size_bytes must be rejected"
    );
}

#[tokio::test]
async fn maintenance_workers_stage_commit_and_abort_on_drop() {
    let plugin = make_plugin(json!({"ttl_seconds": 600, "max_entries": 3}));
    assert!(
        !ai_semantic_cache_maintenance_staged_for_test(&plugin),
        "constructors must not start maintenance without a runtime activation"
    );

    plugin
        .start_background_tasks()
        .expect("start_background_tasks must succeed on a Tokio runtime");
    assert!(ai_semantic_cache_maintenance_staged_for_test(&plugin));
    assert!(!ai_semantic_cache_maintenance_committed_for_test(&plugin));
    assert_eq!(
        ai_semantic_cache_maintenance_handle_count_for_test(&plugin),
        1
    );

    // Activation rollback: drop before commit must abort staged workers.
    drop(plugin);

    let plugin = make_plugin(json!({
        "ttl_seconds": 600,
        "max_entries": 3,
        "semantic_similarity_enabled": true,
        "semantic_embedding_endpoint": "http://127.0.0.1:9/embeddings",
    }));
    plugin
        .start_background_tasks()
        .expect("semantic mode stages cleanup + rebuild workers");
    assert_eq!(
        ai_semantic_cache_maintenance_handle_count_for_test(&plugin),
        2
    );
    plugin.commit_background_tasks();
    assert!(ai_semantic_cache_maintenance_committed_for_test(&plugin));

    // Hot-path notification and the synchronous external test seam both remain
    // available while production cleanup runs only on the lifecycle worker.
    ai_semantic_cache_notify_cleanup_for_test(&plugin);
    ai_semantic_cache_force_cleanup_for_test(&plugin);
    drop(plugin);
}

#[tokio::test]
async fn identical_semantic_misses_coalesce_to_one_embedding_call() {
    let mock_server = MockServer::start().await;
    // Delayed so all waiters attach before the leader publishes.
    Mock::given(method("POST"))
        .and(path("/embeddings"))
        .and(header("authorization", "Bearer test-key"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_delay(Duration::from_millis(150))
                .set_body_json(json!({
                    "data": [{"embedding": [1.0, 0.0, 0.0]}]
                })),
        )
        .expect(1)
        .mount(&mock_server)
        .await;

    let plugin = Arc::new(make_plugin(semantic_config(&mock_server)));
    let body = json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "coalesce me"}]
    });
    let body_str = serde_json::to_string(&body).unwrap();
    let proxy = Arc::new(create_test_proxy());
    let start = Arc::new(tokio::sync::Barrier::new(13));

    let mut tasks = Vec::new();
    for _ in 0..12 {
        let plugin = Arc::clone(&plugin);
        let body_str = body_str.clone();
        let proxy = Arc::clone(&proxy);
        let start = Arc::clone(&start);
        tasks.push(tokio::spawn(async move {
            start.wait().await;
            let mut ctx = RequestContext::new(
                "127.0.0.1".to_string(),
                "POST".to_string(),
                "/v1/chat/completions".to_string(),
            );
            ctx.matched_proxy = Some(proxy);
            ctx.metadata.insert("request_body".to_string(), body_str);
            let mut headers = HashMap::new();
            headers.insert("content-type".to_string(), "application/json".to_string());
            plugin.before_proxy(&mut ctx, &mut headers).await
        }));
    }
    start.wait().await;
    for task in tasks {
        let result = task.await.expect("join");
        assert!(
            matches!(result, PluginResult::Continue),
            "identical misses must continue after a shared embedding"
        );
    }
}

#[tokio::test]
async fn leader_cancel_reelects_one_replacement_without_stampede() {
    let mock_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/embeddings"))
        .and(header("authorization", "Bearer test-key"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_delay(Duration::from_millis(300))
                .set_body_json(json!({
                    "data": [{"embedding": [1.0, 0.0, 0.0]}]
                })),
        )
        .expect(1..=2)
        .mount(&mock_server)
        .await;

    let plugin = Arc::new(make_plugin(semantic_config(&mock_server)));
    let body = json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "cancel leader"}]
    });
    let body_str = serde_json::to_string(&body).unwrap();
    let proxy = Arc::new(create_test_proxy());

    let plugin_leader = Arc::clone(&plugin);
    let body_leader = body_str.clone();
    let proxy_leader = Arc::clone(&proxy);
    let leader = tokio::spawn(async move {
        let mut ctx = RequestContext::new(
            "127.0.0.1".to_string(),
            "POST".to_string(),
            "/v1/chat/completions".to_string(),
        );
        ctx.matched_proxy = Some(proxy_leader);
        ctx.metadata.insert("request_body".to_string(), body_leader);
        let mut headers = HashMap::new();
        headers.insert("content-type".to_string(), "application/json".to_string());
        plugin_leader.before_proxy(&mut ctx, &mut headers).await
    });
    // Let the leader claim the slot, then cancel before it publishes.
    tokio::time::sleep(Duration::from_millis(40)).await;
    leader.abort();
    let _ = leader.await;

    let mut followers = Vec::new();
    for _ in 0..8 {
        let plugin = Arc::clone(&plugin);
        let body_str = body_str.clone();
        let proxy = Arc::clone(&proxy);
        followers.push(tokio::spawn(async move {
            let mut ctx = RequestContext::new(
                "127.0.0.1".to_string(),
                "POST".to_string(),
                "/v1/chat/completions".to_string(),
            );
            ctx.matched_proxy = Some(proxy);
            ctx.metadata.insert("request_body".to_string(), body_str);
            let mut headers = HashMap::new();
            headers.insert("content-type".to_string(), "application/json".to_string());
            plugin.before_proxy(&mut ctx, &mut headers).await
        }));
    }
    for task in followers {
        let result = task.await.expect("follower join");
        assert!(matches!(result, PluginResult::Continue));
    }
}

#[tokio::test]
#[serial_test::serial(ai_semantic_cache_singleflight_wait)]
async fn singleflight_timeout_bypasses_without_duplicating_live_leader() {
    let mock_server = MockServer::start().await;
    // The live leader runs past the follower wait bound. Followers must bypass
    // semantic lookup rather than evicting it and issuing a duplicate request.
    Mock::given(method("POST"))
        .and(path("/embeddings"))
        .and(header("authorization", "Bearer test-key"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_delay(Duration::from_millis(500))
                .set_body_json(json!({
                    "data": [{"embedding": [1.0, 0.0, 0.0]}]
                })),
        )
        .expect(1)
        .mount(&mock_server)
        .await;

    let plugin = Arc::new(make_plugin(semantic_config(&mock_server)));
    let _wait_override =
        SingleflightWaitOverrideGuard::install(plugin.as_ref(), Duration::from_millis(80));
    let body = json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "timeout reelect"}]
    });
    let body_str = serde_json::to_string(&body).unwrap();
    let proxy = Arc::new(create_test_proxy());

    let mut tasks = Vec::new();
    for _ in 0..4 {
        let plugin = Arc::clone(&plugin);
        let body_str = body_str.clone();
        let proxy = Arc::clone(&proxy);
        tasks.push(tokio::spawn(async move {
            let mut ctx = RequestContext::new(
                "127.0.0.1".to_string(),
                "POST".to_string(),
                "/v1/chat/completions".to_string(),
            );
            ctx.matched_proxy = Some(proxy);
            ctx.metadata.insert("request_body".to_string(), body_str);
            let mut headers = HashMap::new();
            headers.insert("content-type".to_string(), "application/json".to_string());
            plugin.before_proxy(&mut ctx, &mut headers).await
        }));
    }
    for task in tasks {
        let result = task.await.expect("join");
        assert!(matches!(result, PluginResult::Continue));
    }
}

#[tokio::test]
async fn high_cardinality_distinct_misses_are_semaphore_bounded() {
    let mock_server = MockServer::start().await;
    let active = Arc::new(AtomicUsize::new(0));
    let peak = Arc::new(AtomicUsize::new(0));
    Mock::given(method("POST"))
        .and(path("/embeddings"))
        .and(header("authorization", "Bearer test-key"))
        .respond_with(ConcurrencyTrackingEmbeddingResponder {
            active: Arc::clone(&active),
            peak: Arc::clone(&peak),
            tracking_duration: Duration::from_millis(400),
            response_delay: Duration::from_millis(500),
        })
        .expect(16)
        .mount(&mock_server)
        .await;
    let plugin = Arc::new(make_plugin(semantic_config(&mock_server)));
    let proxy = Arc::new(create_test_proxy());

    let mut tasks = Vec::new();
    for i in 0..16 {
        let plugin = Arc::clone(&plugin);
        let proxy = Arc::clone(&proxy);
        tasks.push(tokio::spawn(async move {
            let body = json!({
                "model": "gpt-4o",
                "messages": [{"role": "user", "content": format!("distinct prompt {i}")}]
            });
            let body_str = serde_json::to_string(&body).unwrap();
            let mut ctx = RequestContext::new(
                "127.0.0.1".to_string(),
                "POST".to_string(),
                "/v1/chat/completions".to_string(),
            );
            ctx.matched_proxy = Some(proxy);
            ctx.metadata.insert("request_body".to_string(), body_str);
            let mut headers = HashMap::new();
            headers.insert("content-type".to_string(), "application/json".to_string());
            plugin.before_proxy(&mut ctx, &mut headers).await
        }));
    }
    for task in tasks {
        assert!(matches!(task.await.expect("join"), PluginResult::Continue));
    }
    let observed_peak = peak.load(Ordering::Acquire);
    assert!(
        (2..=8).contains(&observed_peak),
        "embedding concurrency peak {observed_peak} must show overlap without exceeding the semaphore"
    );
}

#[tokio::test]
async fn embedding_semaphore_admission_wait_is_bounded() {
    let mock_server = MockServer::start().await;
    let active = Arc::new(AtomicUsize::new(0));
    let peak = Arc::new(AtomicUsize::new(0));
    Mock::given(method("POST"))
        .and(path("/embeddings"))
        .and(header("authorization", "Bearer test-key"))
        .respond_with(ConcurrencyTrackingEmbeddingResponder {
            active: Arc::clone(&active),
            peak: Arc::clone(&peak),
            tracking_duration: Duration::from_millis(400),
            response_delay: Duration::from_millis(500),
        })
        .expect(8)
        .mount(&mock_server)
        .await;

    let plugin = Arc::new(make_plugin(semantic_config(&mock_server)));
    let _wait_override =
        SingleflightWaitOverrideGuard::install(plugin.as_ref(), Duration::from_millis(80));
    let proxy = Arc::new(create_test_proxy());

    let mut tasks = Vec::new();
    for index in 0..9 {
        let plugin = Arc::clone(&plugin);
        let proxy = Arc::clone(&proxy);
        tasks.push(tokio::spawn(async move {
            let body = json!({
                "model": "gpt-4o",
                "messages": [{
                    "role": "user",
                    "content": format!("saturated prompt {index}")
                }]
            });
            let mut ctx = RequestContext::new(
                "127.0.0.1".to_string(),
                "POST".to_string(),
                "/v1/chat/completions".to_string(),
            );
            ctx.matched_proxy = Some(proxy);
            ctx.metadata.insert(
                "request_body".to_string(),
                serde_json::to_string(&body).unwrap(),
            );
            let mut headers = HashMap::new();
            headers.insert("content-type".to_string(), "application/json".to_string());
            plugin.before_proxy(&mut ctx, &mut headers).await
        }));
    }

    for task in tasks {
        assert!(matches!(task.await.expect("join"), PluginResult::Continue));
    }
    assert!(
        (2..=8).contains(&peak.load(Ordering::Acquire)),
        "saturated embedding requests must overlap without exceeding the semaphore"
    );
}

#[tokio::test]
async fn route_rewrite_and_effective_upstream_isolate_cache_entries() {
    async fn drive(
        plugin: &AiSemanticCache,
        proxy: &Arc<ferrum_edge::config::types::Proxy>,
        path: &str,
        body_str: &str,
        upstream: Option<&str>,
        rewrite: Option<&str>,
    ) -> (RequestContext, PluginResult) {
        let mut ctx = RequestContext::new(
            "127.0.0.1".to_string(),
            "POST".to_string(),
            path.to_string(),
        );
        ctx.matched_proxy = Some(Arc::clone(proxy));
        if let Some(upstream) = upstream {
            ctx.route_override_upstream_id = Some(upstream.to_string());
        }
        if let Some(rewrite) = rewrite {
            ctx.route_override_path = Some(rewrite.to_string());
            ctx.route_override_path_is_absolute = true;
        }
        ctx.metadata
            .insert("request_body".to_string(), body_str.to_string());
        let mut headers = HashMap::new();
        headers.insert("content-type".to_string(), "application/json".to_string());
        let result = plugin.before_proxy(&mut ctx, &mut headers).await;
        (ctx, result)
    }

    let plugin = make_plugin(json!({
        "ttl_seconds": 600,
        "scope_by_consumer": false
    }));
    let proxy = Arc::new(create_test_proxy());
    let body = json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "same body"}]
    });
    let body_str = serde_json::to_string(&body).unwrap();

    let (mut ctx_a, miss_a) = drive(
        &plugin,
        &proxy,
        "/v1/chat/completions",
        &body_str,
        Some("upstream-a"),
        None,
    )
    .await;
    assert!(matches!(miss_a, PluginResult::Continue));
    let mut resp_headers = HashMap::new();
    resp_headers.insert("content-type".to_string(), "application/json".to_string());
    let _ = plugin
        .on_final_response_body(&mut ctx_a, 200, &resp_headers, br#"{"up":"A"}"#)
        .await;

    // Same path/body but different effective upstream must miss.
    let (_ctx_b, miss_b) = drive(
        &plugin,
        &proxy,
        "/v1/chat/completions",
        &body_str,
        Some("upstream-b"),
        None,
    )
    .await;
    assert!(
        matches!(miss_b, PluginResult::Continue),
        "different effective upstream/provider must not share a cache entry"
    );

    // Same upstream + path hit.
    let (_ctx_a2, hit_a) = drive(
        &plugin,
        &proxy,
        "/v1/chat/completions",
        &body_str,
        Some("upstream-a"),
        None,
    )
    .await;
    assert!(matches!(hit_a, PluginResult::RejectBinary { .. }));

    // Rewritten backend path under the same public path / upstream isolates.
    let (mut ctx_rw, miss_rw) = drive(
        &plugin,
        &proxy,
        "/v1/chat/completions",
        &body_str,
        Some("upstream-a"),
        Some("/provider/v1/chat"),
    )
    .await;
    assert!(
        matches!(miss_rw, PluginResult::Continue),
        "a post-routing rewrite path must not receive the unre rewritten entry"
    );
    let _ = plugin
        .on_final_response_body(&mut ctx_rw, 200, &resp_headers, br#"{"up":"RW"}"#)
        .await;
    let (_ctx_rw2, hit_rw) = drive(
        &plugin,
        &proxy,
        "/v1/chat/completions",
        &body_str,
        Some("upstream-a"),
        Some("/provider/v1/chat"),
    )
    .await;
    assert!(matches!(hit_rw, PluginResult::RejectBinary { .. }));
}

#[test]
fn priority_is_after_route_dispatch_plugins() {
    let plugin = make_plugin(json!({}));
    assert_eq!(plugin.priority(), priority::AI_SEMANTIC_CACHE);
    const {
        assert!(
            priority::AI_SEMANTIC_CACHE > priority::MESH_ROUTE_DISPATCH,
            "cache lookup must observe mesh_route_dispatch overrides"
        );
        assert!(
            priority::AI_SEMANTIC_CACHE > priority::AI_STREAM_ROUTER,
            "cache lookup must observe ai_stream_router destination overrides"
        );
    }
}

// ── Redis quarantine-delete failure suppressor (issue #3213) ─────────────────

fn quarantine_fp(label: &str) -> [u8; 32] {
    ai_semantic_cache_redis_quarantine_fingerprint_content_for_test(label.as_bytes())
}

#[test]
fn redis_quarantine_denied_del_installs_local_suppressor() {
    let plugin = make_plugin(json!({
        "ttl_seconds": 600,
        "max_entries": 100,
    }));
    assert_eq!(
        ai_semantic_cache_redis_quarantine_ttl_for_test(&plugin),
        std::time::Duration::from_secs(30)
    );
    assert!(ai_semantic_cache_redis_quarantine_cap_for_test(&plugin) <= 4096);

    let key = "semantic-key-denied-del";
    let fp = quarantine_fp("poison-v1");
    ai_semantic_cache_apply_redis_quarantine_delete_outcome_for_test(&plugin, key, fp, false);

    assert_eq!(
        ai_semantic_cache_redis_quarantine_delete_failures_for_test(&plugin),
        1,
        "denied/failed DEL must be counted"
    );
    assert!(
        ai_semantic_cache_redis_quarantine_suppressed_for_test(&plugin, key),
        "failed quarantine delete must install a local suppressor"
    );
    assert!(
        ai_semantic_cache_redis_quarantine_is_suppressed_for_test(&plugin, key),
        "hot-path probe must treat the key as suppressed"
    );
    assert_eq!(
        ai_semantic_cache_redis_quarantine_suppressions_for_test(&plugin),
        1,
        "suppression probe must be observable"
    );
}

#[test]
fn redis_quarantine_successful_del_clears_suppressor() {
    let plugin = make_plugin(json!({}));
    let key = "semantic-key-del-ok";
    let fp = quarantine_fp("poison");
    ai_semantic_cache_apply_redis_quarantine_delete_outcome_for_test(&plugin, key, fp, false);
    assert!(ai_semantic_cache_redis_quarantine_suppressed_for_test(
        &plugin, key
    ));

    ai_semantic_cache_apply_redis_quarantine_delete_outcome_for_test(&plugin, key, fp, true);
    assert!(
        !ai_semantic_cache_redis_quarantine_suppressed_for_test(&plugin, key),
        "successful DEL must clear the local suppressor"
    );
}

#[test]
fn redis_quarantine_transient_failure_suppresses_repeated_access() {
    let plugin = make_plugin(json!({}));
    let key = "semantic-key-transient";
    let fp = quarantine_fp("same-poison");
    ai_semantic_cache_apply_redis_quarantine_delete_outcome_for_test(&plugin, key, fp, false);

    for _ in 0..5 {
        assert!(ai_semantic_cache_redis_quarantine_is_suppressed_for_test(
            &plugin, key
        ));
    }
    assert!(
        ai_semantic_cache_redis_quarantine_suppressions_for_test(&plugin) >= 5,
        "repeated access while suppressed must not require another Redis round-trip"
    );
    assert_eq!(
        ai_semantic_cache_redis_quarantine_delete_failures_for_test(&plugin),
        1,
        "suppressed repeats must not re-count delete failures"
    );
}

#[test]
fn redis_quarantine_ttl_recovery_reconsiders_key() {
    let plugin = make_plugin(json!({}));
    let key = "semantic-key-ttl";
    let fp = quarantine_fp("poison");
    ai_semantic_cache_apply_redis_quarantine_delete_outcome_for_test(&plugin, key, fp, false);
    assert!(ai_semantic_cache_redis_quarantine_suppressed_for_test(
        &plugin, key
    ));

    ai_semantic_cache_expire_redis_quarantine_for_test(&plugin, key);
    assert!(
        !ai_semantic_cache_redis_quarantine_is_suppressed_for_test(&plugin, key),
        "after TTL the same key must be reconsidered (suppressor cleared)"
    );
    assert!(
        !ai_semantic_cache_redis_quarantine_suppressed_for_test(&plugin, key),
        "expired markers must be removed on the reconsider path"
    );
}

#[test]
fn redis_quarantine_fingerprint_replacement_clears_marker() {
    let plugin = make_plugin(json!({}));
    let key = "semantic-key-replaced";
    let fp_old = quarantine_fp("old-poison");
    let fp_new = quarantine_fp("repaired-value");
    assert_ne!(fp_old, fp_new);

    ai_semantic_cache_apply_redis_quarantine_delete_outcome_for_test(&plugin, key, fp_old, false);
    assert!(ai_semantic_cache_redis_quarantine_matches_active_for_test(
        &plugin, key, &fp_old
    ));
    assert!(
        !ai_semantic_cache_redis_quarantine_matches_active_for_test(&plugin, key, &fp_new),
        "a replaced remote fingerprint must clear the suppressor for reconsideration"
    );
    assert!(
        !ai_semantic_cache_redis_quarantine_suppressed_for_test(&plugin, key),
        "replaced fingerprint must leave the key unsuppressed"
    );
}

#[test]
fn redis_quarantine_fingerprints_distinguish_inadmissible_shapes() {
    let content = ai_semantic_cache_redis_quarantine_fingerprint_content_for_test(b"{\"bad\":1}");
    let oversized = ai_semantic_cache_redis_quarantine_fingerprint_oversized_for_test(1_000_000);
    let empty = ai_semantic_cache_redis_quarantine_fingerprint_empty_for_test();
    assert_ne!(content, oversized);
    assert_ne!(content, empty);
    assert_ne!(oversized, empty);
    assert_eq!(
        ai_semantic_cache_redis_quarantine_fingerprint_oversized_for_test(1_000_000),
        oversized
    );
}

#[test]
fn redis_quarantine_capacity_eviction_is_bounded() {
    let plugin = make_plugin(json!({
        "max_entries": 8,
    }));
    let cap = ai_semantic_cache_redis_quarantine_cap_for_test(&plugin);
    assert_eq!(cap, 8);

    for i in 0..(cap + 16) {
        let key = format!("q-key-{i}");
        let fp = quarantine_fp(&key);
        ai_semantic_cache_apply_redis_quarantine_delete_outcome_for_test(&plugin, &key, fp, false);
    }
    assert!(
        ai_semantic_cache_redis_quarantine_len_for_test(&plugin) <= cap,
        "quarantine map must never exceed its hard cap"
    );
}

#[test]
fn redis_quarantine_concurrent_record_and_probe_stay_bounded() {
    let plugin = std::sync::Arc::new(make_plugin(json!({
        "max_entries": 64,
    })));
    let cap = ai_semantic_cache_redis_quarantine_cap_for_test(&plugin);

    std::thread::scope(|scope| {
        for worker in 0..8 {
            let plugin = std::sync::Arc::clone(&plugin);
            scope.spawn(move || {
                for i in 0..64 {
                    let key = format!("w{worker}-k{i}");
                    let fp = quarantine_fp(&key);
                    ai_semantic_cache_apply_redis_quarantine_delete_outcome_for_test(
                        &plugin, &key, fp, false,
                    );
                    let _ =
                        ai_semantic_cache_redis_quarantine_is_suppressed_for_test(&plugin, &key);
                }
            });
        }
    });

    assert!(ai_semantic_cache_redis_quarantine_len_for_test(&plugin) <= cap);
    assert!(ai_semantic_cache_redis_quarantine_delete_failures_for_test(&plugin) > 0);
}

#[test]
fn redis_quarantine_reload_instances_are_isolated() {
    let first = make_plugin(json!({}));
    let second = make_plugin(json!({}));
    assert_ne!(instance_id(&first), instance_id(&second));

    let key = "shared-looking-key";
    let fp = quarantine_fp("poison");
    ai_semantic_cache_apply_redis_quarantine_delete_outcome_for_test(&first, key, fp, false);

    assert!(ai_semantic_cache_redis_quarantine_suppressed_for_test(
        &first, key
    ));
    assert!(
        !ai_semantic_cache_redis_quarantine_suppressed_for_test(&second, key),
        "reload/sibling instances must not share quarantine suppressors"
    );
    ai_semantic_cache_clear_redis_quarantine_for_test(&first, key);
    assert!(!ai_semantic_cache_redis_quarantine_suppressed_for_test(
        &first, key
    ));
}

#[tokio::test]
async fn redis_quarantine_suppressed_key_stays_fail_closed_miss() {
    // Redis client is constructed but pointing at an unused port; the local
    // suppressor must keep the request on the miss path without converting a
    // quarantine failure into a hit.
    let plugin = make_plugin(json!({
        "ttl_seconds": 600,
        "scope_by_consumer": false,
        "sync_mode": "redis",
        "redis_url": "redis://127.0.0.1:1/0",
        "redis_integrity_key": REDIS_INTEGRITY_KEY_FOR_TESTS,
    }));
    let proxy = Arc::new(create_test_proxy());
    let body = json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "quarantine miss"}]
    });
    let body_str = serde_json::to_string(&body).unwrap();

    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/v1/chat/completions".to_string(),
    );
    ctx.matched_proxy = Some(Arc::clone(&proxy));
    ctx.metadata
        .insert("request_body".to_string(), body_str.clone());
    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/json".to_string());
    let first = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(first, PluginResult::Continue));
    let cache_key = staged_cache_key_value(&plugin, &ctx)
        .expect("miss must stage a cache key")
        .to_string();

    let fp = quarantine_fp("remote-poison");
    ai_semantic_cache_apply_redis_quarantine_delete_outcome_for_test(
        &plugin, &cache_key, fp, false,
    );
    let before = ai_semantic_cache_redis_quarantine_suppressions_for_test(&plugin);

    let mut ctx2 = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/v1/chat/completions".to_string(),
    );
    ctx2.matched_proxy = Some(proxy);
    ctx2.metadata.insert("request_body".to_string(), body_str);
    let mut headers2 = HashMap::new();
    headers2.insert("content-type".to_string(), "application/json".to_string());
    let second = plugin.before_proxy(&mut ctx2, &mut headers2).await;
    assert!(
        matches!(second, PluginResult::Continue),
        "suppressed quarantine must remain a miss, never a hit"
    );
    assert_eq!(staged_status(&plugin, &ctx2), Some("MISS"));
    assert!(
        ai_semantic_cache_redis_quarantine_suppressions_for_test(&plugin) > before,
        "before_proxy must observe the local suppressor on the Redis path"
    );
}

#[test]
fn redis_quarantine_found_hit_admits_before_fingerprint() {
    // Behavioral seam that counted hash invocations would distort production;
    // pin the Found-path order in source so valid hits never pay a quarantine
    // SHA-256 pass and fingerprints run only after admission failure.
    let source = include_str!("../../../src/plugins/ai_semantic_cache.rs");
    let found = source
        .split_once("Ok(BoundedRedisValue::Found(data)) => {")
        .and_then(|(_, rest)| rest.split_once("Ok(BoundedRedisValue::Oversized { length }) => {"))
        .map(|(body, _)| body)
        .expect("BoundedRedisValue::Found hit-path region");
    let admit = found
        .find("admit_redis_hit(")
        .expect("Found path must admit before fingerprinting");
    let fingerprint = found
        .find("redis_quarantine_fingerprint_content(&data)")
        .expect("Found path must fingerprint only after admission failure");
    assert!(
        admit < fingerprint,
        "valid Redis Found hits must admit/serve without a quarantine fingerprint pass"
    );
    assert!(
        found.contains("None => {")
            && found[fingerprint..].contains("matches_active(")
            && found[fingerprint..].contains("quarantine_invalid_redis_entry("),
        "inadmissible Found values must fingerprint, then check concurrent same-poison markers before DEL"
    );
    assert!(
        !found[..admit].contains("redis_quarantine_fingerprint_content"),
        "quarantine fingerprint must not precede admit_redis_hit on the Found path"
    );
}

#[test]
fn redis_quarantine_insert_avoids_full_map_expired_sweep() {
    // Sustained over-cap unique poison churn must not invoke a request-driven
    // O(capacity) expired sweep; pin constant-work victim policy in source.
    let source = include_str!("../../../src/plugins/ai_semantic_cache.rs");
    let insert = source
        .split_once("fn insert(&self, cache_key: &str, marker: RedisQuarantineMarker)")
        .and_then(|(_, rest)| rest.split_once("fn release_slot(&self)"))
        .map(|(body, _)| body)
        .expect("RedisQuarantineSuppressor::insert region");
    assert!(
        !insert.contains("evict_expired"),
        "insert must not call a full-map expired sweep under capacity pressure"
    );
    assert!(
        !insert.contains("Vec<String>") && !insert.contains(".collect()"),
        "insert must not allocate a vector of cloned keys for a map-wide scan"
    );
    assert!(
        insert.contains("entries.iter().next()") || insert.contains("self.entries.iter().next()"),
        "over-cap insert must use constant-work arbitrary/sample victim selection"
    );
    assert!(
        !source.contains("fn evict_expired(&self"),
        "request-path full-map expired sweep helper must remain removed"
    );
    // Behavioral: sustained unique over-cap churn stays hard-capped.
    let plugin = make_plugin(json!({ "max_entries": 16 }));
    let cap = ai_semantic_cache_redis_quarantine_cap_for_test(&plugin);
    for i in 0..(cap * 8) {
        let key = format!("churn-{i}");
        let fp = quarantine_fp(&key);
        ai_semantic_cache_apply_redis_quarantine_delete_outcome_for_test(&plugin, &key, fp, false);
    }
    assert!(ai_semantic_cache_redis_quarantine_len_for_test(&plugin) <= cap);
}

#[test]
fn redis_quarantine_delete_outcome_handler_is_shared() {
    // Production DEL mapping and the external test seam must share one private
    // synchronous outcome handler rather than duplicating success/failure logic.
    let source = include_str!("../../../src/plugins/ai_semantic_cache.rs");
    let production = source
        .split_once("async fn quarantine_invalid_redis_entry(")
        .and_then(|(_, rest)| rest.split_once("async fn build_vector_snapshot("))
        .map(|(body, _)| body)
        .expect("quarantine_invalid_redis_entry region");
    assert!(
        production.contains("apply_redis_quarantine_delete_outcome(")
            && production.contains("redis.delete(redis_key).await.is_ok()"),
        "production must map the real Redis DEL result through the shared handler"
    );
    assert!(
        !production.contains("record_delete_failure(")
            && !production.contains("maybe_warn_delete_failure("),
        "production quarantine path must not re-implement outcome mapping inline"
    );
    let test_seam = source
        .split_once("fn apply_redis_quarantine_delete_outcome_for_tests(")
        .and_then(|(_, rest)| rest.split_once("fn redis_quarantine_suppressed_for_tests("))
        .map(|(body, _)| body)
        .expect("apply_redis_quarantine_delete_outcome_for_tests region");
    assert!(
        test_seam.contains("self.apply_redis_quarantine_delete_outcome("),
        "test seam must call the same private outcome handler"
    );
    assert!(
        !test_seam.contains("record_delete_failure(")
            && !test_seam.contains("maybe_warn_delete_failure("),
        "test seam must not duplicate success/failure mapping"
    );
}
