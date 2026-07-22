use ferrum_edge::_test_support::{
    ai_semantic_cache_clear_vector_index_dirty_for_test, ai_semantic_cache_embedding,
    ai_semantic_cache_expire_all_entries_for_test, ai_semantic_cache_force_cleanup_for_test,
    ai_semantic_cache_scope_key, ai_semantic_cache_set_store_post_admit_hook_for_test,
    ai_semantic_cache_set_vector_index_rebuild_blocked_for_test,
    ai_semantic_cache_size_accounting_snapshot_for_test,
    ai_semantic_cache_vector_index_dirty_for_test, rebuild_ai_semantic_cache_vector_index,
    set_ai_semantic_cache_embedding, set_ai_semantic_cache_scope_key,
};
use ferrum_edge::config::types::Consumer;
use ferrum_edge::config::{BackendAllowIps, PoolConfig};
use ferrum_edge::dns::{DnsCache, DnsConfig};
use ferrum_edge::plugins::ai_semantic_cache::AiSemanticCache;
use ferrum_edge::plugins::{
    HTTP_ONLY_PROTOCOLS, Plugin, PluginHttpClient, PluginResult, RequestContext, priority,
};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::sync::{Arc, Barrier};
use wiremock::matchers::{body_string_contains, header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

// Marker set by the proxy on `ctx.metadata` while the response-body hooks run
// over a synthetic 2xx plugin short-circuit body (mirrors
// `crate::proxy::SYNTHETIC_SHORT_CIRCUIT_METADATA_KEY`, which is `pub(crate)` and
// therefore not reachable from this external test crate).
const SYNTHETIC_SHORT_CIRCUIT_METADATA_KEY: &str = "ferrum:synthetic_short_circuit";

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

fn make_plugin(config: serde_json::Value) -> AiSemanticCache {
    AiSemanticCache::new(&config, PluginHttpClient::default()).unwrap()
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
        "redis_url": "redis://localhost:6379/0"
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
        "redis_url": "redis://169.254.169.254:6379/0"
    });
    assert!(
        validate_plugin_config_with_policy("ai_semantic_cache", &denied, &default_policy).is_err(),
        "metadata Redis endpoint must be rejected under the default policy"
    );

    // A loopback Redis (local cache) still validates by default.
    let loopback = json!({
        "sync_mode": "redis",
        "redis_url": "redis://127.0.0.1:6379/0"
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
            .is_ok(),
        "loopback kafka broker must remain valid by default"
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
    assert_eq!(ctx1.metadata.get("ai_cache_status").unwrap(), "MISS");
    assert!(ctx1.metadata.contains_key("_ai_cache_key"));

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

    // First request — cache MISS. This sets `_ai_cache_key`, which is exactly
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
    assert_eq!(ctx1.metadata.get("ai_cache_status").unwrap(), "MISS");
    assert!(ctx1.metadata.contains_key("_ai_cache_key"));

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
    assert_eq!(
        ctx2.metadata.get("ai_cache_status").map(String::as_str),
        Some("MISS")
    );
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
    assert!(ctx1.metadata.contains_key("_ai_cache_key"));

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
    assert_eq!(
        ctx_b.metadata.get("ai_cache_status").map(String::as_str),
        Some("MISS")
    );

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
    assert_eq!(
        ctx_mixed
            .metadata
            .get("ai_cache_status")
            .map(String::as_str),
        Some("MISS")
    );
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
        ctx_b.metadata.get("ai_cache_status").map(String::as_str),
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
    assert_eq!(
        ctx_b.metadata.get("ai_cache_status").map(String::as_str),
        Some("MISS")
    );
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

    for key in ["_ai_cache_key", "ai_cache_status", "ai_cache_match"] {
        if let Some(value) = ctx.metadata.get(key) {
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
    if let Some(scope_key) = ai_semantic_cache_scope_key(&ctx) {
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
    assert_eq!(
        ctx_b.metadata.get("ai_cache_status").map(String::as_str),
        Some("MISS")
    );
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
    assert_eq!(
        ctx.metadata.get("ai_cache_status").map(String::as_str),
        Some("BYPASS")
    );
    assert!(
        !ctx.metadata.contains_key("_ai_cache_key"),
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
    assert_eq!(
        ctx.metadata.get("ai_cache_status").map(String::as_str),
        Some("BYPASS")
    );
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
    assert_eq!(
        ctx.metadata.get("ai_cache_status").map(String::as_str),
        Some("MISS")
    );
    assert!(
        ai_semantic_cache_embedding(&ctx).is_none(),
        "default exact_only mode must not compute text-only embeddings for multimodal requests"
    );
    assert!(
        ai_semantic_cache_scope_key(&ctx).is_none(),
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
            assert_eq!(
                ctx.metadata.get("ai_cache_match").map(String::as_str),
                Some("semantic")
            );
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
    assert_eq!(
        ctx.metadata.get("ai_cache_status").map(String::as_str),
        Some("MISS")
    );

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
    assert_eq!(
        ctx.metadata.get("ai_cache_status").map(String::as_str),
        Some("MISS")
    );
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
    assert_eq!(ctx2.metadata.get("ai_cache_status").unwrap(), "MISS");
}

#[tokio::test]
async fn test_whitespace_normalization_cache_hit() {
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

    // Same prompt with extra whitespace and case differences — should HIT
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
    match result {
        PluginResult::RejectBinary { status_code, .. } => {
            assert_eq!(status_code, 200);
        }
        _ => panic!("Expected cache HIT after whitespace normalization"),
    }
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
    assert!(!ctx.metadata.contains_key("ai_cache_status"));
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
        "tracked total_size must equal the sum of retained entry approx_size values \
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
    ctx.metadata
        .get("_ai_cache_key")
        .cloned()
        .expect("MISS must stage _ai_cache_key")
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
        .insert("_ai_cache_key".to_string(), cache_key.to_string());
    set_ai_semantic_cache_embedding(&mut ctx, embedding);
    set_ai_semantic_cache_scope_key(&mut ctx, scope_key);
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

/// Different-key soft-cap overshoot remains allowed and stays reconcilable:
/// concurrent distinct keys may briefly exceed `max_total_size_bytes`, but the
/// counter still equals the retained-entry size sum.
#[tokio::test]
async fn test_concurrent_different_key_soft_cap_overshoot_reconciles() {
    // Each ~4 KiB body plus structural overhead fits under 6 KiB alone; two
    // concurrent admits both observe an empty total and overshoot together.
    let max_total = 6_000usize;
    let plugin = Arc::new(make_plugin(json!({
        "ttl_seconds": 600,
        "scope_by_consumer": false,
        "max_total_size_bytes": max_total,
        "max_entry_size_bytes": 8_192
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
    let _barrier = install_post_admit_barrier(&plugin, 2);
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
        task.await.expect("soft-cap overshoot task panicked");
    }
    clear_post_admit_hook(&plugin);

    assert_eq!(
        plugin.tracked_keys_count(),
        Some(2),
        "both different-key admits should land under the documented soft-cap race"
    );
    let total = assert_size_accounting_exact(&plugin);
    assert!(
        total > max_total,
        "expected transient different-key soft-cap overshoot (total={total}, max={max_total})"
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
    // endpoint: stage `_ai_cache_key` via a miss that fails closed to exact.
    let cache_key = {
        let (ctx, result) = run_before_proxy(&plugin, &request_body, None).await;
        assert!(matches!(result, PluginResult::Continue));
        ctx.metadata
            .get("_ai_cache_key")
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
            assert_eq!(ctx.metadata.get("ai_cache_status").unwrap(), "HIT");
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
    assert_exact_miss_for_variant(body, other_preamble, br#""4""#).await;
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
            ctx.metadata.get("ai_cache_status").map(String::as_str),
            Some("BYPASS"),
            "unknown/ambiguous body must bypass: {body}"
        );
        assert!(
            !ctx.metadata.contains_key("_ai_cache_key"),
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
            assert_eq!(
                ctx.metadata.get("ai_cache_match").map(String::as_str),
                Some("semantic")
            );
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
    mount_embedding_mock(&mock_server, 8).await;
    let plugin = make_plugin(semantic_config(&mock_server));

    let base = json!({
        "model": "gpt-4.1",
        "max_completion_tokens": 32,
        "stop_sequences": ["END"],
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
    mount_embedding_mock(&mock_server, 9).await;
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
    assert_eq!(ctx.metadata.get("ai_cache_status").unwrap(), "MISS");
    assert_ne!(
        ctx.metadata.get("ai_cache_match").map(String::as_str),
        Some("semantic"),
        "Gemini body must not semantic-hit a Messages-family entry"
    );
}
