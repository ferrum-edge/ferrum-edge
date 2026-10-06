//! Functional Tests for AI Plugins (E2E)
//!
//! Tests AI plugins (ai_prompt_shield, ai_request_guard) end-to-end through
//! the gateway in file mode. These plugins perform local validation without
//! calling external services.
//!
//! Run with: cargo test --test functional_tests -- --ignored --nocapture functional_ai_plugins

use crate::scaffolding::port_registry::TestSocket;

use crate::common::TestGateway;
use std::io::Write;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::time::sleep;

#[tokio::test]
#[ignore]
async fn functional_ai_semantic_cache_rewrites_once_across_h1_h2_h3() {
    use crate::scaffolding::clients::{GetOptions, Http3Client};
    use crate::scaffolding::ports::reserve_port;
    use bytes::Bytes;
    use http_body_util::{BodyExt, Full};
    use hyper::service::service_fn;
    use hyper_util::rt::TokioIo;
    use serde_json::{Value, json};
    use std::convert::Infallible;
    use std::io::Read;

    let reservation = reserve_port().await.expect("reserve semantic cache origin");
    let backend_port = reservation.port;
    let listener = reservation.into_listener();
    let hits = Arc::new(AtomicUsize::new(0));
    let origin_hits = Arc::clone(&hits);
    let origin = tokio::spawn(async move {
        let mut connections = tokio::task::JoinSet::new();
        while let Ok((stream, _)) = listener.accept().await {
            let hits = Arc::clone(&origin_hits);
            connections.spawn(async move {
                let service = service_fn(move |request: hyper::Request<hyper::body::Incoming>| {
                    let hits = Arc::clone(&hits);
                    async move {
                        let is_post = request.method() == http::Method::POST;
                        request.into_body().collect().await.expect("origin upload");
                        let count = if is_post {
                            hits.fetch_add(1, Ordering::SeqCst) + 1
                        } else {
                            0
                        };
                        let body = json!({
                            "id": format!("origin-{count}"),
                            "answer": "A garden contains flowers. ".repeat(30)
                        })
                        .to_string();
                        Ok::<_, Infallible>(
                            hyper::Response::builder()
                                .header("content-type", "application/json")
                                .header("content-length", body.len())
                                .body(Full::new(Bytes::from(body)))
                                .unwrap(),
                        )
                    }
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            });
        }
    });
    let config = json!({
        "version": "1",
        "proxies": [{
            "id": "semantic-cache",
            "listen_path": "/",
            "backend_scheme": "http",
            "backend_host": "127.0.0.1",
            "backend_port": backend_port,
            "strip_listen_path": false,
            "pool_enable_http2": false,
            "plugins": [
                {"plugin_config_id": "rewrite"},
                {"plugin_config_id": "compress"},
                {"plugin_config_id": "cache"}
            ]
        }],
        "consumers": [],
        "upstreams": [],
        "plugin_configs": [
            {
                "id": "rewrite", "plugin_name": "response_transformer",
                "scope": "proxy", "proxy_id": "semantic-cache", "enabled": true,
                "config": {"rules": [
                    {"operation": "rename", "target": "body", "key": "id", "new_key": "origin_id"},
                    {"operation": "add", "target": "body", "key": "id", "value": "client-id"}
                ]}
            },
            {
                "id": "compress", "plugin_name": "compression",
                "scope": "proxy", "proxy_id": "semantic-cache", "enabled": true,
                "config": {"algorithms": ["gzip"], "min_content_length": 10}
            },
            {
                "id": "cache", "plugin_name": "ai_semantic_cache",
                "scope": "proxy", "proxy_id": "semantic-cache", "enabled": true,
                "config": {}
            }
        ]
    });
    let gateway = TestGateway::builder()
        .mode_file(serde_yaml::to_string(&config).unwrap())
        .env("FERRUM_POOL_WARMUP_ENABLED", "false")
        .env("FERRUM_ENABLE_HTTP3", "true")
        .env_ephemeral_port("FERRUM_PROXY_HTTPS_PORT")
        .env("FERRUM_FRONTEND_TLS_CERT_PATH", "tests/certs/server.crt")
        .env("FERRUM_FRONTEND_TLS_KEY_PATH", "tests/certs/server.key")
        .spawn()
        .await
        .expect("start semantic cache gateway");
    let h1 = reqwest::Client::builder()
        .http1_only()
        .no_gzip()
        .build()
        .unwrap();
    let h2 = reqwest::Client::builder()
        .http2_prior_knowledge()
        .no_gzip()
        .build()
        .unwrap();
    let h3 = Http3Client::insecure().unwrap();
    let https_port = gateway.env_port("FERRUM_PROXY_HTTPS_PORT").unwrap();
    for protocol in 1..=3 {
        let request = json!({"messages": [{"role": "user", "content": "Describe a garden"}]});
        let route = format!("/replay-{protocol}");
        let mut miss_body = None;
        let before = hits.load(Ordering::SeqCst);
        for expected in ["MISS", "HIT"] {
            let (status, headers, body) = if protocol == 3 {
                let options = GetOptions::default()
                    .method(http::Method::POST)
                    .header("content-type", "application/json")
                    .header("accept-encoding", "gzip")
                    .header("cookie", "fixture=semantic-cache")
                    .body(Bytes::from(request.to_string()));
                let response = h3
                    .get_with_options(&format!("https://127.0.0.1:{https_port}{route}"), options)
                    .await
                    .expect("H3 semantic cache request");
                assert_eq!(response.body_error, None);
                (response.status, response.headers, response.body_bytes)
            } else {
                let client = if protocol == 1 { &h1 } else { &h2 };
                let response = client
                    .post(gateway.proxy_url(&route))
                    .header("accept-encoding", "gzip")
                    .header("cookie", "fixture=semantic-cache")
                    .json(&request)
                    .send()
                    .await
                    .expect("TCP semantic cache request");
                let version = if protocol == 1 {
                    http::Version::HTTP_11
                } else {
                    http::Version::HTTP_2
                };
                assert_eq!(response.version(), version);
                let status = response.status();
                let headers = response.headers().clone();
                (status, headers, response.bytes().await.unwrap())
            };
            assert_eq!(status, http::StatusCode::OK);
            assert_eq!(headers["x-ai-cache-status"], expected);
            assert_eq!(headers["content-encoding"], "gzip");
            let mut decoded = Vec::new();
            flate2::read::GzDecoder::new(body.as_ref())
                .read_to_end(&mut decoded)
                .unwrap();
            let parsed: Value = serde_json::from_slice(&decoded).unwrap();
            assert_eq!(parsed["id"], "client-id");
            assert_eq!(parsed["origin_id"], format!("origin-{}", before + 1));
            if let Some(miss) = &miss_body {
                assert_eq!(&parsed, miss);
            } else {
                miss_body = Some(parsed);
            }
        }
        assert_eq!(hits.load(Ordering::SeqCst), before + 1);
    }
    origin.abort();
}

// This relay forwards every command to real Redis. It counts transferred reply
// bytes and can pause WATCH or MULTI to make replacement races deterministic.
struct SemanticCacheRedisRelay {
    port: u16,
    reply_bytes: Arc<AtomicUsize>,
    get_calls: Arc<AtomicUsize>,
    del_calls: Arc<AtomicUsize>,
    last_range_end: Arc<AtomicUsize>,
    pause_on: Arc<AtomicUsize>,
    paused: Arc<tokio::sync::Notify>,
    resume: Arc<tokio::sync::Notify>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for SemanticCacheRedisRelay {
    fn drop(&mut self) {
        self.task.abort();
    }
}

type SemanticCacheRedisCommand = (Vec<u8>, Vec<Vec<u8>>);

async fn read_semantic_cache_redis_command(
    reader: &mut (impl tokio::io::AsyncBufRead + Unpin),
) -> std::io::Result<Option<SemanticCacheRedisCommand>> {
    use tokio::io::AsyncBufReadExt;

    let mut frame = Vec::new();
    if reader.read_until(b'\n', &mut frame).await? == 0 {
        return Ok(None);
    }
    assert!(frame.starts_with(b"*") && frame.ends_with(b"\r\n"));
    let count: usize = std::str::from_utf8(&frame[1..frame.len() - 2])
        .unwrap()
        .parse()
        .unwrap();
    assert!((1..=32).contains(&count));
    let mut args = Vec::with_capacity(count);
    for _ in 0..count {
        let mut header = Vec::new();
        reader.read_until(b'\n', &mut header).await?;
        assert!(header.starts_with(b"$") && header.ends_with(b"\r\n"));
        let length: usize = std::str::from_utf8(&header[1..header.len() - 2])
            .unwrap()
            .parse()
            .unwrap();
        assert!(length <= 128 * 1024, "fixture commands must be bounded");
        let mut value = vec![0; length + 2];
        reader.read_exact(&mut value).await?;
        assert!(value.ends_with(b"\r\n"));
        frame.extend_from_slice(&header);
        frame.extend_from_slice(&value);
        value.truncate(length);
        args.push(value);
    }
    Ok(Some((frame, args)))
}

impl SemanticCacheRedisRelay {
    async fn start() -> Self {
        let reservation = crate::scaffolding::ports::reserve_port()
            .await
            .expect("reserve Redis relay port");
        let port = reservation.port;
        let listener = reservation.into_listener();
        let reply_bytes = Arc::new(AtomicUsize::new(0));
        let get_calls = Arc::new(AtomicUsize::new(0));
        let del_calls = Arc::new(AtomicUsize::new(0));
        let last_range_end = Arc::new(AtomicUsize::new(usize::MAX));
        let pause_on = Arc::new(AtomicUsize::new(0));
        let paused = Arc::new(tokio::sync::Notify::new());
        let resume = Arc::new(tokio::sync::Notify::new());
        let state = (
            Arc::clone(&reply_bytes),
            Arc::clone(&get_calls),
            Arc::clone(&del_calls),
            Arc::clone(&last_range_end),
            Arc::clone(&pause_on),
            Arc::clone(&paused),
            Arc::clone(&resume),
        );
        let task = tokio::spawn(async move {
            let mut connections = tokio::task::JoinSet::new();
            while let Ok((downstream, _)) = listener.accept().await {
                let (bytes, gets, dels, range_end, pause_on, paused, resume) = state.clone();
                connections.spawn(async move {
                    let upstream = tokio::net::TcpStream::connect("127.0.0.1:6379")
                        .await
                        .expect("relay must reach real Redis");
                    let (down_read, mut down_write) = downstream.into_split();
                    let (mut up_read, mut up_write) = upstream.into_split();
                    let requests = async move {
                        let mut reader = tokio::io::BufReader::new(down_read);
                        while let Some((frame, args)) =
                            read_semantic_cache_redis_command(&mut reader).await?
                        {
                            match args[0].as_slice() {
                                b"GET" => {
                                    gets.fetch_add(1, Ordering::SeqCst);
                                }
                                b"DEL" => {
                                    dels.fetch_add(1, Ordering::SeqCst);
                                }
                                b"GETRANGE" => {
                                    assert_eq!(args[2], b"0");
                                    let end = std::str::from_utf8(&args[3])
                                        .unwrap()
                                        .parse::<usize>()
                                        .expect("GETRANGE end must be nonnegative");
                                    range_end.store(end, Ordering::SeqCst);
                                }
                                _ => {}
                            }
                            let pause = match args[0].as_slice() {
                                b"WATCH" => 1,
                                b"MULTI" => 2,
                                _ => 0,
                            };
                            if pause != 0
                                && pause_on
                                    .compare_exchange(pause, 0, Ordering::SeqCst, Ordering::SeqCst)
                                    .is_ok()
                            {
                                paused.notify_one();
                                resume.notified().await;
                            }
                            up_write.write_all(&frame).await?;
                        }
                        up_write.shutdown().await
                    };
                    let replies = async move {
                        let mut buffer = [0; 8192];
                        loop {
                            let count = up_read.read(&mut buffer).await?;
                            if count == 0 {
                                break;
                            }
                            bytes.fetch_add(count, Ordering::SeqCst);
                            down_write.write_all(&buffer[..count]).await?;
                        }
                        down_write.shutdown().await
                    };
                    let _: Result<_, std::io::Error> = tokio::try_join!(requests, replies);
                });
            }
        });
        Self {
            port,
            reply_bytes,
            get_calls,
            del_calls,
            last_range_end,
            pause_on,
            paused,
            resume,
            task,
        }
    }

    async fn wait_for_pause(&self) {
        tokio::time::timeout(Duration::from_secs(10), self.paused.notified())
            .await
            .expect("plugin quarantine must reach the armed Redis barrier");
    }
}

#[tokio::test]
#[ignore]
async fn functional_ai_semantic_cache_redis_quarantine_compare_delete_is_race_safe() {
    use ferrum_edge::_test_support::{
        ai_semantic_cache_apply_redis_quarantine_delete_outcome_for_test,
        ai_semantic_cache_expire_redis_quarantine_for_test,
        ai_semantic_cache_redis_quarantine_delete_failures_for_test,
        ai_semantic_cache_redis_quarantine_suppressed_for_test,
        ai_semantic_cache_redis_quarantine_suppressions_for_test,
        ai_semantic_cache_staging_metadata_key_for_test,
    };
    use ferrum_edge::plugins::ai_semantic_cache::AiSemanticCache;
    use ferrum_edge::plugins::utils::redis_rate_limiter::{
        BoundedRedisValue, RedisConfig, RedisRateLimitClient,
    };
    use ferrum_edge::plugins::{Plugin, PluginHttpClient, PluginResult, RequestContext};
    use serde_json::json;
    use std::collections::HashMap;
    use uuid::Uuid;

    let redis_ready = tokio::time::timeout(
        Duration::from_secs(5),
        tokio::net::TcpStream::connect("127.0.0.1:6379"),
    )
    .await;
    if !matches!(redis_ready, Ok(Ok(_))) {
        assert!(
            std::env::var("FERRUM_REDIS_REQUIRED").as_deref() != Ok("1"),
            "the Redis semantic-cache regression gate requires a reachable Redis service"
        );
        eprintln!("Redis not available at 127.0.0.1:6379 — skipping semantic-cache Redis test");
        return;
    }

    const REDIS_URL: &str = "redis://127.0.0.1:6379/15";
    const REQUEST: &[u8] =
        br#"{"model":"test","messages":[{"role":"user","content":"quarantine"}]}"#;
    const RESPONSE: &[u8] = br#"{"answer":"authenticated replacement"}"#;
    const MALFORMED: &[u8] = b"not-json\0\xff";
    const ENTRY_CAP: usize = 1024;
    const READ_CAP: usize = ENTRY_CAP * 6 + 64 * 1024;
    let prefix = format!(
        "ferrum-test:ai-semantic-cache-quarantine:{}",
        Uuid::new_v4()
    );
    let relay = SemanticCacheRedisRelay::start().await;
    let plugin_config = json!({
        "sync_mode": "redis",
        "redis_url": format!("redis://127.0.0.1:{}/15", relay.port),
        "redis_key_prefix": prefix,
        "redis_integrity_key": "0123456789abcdef0123456789abcdef",
        "max_entry_size_bytes": ENTRY_CAP,
        "ttl_seconds": 60,
        // Reply-byte assertions must not include periodic health probes.
        "redis_health_check_interval_seconds": 3600,
    });
    let plugin = Arc::new(
        AiSemanticCache::new(&plugin_config, PluginHttpClient::default())
            .expect("construct Redis cache plugin"),
    );
    let config = RedisConfig::from_plugin_config(
        &json!({"sync_mode": "redis", "redis_url": REDIS_URL, "redis_key_prefix": prefix}),
        &prefix,
    )
    .expect("Redis configuration is valid")
    .expect("Redis mode is enabled");
    let redis = RedisRateLimitClient::new(config, None, false, None)
        .expect("construct direct Redis writer");
    let headers = HashMap::from([
        ("content-type".to_string(), "application/json".to_string()),
        ("content-length".to_string(), REQUEST.len().to_string()),
    ]);
    let new_ctx = || {
        RequestContext::new(
            "127.0.0.1".to_string(),
            "POST".to_string(),
            "/v1/chat/completions".to_string(),
        )
    };
    let mut ctx = new_ctx();
    assert!(matches!(
        plugin
            .on_final_request_body_with_context(&mut ctx, &headers, REQUEST)
            .await,
        PluginResult::Continue
    ));
    let staging_key = ai_semantic_cache_staging_metadata_key_for_test(&plugin, "cache_key");
    let cache_key = ctx.metadata[&staging_key].clone();
    let key = redis.make_key(&[&cache_key]);

    // A separate plugin produces a genuinely authenticated envelope for this
    // exact namespace/key. The reader has no local response to mask Redis misses.
    let mut writer_config = plugin_config.clone();
    writer_config["redis_url"] = json!(REDIS_URL);
    let writer = AiSemanticCache::new(&writer_config, PluginHttpClient::default()).unwrap();
    let mut writer_ctx = new_ctx();
    assert!(matches!(
        writer
            .on_final_request_body_with_context(&mut writer_ctx, &headers, REQUEST)
            .await,
        PluginResult::Continue
    ));
    let response_headers =
        HashMap::from([("content-type".to_string(), "application/json".to_string())]);
    writer
        .on_final_response_body(&mut writer_ctx, 200, &response_headers, RESPONSE)
        .await;
    let persisted = redis.get_bytes_bounded(&key, READ_CAP).await.unwrap();
    let BoundedRedisValue::Found(valid) = persisted else {
        panic!("writer must persist a sealed cache envelope");
    };

    // Authenticate a JSON response admitted by a more permissive writer but
    // over this reader's body cap. This exercises policy admission after MAC
    // verification, rather than rejecting every envelope only at the MAC gate.
    redis.delete(&key).await.unwrap();
    let mut permissive_config = writer_config.clone();
    permissive_config["max_entry_size_bytes"] = json!(ENTRY_CAP * 2);
    let permissive = AiSemanticCache::new(&permissive_config, PluginHttpClient::default()).unwrap();
    let mut permissive_ctx = new_ctx();
    assert!(matches!(
        permissive
            .on_final_request_body_with_context(&mut permissive_ctx, &headers, REQUEST)
            .await,
        PluginResult::Continue
    ));
    let large_body = serde_json::to_vec(&json!({"answer": "x".repeat(ENTRY_CAP)})).unwrap();
    permissive
        .on_final_response_body(&mut permissive_ctx, 200, &response_headers, &large_body)
        .await;
    let persisted = redis.get_bytes_bounded(&key, READ_CAP).await.unwrap();
    let BoundedRedisValue::Found(over_body_cap) = persisted else {
        panic!("permissive writer must persist an authenticated over-body-cap envelope");
    };
    // Both malformed bytes and deserializable but inadmissible envelopes must
    // traverse the actual plugin quarantine path. Empty keys are not misses.
    let mut old_version: serde_json::Value = serde_json::from_slice(&valid).unwrap();
    old_version["version"] = json!(0);
    let mut tampered: serde_json::Value = serde_json::from_slice(&valid).unwrap();
    tampered["integrity"] = json!("00");
    for poison in [
        MALFORMED.to_vec(),
        Vec::new(),
        serde_json::to_vec(&old_version).unwrap(),
        serde_json::to_vec(&tampered).unwrap(),
        over_body_cap,
    ] {
        redis
            .set_bytes_with_expire(&key, &poison, 60)
            .await
            .unwrap();
        let deletes = relay.del_calls.load(Ordering::SeqCst);
        let mut ctx = new_ctx();
        assert!(matches!(
            plugin
                .on_final_request_body_with_context(&mut ctx, &headers, REQUEST)
                .await,
            PluginResult::Continue
        ));
        assert!(matches!(
            redis.get_bytes_bounded(&key, READ_CAP).await,
            Ok(BoundedRedisValue::Missing)
        ));
        assert_eq!(relay.del_calls.load(Ordering::SeqCst), deletes + 1);
        assert_eq!(
            ai_semantic_cache_redis_quarantine_delete_failures_for_test(&plugin),
            0
        );
        assert!(!ai_semantic_cache_redis_quarantine_suppressed_for_test(
            &plugin, &cache_key
        ));
    }

    let start_lookup = || {
        let reader = Arc::clone(&plugin);
        let request_headers = headers.clone();
        tokio::spawn(async move {
            let mut ctx = RequestContext::new(
                "127.0.0.1".to_string(),
                "POST".to_string(),
                "/v1/chat/completions".to_string(),
            );
            reader
                .on_final_request_body_with_context(&mut ctx, &request_headers, REQUEST)
                .await
        })
    };
    // Test replacement before WATCH and after the comparison but before EXEC.
    // In the latter case Redis itself must abort the watched transaction.
    for (barrier, poison) in [(1, MALFORMED), (2, MALFORMED), (1, b""), (2, b"")] {
        redis.set_bytes_with_expire(&key, poison, 60).await.unwrap();
        relay.pause_on.store(barrier, Ordering::SeqCst);
        let lookup = start_lookup();
        relay.wait_for_pause().await;
        redis.set_bytes_with_expire(&key, &valid, 60).await.unwrap();
        // Model another in-flight request installing a marker during lookup.
        ai_semantic_cache_apply_redis_quarantine_delete_outcome_for_test(
            &plugin, &cache_key, [1; 32], false,
        );
        let failures = ai_semantic_cache_redis_quarantine_delete_failures_for_test(&plugin);
        relay.resume.notify_one();
        assert!(matches!(lookup.await.unwrap(), PluginResult::Continue));
        assert!(!ai_semantic_cache_redis_quarantine_suppressed_for_test(
            &plugin, &cache_key
        ));
        assert_eq!(
            ai_semantic_cache_redis_quarantine_delete_failures_for_test(&plugin),
            failures,
            "a false comparison/aborted EXEC is not a delete failure"
        );
        assert!(matches!(
            redis.get_bytes_bounded(&key, READ_CAP).await,
            Ok(BoundedRedisValue::Found(value)) if value == valid
        ));
        let mut ctx = new_ctx();
        assert!(matches!(
            plugin
                .on_final_request_body_with_context(&mut ctx, &headers, REQUEST)
                .await,
            PluginResult::RejectBinary { status_code: 200, body, .. } if body.as_ref() == RESPONSE
        ));
    }

    // A replacement vastly larger than the plugin read cap shares the entire
    // observed prefix. Count real Redis reply bytes through the relay: the
    // comparison must transfer only expected.len()+1, not this 2 MiB value.
    let observed = MALFORMED;
    redis
        .set_bytes_with_expire(&key, observed, 60)
        .await
        .unwrap();
    let persisted = redis.get_bytes_bounded(&key, READ_CAP).await.unwrap();
    let BoundedRedisValue::Found(observed_bytes) = persisted else {
        panic!("malformed value must be observed before replacement");
    };
    assert_eq!(observed_bytes, observed);
    let mut huge = observed_bytes.clone();
    huge.resize(2 * 1024 * 1024, b'x');
    assert!(huge.len() > READ_CAP * 16);
    relay.pause_on.store(1, Ordering::SeqCst);
    let lookup = start_lookup();
    relay.wait_for_pause().await;
    redis.set_bytes_with_expire(&key, &huge, 60).await.unwrap();
    let before = relay.reply_bytes.load(Ordering::SeqCst);
    relay.resume.notify_one();
    assert!(matches!(lookup.await.unwrap(), PluginResult::Continue));
    assert!(relay.reply_bytes.load(Ordering::SeqCst) - before < 16 * 1024);
    assert_eq!(relay.last_range_end.load(Ordering::SeqCst), observed.len());
    assert!(!ai_semantic_cache_redis_quarantine_suppressed_for_test(
        &plugin, &cache_key
    ));
    let relay_config = RedisConfig::from_plugin_config(&plugin_config, &prefix)
        .unwrap()
        .unwrap();
    let compare = Arc::new(RedisRateLimitClient::new(relay_config, None, false, None).unwrap());
    let before = relay.reply_bytes.load(Ordering::SeqCst);
    assert!(
        !compare
            .delete_if_value_matches_bounded(&key, &observed_bytes)
            .await
            .unwrap()
    );
    assert!(relay.reply_bytes.load(Ordering::SeqCst) - before < 16 * 1024);
    assert_eq!(relay.last_range_end.load(Ordering::SeqCst), observed.len());
    assert_eq!(relay.get_calls.load(Ordering::SeqCst), 0);
    assert!(matches!(
        redis.get_bytes_bounded(&key, READ_CAP).await,
        Ok(BoundedRedisValue::Oversized { length }) if length == huge.len()
    ));

    // An initial oversized plugin lookup must retain the key, install a bounded
    // marker, and neither attempt DEL nor increment delete-failure telemetry.
    let deletes = relay.del_calls.load(Ordering::SeqCst);
    let failures = ai_semantic_cache_redis_quarantine_delete_failures_for_test(&plugin);
    let before = relay.reply_bytes.load(Ordering::SeqCst);
    let mut ctx = new_ctx();
    assert!(matches!(
        plugin
            .on_final_request_body_with_context(&mut ctx, &headers, REQUEST)
            .await,
        PluginResult::Continue
    ));
    assert!(relay.reply_bytes.load(Ordering::SeqCst) - before < READ_CAP + 4096);
    assert_eq!(relay.last_range_end.load(Ordering::SeqCst), READ_CAP);
    assert!(ai_semantic_cache_redis_quarantine_suppressed_for_test(
        &plugin, &cache_key
    ));
    assert_eq!(relay.del_calls.load(Ordering::SeqCst), deletes);
    assert_eq!(
        ai_semantic_cache_redis_quarantine_delete_failures_for_test(&plugin),
        failures
    );
    let suppressions = ai_semantic_cache_redis_quarantine_suppressions_for_test(&plugin);
    let before = relay.reply_bytes.load(Ordering::SeqCst);
    let mut ctx = new_ctx();
    assert!(matches!(
        plugin
            .on_final_request_body_with_context(&mut ctx, &headers, REQUEST)
            .await,
        PluginResult::Continue
    ));
    assert_eq!(relay.reply_bytes.load(Ordering::SeqCst), before);
    assert_eq!(
        ai_semantic_cache_redis_quarantine_suppressions_for_test(&plugin),
        suppressions + 1
    );
    assert!(matches!(
        redis.get_bytes_bounded(&key, READ_CAP).await,
        Ok(BoundedRedisValue::Oversized { length }) if length == huge.len()
    ));
    redis.set_bytes_with_expire(&key, &valid, 60).await.unwrap();
    ai_semantic_cache_expire_redis_quarantine_for_test(&plugin, &cache_key);
    let mut ctx = new_ctx();
    assert!(matches!(
        plugin
            .on_final_request_body_with_context(&mut ctx, &headers, REQUEST)
            .await,
        PluginResult::RejectBinary { status_code: 200, body, .. } if body.as_ref() == RESPONSE
    ));
    assert!(!ai_semantic_cache_redis_quarantine_suppressed_for_test(
        &plugin, &cache_key
    ));
    redis.delete(&key).await.unwrap();
    assert!(
        !compare
            .delete_if_value_matches_bounded(&key, b"")
            .await
            .unwrap()
    );
    redis.set_bytes_with_expire(&key, b"", 60).await.unwrap();
    assert!(
        compare
            .delete_if_value_matches_bounded(&key, b"")
            .await
            .unwrap()
    );
    redis
        .set_bytes_with_expire(&key, b"owner-token", 60)
        .await
        .unwrap();
    assert!(
        !compare
            .delete_if_value_matches_bounded(&key, b"other-token")
            .await
            .unwrap()
    );
    assert!(
        compare
            .delete_if_value_matches_bounded(&key, b"owner-token")
            .await
            .unwrap()
    );
    assert_eq!(relay.get_calls.load(Ordering::SeqCst), 0);

    // Even a byte-identical valid rewrite after comparison must abort the
    // watched deletion. Comparing bytes again cannot replace the WATCH fence.
    redis.set_bytes_with_expire(&key, &valid, 60).await.unwrap();
    relay.pause_on.store(2, Ordering::SeqCst);
    let comparison_client = Arc::clone(&compare);
    let comparison_key = key.clone();
    let expected = valid.clone();
    let comparison = tokio::spawn(async move {
        comparison_client
            .delete_if_value_matches_bounded(&comparison_key, &expected)
            .await
    });
    relay.wait_for_pause().await;
    redis.set_bytes_with_expire(&key, &valid, 60).await.unwrap();
    relay.resume.notify_one();
    assert!(!comparison.await.unwrap().unwrap());
    assert!(matches!(
        redis.get_bytes_bounded(&key, READ_CAP).await,
        Ok(BoundedRedisValue::Found(value)) if value == valid
    ));
    redis.delete(&key).await.unwrap();

    // Exercise the released semantic command profile and every optional
    // maintenance denial against real Redis ACLs. These cases live inside the
    // already-selected mandatory Redis gate, including its no-service refusal.
    let mut admin = redis::Client::open(REDIS_URL)
        .unwrap()
        .get_multiplexed_async_connection()
        .await
        .unwrap();
    // UNWATCH is never granted: the bounded quarantine helper does not send it.
    for denied in ["released", "WATCH", "MULTI", "DEL", "EXEC"] {
        let username = format!("semantic-quarantine-{}", Uuid::new_v4().simple());
        let password = Uuid::new_v4().simple().to_string();
        let mut acl = redis::cmd("ACL");
        acl.arg("SETUSER")
            .arg(&username)
            .arg("reset")
            .arg("on")
            .arg(format!(">{password}"))
            .arg(format!("~{prefix}*"))
            .arg("+auth")
            .arg("+hello")
            .arg("+select")
            .arg("+client")
            .arg("+ping")
            .arg("+info")
            .arg("+set")
            .arg("+expire")
            .arg("+multi")
            .arg("+exec")
            .arg("+exists")
            .arg("+strlen")
            .arg("+getrange");
        if denied != "released" {
            acl.arg("+watch")
                .arg("+del")
                .arg(format!("-{}", denied.to_ascii_lowercase()));
        }
        let _: () = acl.query_async(&mut admin).await.unwrap();
        let mut acl_config = plugin_config.clone();
        acl_config["redis_url"] = json!(format!(
            "redis://{username}:{password}@127.0.0.1:{}/15",
            relay.port
        ));
        let client_config = RedisConfig::from_plugin_config(&acl_config, &prefix)
            .unwrap()
            .unwrap();
        let acl_compare = RedisRateLimitClient::new(client_config, None, false, None).unwrap();
        if denied == "released" {
            let restricted_store =
                AiSemanticCache::new(&acl_config, PluginHttpClient::default()).unwrap();
            let mut store_ctx = new_ctx();
            assert!(matches!(
                restricted_store
                    .on_final_request_body_with_context(&mut store_ctx, &headers, REQUEST)
                    .await,
                PluginResult::Continue
            ));
            let store_staging_key =
                ai_semantic_cache_staging_metadata_key_for_test(&restricted_store, "cache_key");
            assert_eq!(store_ctx.metadata[&store_staging_key], cache_key);
            let response_headers =
                HashMap::from([("content-type".to_string(), "application/json".to_string())]);
            restricted_store
                .on_final_response_body(&mut store_ctx, 200, &response_headers, RESPONSE)
                .await;

            let persisted = redis.get_bytes_bounded(&key, READ_CAP).await.unwrap();
            let BoundedRedisValue::Found(envelope) = persisted else {
                panic!("restricted plugin must persist a sealed cache envelope");
            };
            let envelope: serde_json::Value = serde_json::from_slice(&envelope).unwrap();
            assert!(envelope["version"].as_u64().is_some());
            assert_eq!(envelope["status_code"], 200);
            assert!(
                envelope["integrity"]
                    .as_str()
                    .is_some_and(|mac| !mac.is_empty())
            );
            let remaining_ttl: i64 = redis::cmd("TTL")
                .arg(&key)
                .query_async(&mut admin)
                .await
                .unwrap();
            assert!(
                (1..=60).contains(&remaining_ttl),
                "restricted plugin store must apply its configured Redis TTL"
            );

            // A new instance has no local entry, so this HIT must read and
            // admit the envelope persisted under the restricted ACL.
            let restricted_reader =
                AiSemanticCache::new(&acl_config, PluginHttpClient::default()).unwrap();
            let mut reader_ctx = new_ctx();
            assert!(matches!(
                restricted_reader
                    .on_final_request_body_with_context(&mut reader_ctx, &headers, REQUEST)
                    .await,
                PluginResult::RejectBinary { status_code: 200, body, .. }
                    if body.as_ref() == RESPONSE
            ));
        }
        redis
            .set_bytes_with_expire(&key, MALFORMED, 60)
            .await
            .unwrap();
        // Establish required-command availability before optional maintenance.
        // The 3600s probe interval cannot conceal a mistaken outage transition.
        assert!(matches!(
            acl_compare.get_bytes_bounded(&key, READ_CAP).await,
            Ok(BoundedRedisValue::Found(value)) if value == MALFORMED
        ));
        assert!(
            acl_compare.is_available(),
            "required reads must work for {denied}"
        );
        if denied == "EXEC" {
            // Redis wraps a denial of EXEC itself in a single EXECABORT reply,
            // rather than exposing NOPERM as a queued-command server error.
            let restricted_url = acl_config["redis_url"].as_str().unwrap();
            let mut rejected_exec = redis::Client::open(restricted_url)
                .unwrap()
                .get_multiplexed_async_connection()
                .await
                .unwrap();
            let _: () = redis::cmd("MULTI")
                .query_async(&mut rejected_exec)
                .await
                .unwrap();
            let queued: String = redis::cmd("DEL")
                .arg(&key)
                .query_async(&mut rejected_exec)
                .await
                .unwrap();
            assert_eq!(queued, "QUEUED");
            let error = redis::cmd("EXEC")
                .query_async::<redis::Value>(&mut rejected_exec)
                .await
                .unwrap_err();
            assert_eq!(error.code(), Some("EXECABORT"));
            assert!(error.detail().is_some_and(|detail| {
                detail.starts_with("Transaction discarded because of: NOPERM ")
            }));
        }
        if matches!(denied, "MULTI" | "DEL" | "EXEC") {
            // A proven mismatch settles before MULTI and needs no UNWATCH, so
            // an ACL without +unwatch still answers it as a plain false.
            assert!(matches!(
                acl_compare
                    .delete_if_value_matches_bounded(&key, b"different")
                    .await,
                Ok(false)
            ));
        }
        assert!(
            acl_compare
                .delete_if_value_matches_bounded(&key, MALFORMED)
                .await
                .is_err(),
            "the restricted ACL must refuse the targeted quarantine operation: {denied}"
        );
        assert!(
            acl_compare.is_available(),
            "optional quarantine permission denial must preserve backend availability: {denied}"
        );
        assert!(matches!(
            acl_compare.get_bytes_bounded(&key, READ_CAP).await,
            Ok(BoundedRedisValue::Found(value)) if value == MALFORMED
        ));
        let remaining_ttl: i64 = redis::cmd("TTL")
            .arg(&key)
            .query_async(&mut admin)
            .await
            .unwrap();
        assert!(
            (1..=60).contains(&remaining_ttl),
            "permission denial must leave the expiring remote entry's TTL intact"
        );

        // Prime the actual plugin's pooled read connection on an absent key.
        // A later HIT through that same plugin proves permission denial did
        // not incorrectly mark it unavailable; health probes are 3600s apart.
        redis.delete(&key).await.unwrap();
        let acl_plugin =
            Arc::new(AiSemanticCache::new(&acl_config, PluginHttpClient::default()).unwrap());
        let mut ctx = new_ctx();
        assert!(matches!(
            acl_plugin
                .on_final_request_body_with_context(&mut ctx, &headers, REQUEST)
                .await,
            PluginResult::Continue
        ));
        let acl_staging_key =
            ai_semantic_cache_staging_metadata_key_for_test(&acl_plugin, "cache_key");
        assert_eq!(ctx.metadata[&acl_staging_key], cache_key);
        redis
            .set_bytes_with_expire(&key, MALFORMED, 60)
            .await
            .unwrap();
        // WATCH denials use a pre-WATCH replacement. Transaction denials use
        // a post-comparison replacement; MULTI denial must never let a
        // following DEL escape the transaction and erase that value.
        let barrier = if matches!(denied, "released" | "WATCH") {
            1
        } else {
            2
        };
        relay.pause_on.store(barrier, Ordering::SeqCst);
        let reader = Arc::clone(&acl_plugin);
        let request_headers = headers.clone();
        let lookup = tokio::spawn(async move {
            let mut ctx = RequestContext::new(
                "127.0.0.1".to_string(),
                "POST".to_string(),
                "/v1/chat/completions".to_string(),
            );
            reader
                .on_final_request_body_with_context(&mut ctx, &request_headers, REQUEST)
                .await
        });
        relay.wait_for_pause().await;
        redis.set_bytes_with_expire(&key, &valid, 60).await.unwrap();
        relay.resume.notify_one();
        assert!(matches!(lookup.await.unwrap(), PluginResult::Continue));
        assert_eq!(
            ai_semantic_cache_redis_quarantine_delete_failures_for_test(&acl_plugin),
            1
        );
        assert!(ai_semantic_cache_redis_quarantine_suppressed_for_test(
            &acl_plugin,
            &cache_key
        ));
        assert!(matches!(
            redis.get_bytes_bounded(&key, READ_CAP).await,
            Ok(BoundedRedisValue::Found(value)) if value == valid
        ));
        let before = relay.reply_bytes.load(Ordering::SeqCst);
        let mut ctx = new_ctx();
        assert!(matches!(
            acl_plugin
                .on_final_request_body_with_context(&mut ctx, &headers, REQUEST)
                .await,
            PluginResult::Continue
        ));
        assert_eq!(relay.reply_bytes.load(Ordering::SeqCst), before);
        assert_eq!(
            ai_semantic_cache_redis_quarantine_delete_failures_for_test(&acl_plugin),
            1,
            "local suppression must prevent repeated maintenance attempts"
        );
        ai_semantic_cache_expire_redis_quarantine_for_test(&acl_plugin, &cache_key);
        let mut ctx = new_ctx();
        assert!(matches!(
            acl_plugin
                .on_final_request_body_with_context(&mut ctx, &headers, REQUEST)
                .await,
            PluginResult::RejectBinary { status_code: 200, body, .. } if body.as_ref() == RESPONSE
        ));
        assert!(!ai_semantic_cache_redis_quarantine_suppressed_for_test(
            &acl_plugin,
            &cache_key
        ));
        assert!(matches!(
            redis.get_bytes_bounded(&key, READ_CAP).await,
            Ok(BoundedRedisValue::Found(value)) if value == valid
        ));
        drop(acl_plugin);
        drop(acl_compare);
        let _: i64 = redis::cmd("ACL")
            .arg("DELUSER")
            .arg(&username)
            .query_async(&mut admin)
            .await
            .unwrap();
    }
    assert_eq!(relay.get_calls.load(Ordering::SeqCst), 0);
    redis.delete(&key).await.unwrap();
}

// ============================================================================
// Echo Server Helper
// ============================================================================

/// Start a simple HTTP echo server that reads the full request and echoes
/// back a JSON response with status 200.
///
/// Accepts a pre-bound listener to avoid port races (the caller holds the
/// listener until passing it here, so the port cannot be stolen).
async fn start_echo_server_on(listener: TcpListener) {
    loop {
        if let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = vec![0u8; 16384];
                let _n = stream.read(&mut buf).await.unwrap_or(0);

                let body = r#"{"status":"ok"}"#;
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(response.as_bytes()).await;
                let _ = stream.shutdown().await;
            });
        }
    }
}

async fn start_counted_json_server_on(
    listener: TcpListener,
    status: u16,
    body: &'static str,
    counted_request_prefix: &'static [u8],
    hits: Arc<AtomicUsize>,
) {
    loop {
        if let Ok((mut stream, _)) = listener.accept().await {
            let hits = Arc::clone(&hits);
            tokio::spawn(async move {
                let mut buf = vec![0u8; 16384];
                let bytes_read = stream.read(&mut buf).await.unwrap_or(0);
                if buf[..bytes_read].starts_with(counted_request_prefix) {
                    hits.fetch_add(1, Ordering::Relaxed);
                }
                let response = format!(
                    "HTTP/1.1 {status} Test\r\nContent-Length: {}\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes()).await;
                let _ = stream.shutdown().await;
            });
        }
    }
}

/// Detect the gateway binary path (debug preferred, fallback to release).
fn gateway_binary_path() -> &'static str {
    if std::path::Path::new("./target/debug/ferrum-edge").exists() {
        "./target/debug/ferrum-edge"
    } else {
        "./target/release/ferrum-edge"
    }
}

/// Start the gateway in file mode with the given config and ports.
fn start_gateway(
    config_path: &str,
    proxy_port: u16,
    admin_port: u16,
    identity: &crate::common::SpawnedGatewayIdentity,
) -> std::process::Child {
    let binary_path = gateway_binary_path();

    let mut cmd = std::process::Command::new(binary_path);
    cmd.arg("run");
    cmd.env("FERRUM_MODE", "file")
        .env("FERRUM_FILE_CONFIG_PATH", config_path)
        .env("FERRUM_PROXY_HTTP_PORT", proxy_port.to_string())
        .env("FERRUM_ADMIN_HTTP_PORT", admin_port.to_string())
        .env("FERRUM_LOG_LEVEL", "debug")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    identity.apply_to_command(&mut cmd);
    cmd.spawn().expect("Failed to start gateway binary")
}

/// Wait until `child` owns `admin_port`. Unauthenticated `/health` and
/// CIDR-granted health detail are not identity (issue #4253).
async fn wait_for_owned_gateway(
    child: &mut std::process::Child,
    admin_port: u16,
    identity: &crate::common::SpawnedGatewayIdentity,
) -> bool {
    crate::common::wait_for_owned_gateway_identity(
        child,
        admin_port,
        identity,
        Duration::from_secs(15),
    )
    .await
    .is_ok()
}

/// Start the gateway with retry on port-binding failures.
///
/// Allocates fresh ephemeral proxy and admin ports on each attempt to handle
/// the bind-drop-rebind port race (another process can steal the port between
/// the drop and the gateway bind). Returns (child, proxy_port, admin_port).
async fn start_gateway_with_retry(config_path: &str) -> (std::process::Child, u16, u16) {
    const MAX_ATTEMPTS: u32 = 3;
    for attempt in 1..=MAX_ATTEMPTS {
        let proxy_listener = TcpListener::bind_test("127.0.0.1:0").await.unwrap();
        let proxy_port = proxy_listener.local_addr().unwrap().port();
        drop(proxy_listener);

        let admin_listener = TcpListener::bind_test("127.0.0.1:0").await.unwrap();
        let admin_port = admin_listener.local_addr().unwrap().port();
        drop(admin_listener);

        let identity = crate::common::SpawnedGatewayIdentity::mint("ai-plugins");
        let mut child = start_gateway(config_path, proxy_port, admin_port, &identity);

        if wait_for_owned_gateway(&mut child, admin_port, &identity).await {
            return (child, proxy_port, admin_port);
        }

        eprintln!(
            "Gateway startup attempt {}/{} failed (ports: proxy={}, admin={})",
            attempt, MAX_ATTEMPTS, proxy_port, admin_port
        );
        let _ = child.kill();
        let _ = child.wait();

        if attempt < MAX_ATTEMPTS {
            sleep(Duration::from_secs(1)).await;
        }
    }
    panic!("Gateway did not start after {} attempts", MAX_ATTEMPTS);
}

// ============================================================================
// ai_federation request-path isolation
// ============================================================================

#[ignore]
#[tokio::test]
async fn test_ai_federation_terminal_dispatch_is_backend_accounting_neutral() {
    let backend_listener = TcpListener::bind_test("127.0.0.1:0").await.unwrap();
    let backend_port = backend_listener.local_addr().unwrap().port();
    let backend_hits = Arc::new(AtomicUsize::new(0));
    let backend_task = tokio::spawn(start_counted_json_server_on(
        backend_listener,
        200,
        r#"{"backend":true}"#,
        b"POST /chat ",
        Arc::clone(&backend_hits),
    ));

    let provider_listener = TcpListener::bind_test("127.0.0.1:0").await.unwrap();
    let provider_port = provider_listener.local_addr().unwrap().port();
    let provider_hits = Arc::new(AtomicUsize::new(0));
    let provider_task = tokio::spawn(start_counted_json_server_on(
        provider_listener,
        503,
        r#"{"error":"provider unavailable"}"#,
        b"POST /v1/chat/completions ",
        Arc::clone(&provider_hits),
    ));

    let config = format!(
        r#"
version: "1"
proxies:
  - id: "federation-isolation"
    listen_path: "/federation-isolation"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: {backend_port}
    strip_listen_path: true
    pool_enable_http2: false
    upstream_id: "federation-isolation-upstream"
    circuit_breaker:
      failure_threshold: 1
      success_threshold: 1
      timeout_seconds: 60
      failure_status_codes: [503]
      half_open_max_requests: 1
      trip_on_connection_errors: true
    plugins:
      - plugin_config_id: "federation-content-type-transformer"
      - plugin_config_id: "federation-isolation-plugin"

consumers: []
upstreams:
  - id: "federation-isolation-upstream"
    algorithm: round_robin
    targets:
      - host: "127.0.0.1"
        port: {backend_port}
        weight: 1
    health_checks:
      passive:
        unhealthy_status_codes: [503]
        unhealthy_threshold: 1
        unhealthy_window_seconds: 60
        healthy_after_seconds: 0

plugin_configs:
  - id: "federation-content-type-transformer"
    proxy_id: "federation-isolation"
    plugin_name: "request_transformer"
    scope: "proxy"
    enabled: true
    config:
      rules:
        - operation: "update"
          target: "header"
          key: "content-type"
          value: "application/json"
  - id: "federation-isolation-plugin"
    proxy_id: "federation-isolation"
    plugin_name: "ai_federation"
    scope: "proxy"
    enabled: true
    config:
      fallback_enabled: false
      fail_on_no_matching_provider: false
      providers:
        - name: "mock-provider"
          provider_type: "openai"
          api_key: "test-key"
          model_patterns: ["gpt-*"]
          base_url: "http://127.0.0.1:{provider_port}/v1/chat/completions"
          allow_plaintext: true
  - id: "federation-isolation-metrics"
    plugin_name: "prometheus_metrics"
    scope: "global"
    enabled: true
    config:
      render_cache_ttl_seconds: 0
"#
    );

    let gateway = TestGateway::builder()
        .mode_file(config)
        .env("FERRUM_POOL_WARMUP_ENABLED", "false")
        .spawn()
        .await
        .expect("start federation isolation gateway");
    let client = reqwest::Client::new();

    let provider_response = client
        .post(gateway.proxy_url("/federation-isolation/chat"))
        .header("content-type", "text/plain")
        .body(
            serde_json::to_vec(&serde_json::json!({
                "model": "gpt-4o",
                "messages": [{"role": "user", "content": "hello"}]
            }))
            .expect("serialize federated request"),
        )
        .send()
        .await
        .expect("send federated request");
    assert_eq!(provider_response.status().as_u16(), 503);
    assert_eq!(provider_hits.load(Ordering::Relaxed), 1);
    assert_eq!(
        backend_hits.load(Ordering::Relaxed),
        0,
        "terminal federation dispatch must not send the application request to backend transport"
    );

    let runtime_metrics: serde_json::Value = client
        .get(gateway.admin_url("/admin/metrics"))
        .header("Authorization", gateway.auth_header())
        .send()
        .await
        .expect("read runtime metrics after provider response")
        .json()
        .await
        .expect("parse runtime metrics after provider response");
    if let Some(breaker) = runtime_metrics["circuit_breakers"]
        .as_array()
        .and_then(|breakers| {
            breakers
                .iter()
                .find(|breaker| breaker["proxy_id"] == "federation-isolation")
        })
    {
        assert_eq!(breaker["state"], "closed");
        assert_eq!(breaker["failure_count"].as_u64().unwrap_or(0), 0);
    }
    assert!(
        runtime_metrics["health_check"]["unhealthy_targets"]
            .as_array()
            .expect("runtime unhealthy target list")
            .iter()
            .all(|target| target["proxy_id"] != "federation-isolation"),
        "provider failures must not poison backend passive health: {runtime_metrics}"
    );

    let metrics = client
        .get(gateway.admin_url("/metrics"))
        .header("Authorization", gateway.auth_header())
        .send()
        .await
        .expect("scrape metrics after synthetic provider response")
        .text()
        .await
        .expect("read metrics body");
    assert!(
        !metrics.contains("ferrum_backend_duration_ms_count{proxy_id=\"federation-isolation\""),
        "provider latency must not be recorded as backend latency: {metrics}"
    );

    let passthrough_response = client
        .post(gateway.proxy_url("/federation-isolation/chat"))
        .header("content-type", "text/plain")
        .body(
            serde_json::to_vec(&serde_json::json!({
                "model": "local-only",
                "messages": [{"role": "user", "content": "hello"}]
            }))
            .expect("serialize unmatched pass-through request"),
        )
        .send()
        .await
        .expect("send unmatched pass-through request");
    assert_eq!(
        passthrough_response.status().as_u16(),
        200,
        "the provider 503 must not open or penalize the backend circuit"
    );
    assert_eq!(backend_hits.load(Ordering::Relaxed), 1);
    assert_eq!(provider_hits.load(Ordering::Relaxed), 1);

    backend_task.abort();
    provider_task.abort();
}

// ============================================================================
// ai_federation incremental streaming (issue #3298)
// ============================================================================

/// Largest provider request head + body this fixture will read off one socket
/// before it stops accumulating. Requests in these tests are a few hundred
/// bytes; the cap only keeps a hostile/looping peer bounded.
const SSE_PROVIDER_MAX_REQUEST_BYTES: usize = 65536;

/// Read one whole HTTP request (head plus any `Content-Length` body) off
/// `stream`, or `None` when the peer never delivered one.
///
/// Returning `None` is the load-bearing case: an accepted socket that carries
/// no request head is NOT a provider exchange (issue #4486). A client-side
/// connection pool may establish a TCP connection it then abandons without
/// writing anything, and billing that as an upstream AI call is exactly the
/// mis-measurement the disconnect test was reporting.
async fn read_provider_request(stream: &mut tokio::net::TcpStream) -> Option<Vec<u8>> {
    let mut request: Vec<u8> = Vec::with_capacity(4096);
    let mut buf = vec![0u8; 16384];
    let mut head_end: Option<usize> = None;
    loop {
        if head_end.is_none()
            && let Some(position) = request.windows(4).position(|window| window == b"\r\n\r\n")
        {
            head_end = Some(position + 4);
        }
        if let Some(head_end) = head_end {
            // Only a `Content-Length` body is possible here: the gateway
            // buffers this request before dispatch, so it never sends a
            // chunked provider body.
            let declared = content_length_of(&request[..head_end]).unwrap_or(0);
            if request.len() - head_end >= declared {
                break;
            }
        }
        if request.len() >= SSE_PROVIDER_MAX_REQUEST_BYTES {
            break;
        }
        match stream.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(read) => request.extend_from_slice(&buf[..read]),
        }
    }
    // A half-written head is not an exchange either.
    if head_end.is_some() && request.starts_with(b"POST ") {
        Some(request)
    } else {
        None
    }
}

/// `Content-Length` of an ASCII request head, if it declares one.
fn content_length_of(head: &[u8]) -> Option<usize> {
    let head = std::str::from_utf8(head).ok()?;
    head.lines()
        .find_map(|line| {
            line.split_once(':')
                .filter(|(name, _)| name.eq_ignore_ascii_case("content-length"))
        })
        .and_then(|(_, value)| value.trim().parse().ok())
}

/// Serve exactly one SSE response, releasing the tail only after the caller
/// signals that the FIRST event already reached the downstream client.
///
/// This is what makes the time-to-first-token assertion behavior-driven rather
/// than timing-driven: a gateway that buffered the provider response would never
/// hand the first event to the client, the test would never fire `release`, and
/// the fixture would never write the tail — the assertion fails by deadlock
/// avoidance (the bounded request timeout), never by a sleep guess.
///
/// `hits` counts COMPLETED PROVIDER EXCHANGES — sockets that delivered a whole
/// `POST` request — never accepted connections. `completed` publishes how many
/// of those exchanges have been written out and shut down, so a caller can wait
/// on the fixture's own observable for an abandoned exchange to tear down
/// instead of guessing at a sleep (issue #4486).
///
/// `release` is claimed by the first socket that actually delivers a request,
/// not by the first socket accepted, so a stray connection cannot consume the
/// hold that a test's time-to-first-token assertion depends on.
async fn start_sse_provider_on(
    listener: TcpListener,
    head: &'static str,
    tail: &'static str,
    hits: Arc<AtomicUsize>,
    release: tokio::sync::oneshot::Receiver<()>,
    completed: tokio::sync::watch::Sender<usize>,
) {
    let release = Arc::new(tokio::sync::Mutex::new(Some(release)));
    loop {
        let Ok((mut stream, _)) = listener.accept().await else {
            continue;
        };
        let hits = Arc::clone(&hits);
        let release = Arc::clone(&release);
        let completed = completed.clone();
        tokio::spawn(async move {
            if read_provider_request(&mut stream).await.is_none() {
                return;
            }
            hits.fetch_add(1, Ordering::Relaxed);
            let release = release.lock().await.take();
            let _ = stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-cache\r\nConnection: close\r\n\r\n",
                )
                .await;
            let _ = stream.write_all(head.as_bytes()).await;
            let _ = stream.flush().await;
            if let Some(release) = release {
                // Bounded: the test always resolves this channel (by sending or
                // by dropping the sender), so the fixture never hangs.
                let _ = release.await;
            }
            let _ = stream.write_all(tail.as_bytes()).await;
            let _ = stream.shutdown().await;
            completed.send_modify(|count| *count += 1);
        });
    }
}

fn federation_streaming_config(provider_port: u16, backend_port: u16, path: &str) -> String {
    format!(
        r#"
version: "1"
proxies:
  - id: "federation-streaming"
    listen_path: "/federation-streaming"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: {backend_port}
    strip_listen_path: true
    pool_enable_http2: false
    plugins:
      - plugin_config_id: "federation-streaming-plugin"

consumers: []
plugin_configs:
  - id: "federation-streaming-plugin"
    proxy_id: "federation-streaming"
    plugin_name: "ai_federation"
    scope: "proxy"
    enabled: true
    config:
      streaming:
        enabled: true
      fail_on_no_matching_provider: false
      providers:
        - name: "mock-streaming-provider"
          provider_type: "openai"
          api_key: "test-key"
          model_patterns: ["gpt-*"]
          base_url: "http://127.0.0.1:{provider_port}{path}"
          allow_plaintext: true
"#
    )
}

#[ignore]
#[tokio::test]
async fn test_ai_federation_streams_first_token_before_provider_completes() {
    let backend_listener = TcpListener::bind_test("127.0.0.1:0").await.unwrap();
    let backend_port = backend_listener.local_addr().unwrap().port();
    let backend_hits = Arc::new(AtomicUsize::new(0));
    let backend_task = tokio::spawn(start_counted_json_server_on(
        backend_listener,
        200,
        r#"{"backend":true}"#,
        b"POST /",
        Arc::clone(&backend_hits),
    ));

    let provider_listener = TcpListener::bind_test("127.0.0.1:0").await.unwrap();
    let provider_port = provider_listener.local_addr().unwrap().port();
    let provider_hits = Arc::new(AtomicUsize::new(0));
    let (release_tx, release_rx) = tokio::sync::oneshot::channel();
    let (provider_completed_tx, _provider_completed_rx) = tokio::sync::watch::channel(0usize);
    let provider_task = tokio::spawn(start_sse_provider_on(
        provider_listener,
        "data: {\"id\":\"c1\",\"object\":\"chat.completion.chunk\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"He\"}}]}\n\n",
        concat!(
            "data: {\"id\":\"c1\",\"object\":\"chat.completion.chunk\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"llo\"}}]}\n\n",
            "data: {\"id\":\"c1\",\"object\":\"chat.completion.chunk\",\"choices\":[],\"usage\":{\"prompt_tokens\":3,\"completion_tokens\":2,\"total_tokens\":5}}\n\n",
            "data: [DONE]\n\n",
        ),
        Arc::clone(&provider_hits),
        release_rx,
        provider_completed_tx,
    ));

    let gateway = TestGateway::builder()
        .mode_file(federation_streaming_config(
            provider_port,
            backend_port,
            "/v1/chat/completions",
        ))
        .env("FERRUM_POOL_WARMUP_ENABLED", "false")
        .spawn()
        .await
        .expect("start federation streaming gateway");

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(20))
        .build()
        .expect("build streaming client");
    let mut response = client
        .post(gateway.proxy_url("/federation-streaming/chat"))
        .header("content-type", "application/json")
        .body(
            serde_json::to_vec(&serde_json::json!({
                "model": "gpt-4o",
                "messages": [{"role": "user", "content": "hello"}],
                "stream": true
            }))
            .expect("serialize streaming request"),
        )
        .send()
        .await
        .expect("send streaming request");

    assert_eq!(response.status().as_u16(), 200);
    assert!(
        response
            .headers()
            .get("content-type")
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.contains("text/event-stream")),
        "claimed stream must stay an event stream: {:?}",
        response.headers()
    );

    // Read until the FIRST provider event is client-visible. The provider is
    // still holding the rest of the stream, so this can only succeed if the
    // gateway relayed incrementally.
    let mut received = Vec::new();
    let mut release_tx = Some(release_tx);
    while let Some(chunk) = response.chunk().await.expect("read stream chunk") {
        received.extend_from_slice(&chunk);
        if let Some(tx) = release_tx.take() {
            let text = String::from_utf8_lossy(&received);
            assert!(
                text.contains("\"content\":\"He\""),
                "first client-visible bytes must be the first provider event: {text}"
            );
            assert!(
                !text.contains("[DONE]"),
                "the provider has not sent the terminal marker yet: {text}"
            );
            // Only now may the provider finish the stream.
            tx.send(()).expect("release provider tail");
        }
    }

    let text = String::from_utf8(received).expect("stream is UTF-8");
    assert!(text.contains("\"content\":\"llo\""), "second event: {text}");
    assert!(
        text.contains("\"total_tokens\":5"),
        "terminal usage: {text}"
    );
    assert_eq!(
        text.matches("[DONE]").count(),
        1,
        "exactly one terminal marker: {text}"
    );
    assert!(
        text.ends_with("data: [DONE]\n\n"),
        "terminal ordering: {text}"
    );
    assert!(!text.contains("event: error"), "clean stream: {text}");

    assert_eq!(provider_hits.load(Ordering::Relaxed), 1);
    assert_eq!(
        backend_hits.load(Ordering::Relaxed),
        0,
        "a claimed stream must never reach the configured backend"
    );

    provider_task.abort();
    backend_task.abort();
}

#[ignore]
#[tokio::test]
async fn test_ai_federation_truncated_provider_stream_fails_closed_without_splicing() {
    let backend_listener = TcpListener::bind_test("127.0.0.1:0").await.unwrap();
    let backend_port = backend_listener.local_addr().unwrap().port();
    let backend_hits = Arc::new(AtomicUsize::new(0));
    let backend_task = tokio::spawn(start_counted_json_server_on(
        backend_listener,
        200,
        r#"{"backend":true}"#,
        b"POST /",
        Arc::clone(&backend_hits),
    ));

    let provider_listener = TcpListener::bind_test("127.0.0.1:0").await.unwrap();
    let provider_port = provider_listener.local_addr().unwrap().port();
    let provider_hits = Arc::new(AtomicUsize::new(0));
    let (release_tx, release_rx) = tokio::sync::oneshot::channel();
    let (provider_completed_tx, _provider_completed_rx) = tokio::sync::watch::channel(0usize);
    // Head only: the provider closes without ever sending `data: [DONE]`.
    let provider_task = tokio::spawn(start_sse_provider_on(
        provider_listener,
        "data: {\"id\":\"c1\",\"object\":\"chat.completion.chunk\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"He\"}}]}\n\n",
        "",
        Arc::clone(&provider_hits),
        release_rx,
        provider_completed_tx,
    ));

    let gateway = TestGateway::builder()
        .mode_file(federation_streaming_config(
            provider_port,
            backend_port,
            "/v1/chat/completions",
        ))
        .env("FERRUM_POOL_WARMUP_ENABLED", "false")
        .spawn()
        .await
        .expect("start federation truncated-stream gateway");

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(20))
        .build()
        .expect("build streaming client");
    let mut response = client
        .post(gateway.proxy_url("/federation-streaming/chat"))
        .header("content-type", "application/json")
        .body(
            serde_json::to_vec(&serde_json::json!({
                "model": "gpt-4o",
                "messages": [{"role": "user", "content": "hello"}],
                "stream": true
            }))
            .expect("serialize streaming request"),
        )
        .send()
        .await
        .expect("send streaming request");
    assert_eq!(response.status().as_u16(), 200);

    let mut received = Vec::new();
    let mut release_tx = Some(release_tx);
    while let Some(chunk) = response.chunk().await.expect("read stream chunk") {
        received.extend_from_slice(&chunk);
        if let Some(tx) = release_tx.take() {
            // Let the provider close without a terminal marker.
            tx.send(()).expect("release provider close");
        }
    }

    let text = String::from_utf8(received).expect("stream is UTF-8");
    assert!(
        text.contains("event: error"),
        "a truncated provider stream must end with a gateway-authored error event: {text}"
    );
    assert!(
        !text.contains("[DONE]"),
        "a truncated stream must never look like a completed generation: {text}"
    );
    assert!(
        !text.contains("test-key"),
        "no credential may appear in the client-visible stream: {text}"
    );
    assert_eq!(
        provider_hits.load(Ordering::Relaxed),
        1,
        "post-commit failure must never splice a second provider request"
    );
    assert_eq!(backend_hits.load(Ordering::Relaxed), 0);

    provider_task.abort();
    backend_task.abort();
}

/// A client that disconnects mid-generation cancels the claimed stream, and the
/// gateway keeps serving: the next streaming request gets its OWN provider
/// exchange and completes normally. Live coverage for the cancellation branch of
/// the streaming lifecycle reservation.
#[ignore]
#[tokio::test]
async fn test_ai_federation_client_disconnect_cancels_without_wedging_the_route() {
    let backend_listener = TcpListener::bind_test("127.0.0.1:0").await.unwrap();
    let backend_port = backend_listener.local_addr().unwrap().port();
    let backend_hits = Arc::new(AtomicUsize::new(0));
    let backend_task = tokio::spawn(start_counted_json_server_on(
        backend_listener,
        200,
        r#"{"backend":true}"#,
        b"POST /",
        Arc::clone(&backend_hits),
    ));

    let provider_listener = TcpListener::bind_test("127.0.0.1:0").await.unwrap();
    let provider_port = provider_listener.local_addr().unwrap().port();
    let provider_hits = Arc::new(AtomicUsize::new(0));
    let (release_tx, release_rx) = tokio::sync::oneshot::channel();
    // Counts COMPLETED provider exchanges that have been fully torn down, so
    // the hit assertion below waits on the fixture rather than on a sleep.
    let (provider_completed_tx, mut provider_completed_rx) = tokio::sync::watch::channel(0usize);
    // Only the FIRST provider connection that actually delivers a request waits
    // for the release; every later one writes head and tail immediately.
    let provider_task = tokio::spawn(start_sse_provider_on(
        provider_listener,
        "data: {\"id\":\"c1\",\"object\":\"chat.completion.chunk\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"He\"}}]}\n\n",
        "data: [DONE]\n\n",
        Arc::clone(&provider_hits),
        release_rx,
        provider_completed_tx,
    ));

    let gateway = TestGateway::builder()
        .mode_file(federation_streaming_config(
            provider_port,
            backend_port,
            "/v1/chat/completions",
        ))
        .env("FERRUM_POOL_WARMUP_ENABLED", "false")
        .spawn()
        .await
        .expect("start federation cancellation gateway");

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(20))
        .build()
        .expect("build streaming client");
    let streaming_request = serde_json::to_vec(&serde_json::json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "hello"}],
        "stream": true
    }))
    .expect("serialize streaming request");

    let mut response = client
        .post(gateway.proxy_url("/federation-streaming/chat"))
        .header("content-type", "application/json")
        .body(streaming_request.clone())
        .send()
        .await
        .expect("send streaming request");
    assert_eq!(response.status().as_u16(), 200);

    // Take exactly the first event, then abandon the response: this is a client
    // disconnect in the middle of a committed generation.
    let first = response
        .chunk()
        .await
        .expect("read first chunk")
        .expect("the first event must arrive before the provider completes");
    let first_text = String::from_utf8_lossy(&first).to_string();
    assert!(
        first_text.contains("\"content\":\"He\""),
        "first client-visible bytes: {first_text}"
    );
    assert!(!first_text.contains("[DONE]"), "{first_text}");
    drop(response);
    // Let the abandoned provider exchange finish writing into a gone client.
    release_tx.send(()).expect("release the abandoned stream");

    // The route is not wedged: a fresh stream gets its OWN provider exchange and
    // completes with exactly one terminal marker.
    let mut response = client
        .post(gateway.proxy_url("/federation-streaming/chat"))
        .header("content-type", "application/json")
        .body(streaming_request)
        .send()
        .await
        .expect("send follow-up streaming request");
    assert_eq!(response.status().as_u16(), 200);
    let mut received = Vec::new();
    while let Some(chunk) = response.chunk().await.expect("read stream chunk") {
        received.extend_from_slice(&chunk);
    }
    let text = String::from_utf8(received).expect("stream is UTF-8");
    assert!(
        text.contains("\"content\":\"He\""),
        "follow-up stream content: {text}"
    );
    assert_eq!(
        text.matches("[DONE]").count(),
        1,
        "follow-up stream must complete exactly once: {text}"
    );
    assert!(!text.contains("event: error"), "clean follow-up: {text}");
    assert!(!text.contains("test-key"), "credential leaked: {text}");

    // Read the count only once the mock says BOTH exchanges — the abandoned one
    // and the follow-up — are written out and shut down. Waiting on the
    // fixture's own observable keeps this behavior-driven; a sleep would just
    // move the race (issue #4486).
    tokio::time::timeout(Duration::from_secs(10), async {
        while *provider_completed_rx.borrow_and_update() < 2 {
            provider_completed_rx
                .changed()
                .await
                .expect("the provider fixture outlives the assertion");
        }
    })
    .await
    .expect("both provider exchanges must tear down");

    assert_eq!(
        provider_hits.load(Ordering::Relaxed),
        2,
        "the follow-up stream must be its own provider exchange"
    );
    assert_eq!(backend_hits.load(Ordering::Relaxed), 0);

    provider_task.abort();
    backend_task.abort();
}

// ============================================================================
// ai_prompt_shield tests
// ============================================================================

#[ignore]
#[tokio::test]
async fn test_ai_prompt_shield_rejects_pii() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let config_path = temp_dir.path().join("config.yaml");

    // Bind echo server — hold the listener to avoid port races
    let echo_listener = TcpListener::bind_test("127.0.0.1:0").await.unwrap();
    let backend_port = echo_listener.local_addr().unwrap().port();

    let config_content = format!(
        r#"
version: "1"
proxies:
  - id: "ai-proxy"
    listen_path: "/ai"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: {backend_port}
    strip_listen_path: true
    plugins:
      - plugin_config_id: "shield-1"

consumers: []

plugin_configs:
  - id: "shield-1"
    proxy_id: "ai-proxy"
    plugin_name: "ai_prompt_shield"
    scope: "proxy"
    enabled: true
    config:
      action: "reject"
      patterns:
        - "ssn"
        - "credit_card"
        - "email"

upstreams: []
"#
    );

    let mut f = std::fs::File::create(&config_path).unwrap();
    f.write_all(config_content.as_bytes()).unwrap();
    drop(f);

    let _echo = tokio::spawn(start_echo_server_on(echo_listener));
    sleep(Duration::from_millis(100)).await;

    let (mut gw, proxy_port, _admin_port) =
        start_gateway_with_retry(config_path.to_str().unwrap()).await;

    // Send a request with an SSN in the message content
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("http://127.0.0.1:{}/ai/chat", proxy_port))
        .header("Content-Type", "application/json")
        .body(
            serde_json::json!({
                "messages": [
                    {
                        "role": "user",
                        "content": "My SSN is 123-45-6789, can you help me?"
                    }
                ]
            })
            .to_string(),
        )
        .send()
        .await
        .expect("Request failed");

    assert_eq!(
        resp.status().as_u16(),
        400,
        "Should reject request with PII"
    );
    let body = resp.text().await.unwrap();
    assert!(
        body.contains("PII detected"),
        "Response should mention PII detection, got: {}",
        body
    );
    assert!(
        body.contains("ssn"),
        "Response should identify SSN pattern, got: {}",
        body
    );

    let _ = gw.kill();
    let _ = gw.wait();
}

#[ignore]
#[tokio::test]
async fn test_ai_prompt_shield_allows_clean_request() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let config_path = temp_dir.path().join("config.yaml");

    let echo_listener = TcpListener::bind_test("127.0.0.1:0").await.unwrap();
    let backend_port = echo_listener.local_addr().unwrap().port();

    let config_content = format!(
        r#"
version: "1"
proxies:
  - id: "ai-proxy"
    listen_path: "/ai"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: {backend_port}
    strip_listen_path: true
    plugins:
      - plugin_config_id: "shield-1"

consumers: []

plugin_configs:
  - id: "shield-1"
    proxy_id: "ai-proxy"
    plugin_name: "ai_prompt_shield"
    scope: "proxy"
    enabled: true
    config:
      action: "reject"
      patterns:
        - "ssn"
        - "credit_card"
        - "email"

upstreams: []
"#
    );

    let mut f = std::fs::File::create(&config_path).unwrap();
    f.write_all(config_content.as_bytes()).unwrap();
    drop(f);

    let _echo = tokio::spawn(start_echo_server_on(echo_listener));
    sleep(Duration::from_millis(100)).await;

    let (mut gw, proxy_port, _admin_port) =
        start_gateway_with_retry(config_path.to_str().unwrap()).await;

    // Send a clean request with no PII
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("http://127.0.0.1:{}/ai/chat", proxy_port))
        .header("Content-Type", "application/json")
        .body(
            serde_json::json!({
                "messages": [
                    {
                        "role": "user",
                        "content": "What is the weather in Tokyo today?"
                    }
                ]
            })
            .to_string(),
        )
        .send()
        .await
        .expect("Request failed");

    assert_eq!(
        resp.status().as_u16(),
        200,
        "Clean request should pass through to backend"
    );

    let _ = gw.kill();
    let _ = gw.wait();
}

// ============================================================================
// ai_request_guard tests
// ============================================================================

#[ignore]
#[tokio::test]
async fn test_ai_request_guard_rejects_disallowed_model() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let config_path = temp_dir.path().join("config.yaml");

    let echo_listener = TcpListener::bind_test("127.0.0.1:0").await.unwrap();
    let backend_port = echo_listener.local_addr().unwrap().port();

    let config_content = format!(
        r#"
version: "1"
proxies:
  - id: "ai-proxy"
    listen_path: "/ai"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: {backend_port}
    strip_listen_path: true
    plugins:
      - plugin_config_id: "guard-1"

consumers: []

plugin_configs:
  - id: "guard-1"
    proxy_id: "ai-proxy"
    plugin_name: "ai_request_guard"
    scope: "proxy"
    enabled: true
    config:
      max_tokens_limit: 100
      enforce_max_tokens: "reject"
      allowed_models:
        - "gpt-4"

upstreams: []
"#
    );

    let mut f = std::fs::File::create(&config_path).unwrap();
    f.write_all(config_content.as_bytes()).unwrap();
    drop(f);

    let _echo = tokio::spawn(start_echo_server_on(echo_listener));
    sleep(Duration::from_millis(100)).await;

    let (mut gw, proxy_port, _admin_port) =
        start_gateway_with_retry(config_path.to_str().unwrap()).await;

    // Send a request with a disallowed model
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("http://127.0.0.1:{}/ai/chat", proxy_port))
        .header("Content-Type", "application/json")
        .body(
            serde_json::json!({
                "model": "gpt-3.5-turbo",
                "max_tokens": 50,
                "messages": [
                    {
                        "role": "user",
                        "content": "Hello"
                    }
                ]
            })
            .to_string(),
        )
        .send()
        .await
        .expect("Request failed");

    assert_eq!(
        resp.status().as_u16(),
        400,
        "Should reject disallowed model"
    );
    let body = resp.text().await.unwrap();
    assert!(
        body.contains("not in the allowed models list"),
        "Response should indicate model is not allowed, got: {}",
        body
    );

    let _ = gw.kill();
    let _ = gw.wait();
}

#[ignore]
#[tokio::test]
async fn test_ai_request_guard_rejects_excess_tokens() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let config_path = temp_dir.path().join("config.yaml");

    let echo_listener = TcpListener::bind_test("127.0.0.1:0").await.unwrap();
    let backend_port = echo_listener.local_addr().unwrap().port();

    let config_content = format!(
        r#"
version: "1"
proxies:
  - id: "ai-proxy"
    listen_path: "/ai"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: {backend_port}
    strip_listen_path: true
    plugins:
      - plugin_config_id: "guard-1"

consumers: []

plugin_configs:
  - id: "guard-1"
    proxy_id: "ai-proxy"
    plugin_name: "ai_request_guard"
    scope: "proxy"
    enabled: true
    config:
      max_tokens_limit: 100
      enforce_max_tokens: "reject"
      allowed_models:
        - "gpt-4"

upstreams: []
"#
    );

    let mut f = std::fs::File::create(&config_path).unwrap();
    f.write_all(config_content.as_bytes()).unwrap();
    drop(f);

    let _echo = tokio::spawn(start_echo_server_on(echo_listener));
    sleep(Duration::from_millis(100)).await;

    let (mut gw, proxy_port, _admin_port) =
        start_gateway_with_retry(config_path.to_str().unwrap()).await;

    // Send a request with excessive max_tokens
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("http://127.0.0.1:{}/ai/chat", proxy_port))
        .header("Content-Type", "application/json")
        .body(
            serde_json::json!({
                "model": "gpt-4",
                "max_tokens": 500,
                "messages": [
                    {
                        "role": "user",
                        "content": "Hello"
                    }
                ]
            })
            .to_string(),
        )
        .send()
        .await
        .expect("Request failed");

    assert_eq!(
        resp.status().as_u16(),
        400,
        "Should reject excessive max_tokens"
    );
    let body = resp.text().await.unwrap();
    assert!(
        body.contains("max_tokens exceeds limit"),
        "Response should indicate token limit exceeded, got: {}",
        body
    );
    assert!(
        body.contains("500") && body.contains("100"),
        "Response should show requested and max values, got: {}",
        body
    );

    let _ = gw.kill();
    let _ = gw.wait();
}

#[ignore]
#[tokio::test]
async fn test_ai_request_guard_allows_valid_request() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let config_path = temp_dir.path().join("config.yaml");

    let echo_listener = TcpListener::bind_test("127.0.0.1:0").await.unwrap();
    let backend_port = echo_listener.local_addr().unwrap().port();

    let config_content = format!(
        r#"
version: "1"
proxies:
  - id: "ai-proxy"
    listen_path: "/ai"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: {backend_port}
    strip_listen_path: true
    plugins:
      - plugin_config_id: "guard-1"

consumers: []

plugin_configs:
  - id: "guard-1"
    proxy_id: "ai-proxy"
    plugin_name: "ai_request_guard"
    scope: "proxy"
    enabled: true
    config:
      max_tokens_limit: 100
      enforce_max_tokens: "reject"
      allowed_models:
        - "gpt-4"

upstreams: []
"#
    );

    let mut f = std::fs::File::create(&config_path).unwrap();
    f.write_all(config_content.as_bytes()).unwrap();
    drop(f);

    let _echo = tokio::spawn(start_echo_server_on(echo_listener));
    sleep(Duration::from_millis(100)).await;

    let (mut gw, proxy_port, _admin_port) =
        start_gateway_with_retry(config_path.to_str().unwrap()).await;

    // Send a valid request: allowed model + tokens within limit
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("http://127.0.0.1:{}/ai/chat", proxy_port))
        .header("Content-Type", "application/json")
        .body(
            serde_json::json!({
                "model": "gpt-4",
                "max_tokens": 50,
                "messages": [
                    {
                        "role": "user",
                        "content": "What is the capital of France?"
                    }
                ]
            })
            .to_string(),
        )
        .send()
        .await
        .expect("Request failed");

    assert_eq!(
        resp.status().as_u16(),
        200,
        "Valid request should pass through to backend"
    );

    let _ = gw.kill();
    let _ = gw.wait();
}
