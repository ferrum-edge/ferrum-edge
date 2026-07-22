use ferrum_edge::_test_support::{
    RedisConfig, redis_client_credentials, redis_config_url_with_ip,
    redis_rate_limit_client_for_test,
};
use serde_json::json;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::oneshot;

fn make_config(url: &str, tls: bool) -> RedisConfig {
    RedisConfig {
        url: url.to_string(),
        tls,
        key_prefix: "ferrum:test".to_string(),
        pool_size: 4,
        connect_timeout_seconds: 5,
        health_check_interval_seconds: 5,
        username: None,
        password: None,
    }
}

#[test]
fn test_hostname_uses_url_parser_and_preserves_credentials() {
    let config = make_config("redis://user:pass@redis:6379/15", false);
    assert_eq!(config.hostname().as_deref(), Some("redis"));
}

#[test]
fn test_hostname_skips_ipv6_literals() {
    let config = make_config("redis://[2001:db8::10]:6379/0", false);
    assert_eq!(config.hostname(), None);
}

#[test]
fn test_url_with_resolved_ip_replaces_host_not_scheme() {
    let config = make_config("redis://redis:6379/0", false);
    let url = redis_config_url_with_ip(&config, IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
    assert_eq!(url, "redis://127.0.0.1:6379/0");
}

#[test]
fn test_url_with_resolved_ip_preserves_credentials_and_path() {
    let config = make_config("redis://user:pass@redis:6379/15", false);
    let url = redis_config_url_with_ip(&config, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)));
    assert_eq!(url, "redis://user:pass@10.0.0.5:6379/15");
}

#[test]
fn test_url_with_resolved_ip_formats_ipv6_authority() {
    let config = make_config("redis://cache.internal:6379/0", false);
    let url = redis_config_url_with_ip(&config, IpAddr::V6(Ipv6Addr::LOCALHOST));
    assert_eq!(url, "redis://[::1]:6379/0");
}

#[test]
fn test_url_with_resolved_ip_preserves_tls_hostname_for_sni() {
    let config = make_config("redis://cache.internal:6379/0", true);
    let url = redis_config_url_with_ip(&config, IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
    assert_eq!(url, "rediss://cache.internal:6379/0");
}

// ── ACL credential injection ─────────────────────────────────────────────
//
// Regression coverage for "Redis ACL credentials silently ignored": before
// the fix, `redis_username` / `redis_password` were parsed off the plugin
// JSON config but never forwarded to `redis::Client::open()` /
// `build_with_tls()`, so the gateway would connect unauthenticated even
// though the operator had configured ACL credentials. These tests assert
// that the credentials now flow through to `redis::ConnectionInfo`.

#[test]
fn test_explicit_credentials_are_applied_to_plain_client() {
    let mut config = make_config("redis://localhost:6379/0", false);
    config.username = Some("alice".to_string());
    config.password = Some("secret".to_string());

    let (user, pass) =
        redis_client_credentials(config, "redis://localhost:6379/0").expect("build_client");
    assert_eq!(user.as_deref(), Some("alice"));
    assert_eq!(pass.as_deref(), Some("secret"));
}

#[test]
fn test_explicit_credentials_are_applied_to_tls_client() {
    let mut config = make_config("rediss://cache.internal:6379/0", true);
    config.username = Some("svc-rate-limit".to_string());
    config.password = Some("hunter2".to_string());

    // Use rediss:// + TLS so we exercise the build_with_tls branch.
    let (user, pass) =
        redis_client_credentials(config, "rediss://cache.internal:6379/0").expect("build_client");
    assert_eq!(user.as_deref(), Some("svc-rate-limit"));
    assert_eq!(pass.as_deref(), Some("hunter2"));
}

#[test]
fn test_explicit_credentials_override_url_userinfo() {
    // URL-embedded creds (`bob:fromurl`) are parsed by the redis crate, but the
    // explicit fields must take precedence so operators have a single source of
    // truth for credential rotation.
    let mut config = make_config("redis://bob:fromurl@localhost:6379/0", false);
    config.username = Some("alice".to_string());
    config.password = Some("frompayload".to_string());

    let (user, pass) = redis_client_credentials(config, "redis://bob:fromurl@localhost:6379/0")
        .expect("build_client");
    assert_eq!(user.as_deref(), Some("alice"));
    assert_eq!(pass.as_deref(), Some("frompayload"));
}

#[test]
fn test_url_userinfo_is_preserved_when_no_explicit_credentials() {
    // When neither `redis_username` nor `redis_password` is set, the URL
    // userinfo flows through (matches redis-rs' default URL parsing).
    let config = make_config("redis://carol:urlpw@localhost:6379/0", false);

    let (user, pass) = redis_client_credentials(config, "redis://carol:urlpw@localhost:6379/0")
        .expect("build_client");
    assert_eq!(user.as_deref(), Some("carol"));
    assert_eq!(pass.as_deref(), Some("urlpw"));
}

#[test]
fn test_password_only_credential() {
    // Common Redis 5 pattern: AUTH with no username, just a password.
    let mut config = make_config("redis://localhost:6379/0", false);
    config.username = None;
    config.password = Some("redis-pw".to_string());

    let (user, pass) =
        redis_client_credentials(config, "redis://localhost:6379/0").expect("build_client");
    assert_eq!(user, None);
    assert_eq!(pass.as_deref(), Some("redis-pw"));
}

#[test]
fn test_no_credentials_means_unauthenticated() {
    let config = make_config("redis://localhost:6379/0", false);
    let (user, pass) =
        redis_client_credentials(config, "redis://localhost:6379/0").expect("build_client");
    assert_eq!(user, None);
    assert_eq!(pass, None);
}

#[test]
fn test_from_plugin_config_local_modes() {
    assert!(
        RedisConfig::from_plugin_config(&json!({}), "ferrum:test")
            .unwrap()
            .is_none()
    );
    assert!(
        RedisConfig::from_plugin_config(&json!({"sync_mode": "local"}), "ferrum:test")
            .unwrap()
            .is_none()
    );
}

#[test]
fn test_from_plugin_config_rejects_invalid_redis_mode() {
    let cases = [
        json!(null),
        json!([]),
        json!({"sync_mode": false}),
        json!({"sync_mode": "redsi"}),
        json!({"sync_mode": "redis"}),
        json!({"sync_mode": "redis", "redis_url": ""}),
        json!({"sync_mode": "redis", "redis_url": "redis://localhost:6379/0", "redis_tls": "true"}),
        json!({"sync_mode": "redis", "redis_url": "redis://localhost:6379/0", "redis_key_prefix": ""}),
        json!({"sync_mode": "redis", "redis_url": "redis://localhost:6379/0", "redis_pool_size": 0}),
        json!({"sync_mode": "redis", "redis_url": "redis://localhost:6379/0", "redis_connect_timeout_seconds": 0}),
        json!({"sync_mode": "redis", "redis_url": "redis://localhost:6379/0", "redis_health_check_interval_seconds": 0}),
        json!({"sync_mode": "redis", "redis_url": "redis://localhost:6379/0", "redis_username": false}),
        json!({"sync_mode": "redis", "redis_url": "redis://localhost:6379/0", "redis_password": []}),
    ];

    for config in cases {
        assert!(
            RedisConfig::from_plugin_config(&config, "ferrum:test").is_err(),
            "config should fail validation: {config}"
        );
    }
}

#[test]
fn test_from_plugin_config_rejects_malformed_redis_urls() {
    for redis_url in [
        "not a url",
        "http://cache.internal:6379/0",
        "redis:///0",
        "rediss:///0",
    ] {
        let config = json!({
            "sync_mode": "redis",
            "redis_url": redis_url
        });
        assert!(
            RedisConfig::from_plugin_config(&config, "ferrum:test").is_err(),
            "redis_url should fail validation: {redis_url}"
        );
    }
}

#[test]
fn test_from_plugin_config_parses_valid_redis_mode() {
    let config = RedisConfig::from_plugin_config(
        &json!({
            "sync_mode": "redis",
            "redis_url": "redis://cache.internal:6379/0",
            "redis_tls": true,
            "redis_key_prefix": "tenant:rate",
            "redis_pool_size": 8,
            "redis_connect_timeout_seconds": 2,
            "redis_health_check_interval_seconds": 3,
            "redis_username": "svc",
            "redis_password": "secret"
        }),
        "ferrum:test",
    )
    .unwrap()
    .unwrap();

    assert_eq!(config.url, "redis://cache.internal:6379/0");
    assert!(config.tls);
    assert_eq!(config.key_prefix, "tenant:rate");
    assert_eq!(config.pool_size, 8);
    assert_eq!(config.connect_timeout_seconds, 2);
    assert_eq!(config.health_check_interval_seconds, 3);
    assert_eq!(config.username.as_deref(), Some("svc"));
    assert_eq!(config.password.as_deref(), Some("secret"));
}

// ── Connection-attempt timeout wiring (issue #2310) ───────────────────────
//
// redis-rs 1.2.1 defaults ConnectionManager/AsyncConnectionConfig timeouts to
// one second. Ferrum must install `redis_connect_timeout_seconds` into those
// inner configs so values above one second are effective. Assertions below are
// outcome-based (success/failure / config equality), not wall-clock ranges.

#[test]
fn connect_timeout_is_installed_into_redis_manager_config_above_and_below_one_second() {
    for seconds in [1_u64, 2, 5, 30] {
        let mut config = make_config("redis://127.0.0.1:6379/0", false);
        config.connect_timeout_seconds = seconds;
        let client = redis_rate_limit_client_for_test(config);
        assert_eq!(
            client.connection_timeout_for_test(),
            Duration::from_secs(seconds)
        );
        assert_eq!(
            client.connection_manager_timeout_for_test(),
            Some(Duration::from_secs(seconds)),
            "inner ConnectionManagerConfig must carry Ferrum timeout ({seconds}s), not the crate 1s default"
        );
    }
}

/// Accept TCP, optionally delay, then answer every RESP array command with +OK.
///
/// Used to simulate a Redis endpoint whose protocol handshake is delayed after
/// TCP accept (the failure mode in issue #2310).
async fn spawn_delayed_redis_handshake_server(
    handshake_delay: Option<Duration>,
) -> (u16, oneshot::Sender<()>, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = listener.local_addr().expect("local_addr").port();
    let accepts = Arc::new(AtomicUsize::new(0));
    let accepts_task = Arc::clone(&accepts);
    let (shutdown_tx, mut shutdown_rx) = oneshot::channel::<()>();

    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = &mut shutdown_rx => break,
                accepted = listener.accept() => {
                    let Ok((mut stream, _)) = accepted else { break; };
                    accepts_task.fetch_add(1, Ordering::Relaxed);
                    let delay = handshake_delay;
                    tokio::spawn(async move {
                        if let Some(delay) = delay {
                            tokio::time::sleep(delay).await;
                        }
                        let mut buf = vec![0_u8; 4096];
                        loop {
                            match stream.read(&mut buf).await {
                                Ok(0) | Err(_) => break,
                                Ok(n) => {
                                    // Rough RESP command count: each top-level array
                                    // begins with '*'. Enough for CLIENT SETINFO pipelines.
                                    let commands = buf[..n].iter().filter(|&&b| b == b'*').count().max(1);
                                    let mut reply = Vec::new();
                                    for _ in 0..commands {
                                        reply.extend_from_slice(b"+OK\r\n");
                                    }
                                    if stream.write_all(&reply).await.is_err() {
                                        break;
                                    }
                                }
                            }
                        }
                    });
                }
            }
        }
    });

    (port, shutdown_tx, accepts)
}

#[tokio::test]
async fn connect_timeout_above_one_second_allows_delayed_redis_handshake() {
    // Handshake completes after >1s. With the buggy crate default (1s) this
    // fails; with Ferrum's configured 5s inner timeout it must succeed.
    let (port, shutdown, _accepts) =
        spawn_delayed_redis_handshake_server(Some(Duration::from_millis(1500))).await;
    let mut config = make_config(&format!("redis://127.0.0.1:{port}/0"), false);
    config.connect_timeout_seconds = 5;
    config.health_check_interval_seconds = 60;
    let client = redis_rate_limit_client_for_test(config);

    assert!(
        client.connect_cached_for_test().await,
        "cached path must honor redis_connect_timeout_seconds > 1s"
    );

    // Fresh client for dedicated path (cached manager is already warm).
    let mut config = make_config(&format!("redis://127.0.0.1:{port}/0"), false);
    config.connect_timeout_seconds = 5;
    config.health_check_interval_seconds = 60;
    let dedicated = redis_rate_limit_client_for_test(config);
    assert!(
        dedicated.connect_dedicated_for_test().await,
        "dedicated path must honor redis_connect_timeout_seconds > 1s"
    );

    let mut config = make_config(&format!("redis://127.0.0.1:{port}/0"), false);
    config.connect_timeout_seconds = 5;
    config.health_check_interval_seconds = 60;
    let health = redis_rate_limit_client_for_test(config);
    assert!(
        health.health_check_connect_for_test().await,
        "health-check path must honor redis_connect_timeout_seconds > 1s"
    );

    let _ = shutdown.send(());
}

#[tokio::test]
async fn connect_timeout_of_one_second_fails_closed_on_hung_handshake() {
    // Accept, then delay the Redis protocol reply far beyond the configured
    // timeout. A 1s Ferrum timeout must fail closed on every path. Outcomes
    // only — no elapsed-time assertions.
    let (port, shutdown, accepts) =
        spawn_delayed_redis_handshake_server(Some(Duration::from_secs(30))).await;

    let mut config = make_config(&format!("redis://127.0.0.1:{port}/0"), false);
    config.connect_timeout_seconds = 1;
    config.health_check_interval_seconds = 60;
    let client = redis_rate_limit_client_for_test(config);
    assert!(
        !client.connect_cached_for_test().await,
        "cached path must fail closed when handshake exceeds 1s timeout"
    );
    assert!(
        !client.is_available(),
        "failed connect must mark Redis unavailable for local fallback"
    );
    assert!(
        accepts.load(Ordering::Relaxed) >= 1,
        "server must have accepted at least one dial attempt"
    );

    let mut config = make_config(&format!("redis://127.0.0.1:{port}/0"), false);
    config.connect_timeout_seconds = 1;
    config.health_check_interval_seconds = 60;
    let dedicated = redis_rate_limit_client_for_test(config);
    assert!(
        !dedicated.connect_dedicated_for_test().await,
        "dedicated path must fail closed when handshake exceeds 1s timeout"
    );

    let mut config = make_config(&format!("redis://127.0.0.1:{port}/0"), false);
    config.connect_timeout_seconds = 1;
    config.health_check_interval_seconds = 60;
    let health = redis_rate_limit_client_for_test(config);
    assert!(
        !health.health_check_connect_for_test().await,
        "health-check path must fail closed when handshake exceeds 1s timeout"
    );

    let _ = shutdown.send(());
}

#[test]
fn plugin_consumers_parse_connect_timeout_above_one_second() {
    // rate_limiting / graphql / grpc_method_router all share RedisConfig parsing.
    // Prove each consumer's documented default prefix + a >1s timeout parses.
    for (prefix, seconds) in [
        ("ferrum:rate_limiting", 5_u64),
        ("ferrum:graphql", 2_u64),
        ("ferrum:grpc_method_router", 10_u64),
    ] {
        let config = RedisConfig::from_plugin_config(
            &json!({
                "sync_mode": "redis",
                "redis_url": "redis://127.0.0.1:6379/0",
                "redis_connect_timeout_seconds": seconds,
            }),
            prefix,
        )
        .expect("parse")
        .expect("redis mode");
        assert_eq!(config.connect_timeout_seconds, seconds);
        assert_eq!(config.key_prefix, prefix);
        let client = redis_rate_limit_client_for_test(config);
        assert_eq!(
            client.connection_manager_timeout_for_test(),
            Some(Duration::from_secs(seconds))
        );
    }
}

// ── redis_pool_size cardinality / selection (issue #2304) ─────────────────
//
// Before the fix, `redis_pool_size` was parsed and validated but every instance
// cached exactly one ConnectionManager. These tests prove configured pool size
// controls runtime cardinality and round-robin selection — not merely parsing.

#[test]
fn pool_size_controls_client_cardinality_for_named_consumers() {
    // rate_limiting / graphql / grpc_method_router all construct RedisRateLimitClient
    // through RedisConfig / RateLimitBackend::from_plugin_config.
    for (prefix, pool_size) in [
        ("ferrum:rate_limiting", 1_usize),
        ("ferrum:graphql", 3_usize),
        ("ferrum:grpc_method_router", 8_usize),
    ] {
        let config = RedisConfig::from_plugin_config(
            &json!({
                "sync_mode": "redis",
                "redis_url": "redis://127.0.0.1:6379/0",
                "redis_pool_size": pool_size,
            }),
            prefix,
        )
        .expect("parse")
        .expect("redis mode");
        assert_eq!(config.pool_size, pool_size);
        assert_eq!(config.key_prefix, prefix);
        let client = redis_rate_limit_client_for_test(config);
        assert_eq!(
            client.pool_size_for_test(),
            pool_size,
            "client pool must match redis_pool_size for {prefix}"
        );
        assert_eq!(
            client.cached_pool_cardinality_for_test(),
            0,
            "pool slots must be empty before lazy establishment"
        );
    }
}

#[test]
fn pool_slot_selection_is_deterministic_round_robin() {
    let mut config = make_config("redis://127.0.0.1:6379/0", false);
    config.pool_size = 4;
    let client = redis_rate_limit_client_for_test(config);
    assert_eq!(
        client.select_slot_indexes_for_test(10),
        vec![0, 1, 2, 3, 0, 1, 2, 3, 0, 1]
    );

    let mut config = make_config("redis://127.0.0.1:6379/0", false);
    config.pool_size = 1;
    let single = redis_rate_limit_client_for_test(config);
    assert_eq!(single.select_slot_indexes_for_test(5), vec![0, 0, 0, 0, 0]);
}

#[tokio::test]
async fn pool_size_one_establishes_single_tcp_connection() {
    let (port, shutdown, accepts) = spawn_delayed_redis_handshake_server(None).await;
    let mut config = make_config(&format!("redis://127.0.0.1:{port}/0"), false);
    config.pool_size = 1;
    config.health_check_interval_seconds = 60;
    let client = redis_rate_limit_client_for_test(config);

    assert_eq!(client.warm_pool_for_test().await, 1);
    assert_eq!(client.cached_pool_cardinality_for_test(), 1);
    assert_eq!(
        accepts.load(Ordering::Relaxed),
        1,
        "pool_size=1 must open exactly one multiplexed TCP connection"
    );

    // Re-warming must reuse the cached manager, not dial again.
    assert_eq!(client.warm_pool_for_test().await, 1);
    assert_eq!(accepts.load(Ordering::Relaxed), 1);

    let _ = shutdown.send(());
}

#[tokio::test]
async fn pool_size_four_establishes_four_tcp_connections() {
    let (port, shutdown, accepts) = spawn_delayed_redis_handshake_server(None).await;
    let mut config = make_config(&format!("redis://127.0.0.1:{port}/0"), false);
    config.pool_size = 4;
    config.health_check_interval_seconds = 60;
    let client = redis_rate_limit_client_for_test(config);

    assert_eq!(client.warm_pool_for_test().await, 4);
    assert_eq!(client.cached_pool_cardinality_for_test(), 4);
    assert_eq!(
        accepts.load(Ordering::Relaxed),
        4,
        "pool_size=4 must open four multiplexed TCP connections"
    );

    // Second warm must reuse all slots.
    assert_eq!(client.warm_pool_for_test().await, 4);
    assert_eq!(accepts.load(Ordering::Relaxed), 4);
    assert_eq!(client.cached_pool_cardinality_for_test(), 4);

    let _ = shutdown.send(());
}

#[tokio::test]
async fn pool_clear_on_reconnect_drops_all_slots_then_reestablishes() {
    let (port, shutdown, accepts) = spawn_delayed_redis_handshake_server(None).await;
    let mut config = make_config(&format!("redis://127.0.0.1:{port}/0"), false);
    config.pool_size = 3;
    config.health_check_interval_seconds = 60;
    let client = redis_rate_limit_client_for_test(config);

    assert_eq!(client.warm_pool_for_test().await, 3);
    assert_eq!(accepts.load(Ordering::Relaxed), 3);

    // Reconnect clearing must wipe every slot (partial-failure / mark_unavailable path).
    client.clear_pool_for_test();
    assert_eq!(client.cached_pool_cardinality_for_test(), 0);

    assert_eq!(client.warm_pool_for_test().await, 3);
    assert_eq!(
        accepts.load(Ordering::Relaxed),
        6,
        "after clear, all three slots must dial again"
    );
    assert_eq!(client.cached_pool_cardinality_for_test(), 3);

    let _ = shutdown.send(());
}

#[tokio::test]
async fn named_consumer_pool_sizes_produce_matching_tcp_cardinality() {
    // End-to-end for the three issue-named consumers: parse their config shape,
    // construct the shared client, and prove TCP accepts == redis_pool_size.
    for (prefix, pool_size) in [
        ("ferrum:rate_limiting", 2_usize),
        ("ferrum:graphql", 5_usize),
        ("ferrum:grpc_method_router", 3_usize),
    ] {
        let (port, shutdown, accepts) = spawn_delayed_redis_handshake_server(None).await;
        let config = RedisConfig::from_plugin_config(
            &json!({
                "sync_mode": "redis",
                "redis_url": format!("redis://127.0.0.1:{port}/0"),
                "redis_pool_size": pool_size,
                "redis_health_check_interval_seconds": 60,
            }),
            prefix,
        )
        .expect("parse")
        .expect("redis mode");
        let client = redis_rate_limit_client_for_test(config);
        assert_eq!(client.pool_size_for_test(), pool_size);
        assert_eq!(client.warm_pool_for_test().await, pool_size);
        assert_eq!(
            accepts.load(Ordering::Relaxed),
            pool_size,
            "{prefix}: TCP accepts must equal redis_pool_size={pool_size}"
        );
        assert_eq!(client.cached_pool_cardinality_for_test(), pool_size);
        let _ = shutdown.send(());
    }
}

#[test]
fn rate_limit_backend_from_plugin_config_honors_pool_size_for_named_consumers() {
    use ferrum_edge::plugins::utils::http_client::PluginHttpClient;
    use ferrum_edge::plugins::utils::rate_limit::{
        DynamicHttpRateLimitAlgorithm, RateLimitBackend,
    };

    let http = PluginHttpClient::default();
    let algorithm = DynamicHttpRateLimitAlgorithm::new();

    for (plugin_name, pool_size) in [
        ("rate_limiting", 1_usize),
        ("graphql", 4_usize),
        ("grpc_method_router", 7_usize),
    ] {
        let backend: RateLimitBackend<String, DynamicHttpRateLimitAlgorithm> =
            RateLimitBackend::from_plugin_config(
                plugin_name,
                &json!({
                    "sync_mode": "redis",
                    "redis_url": "redis://127.0.0.1:6379/0",
                    "redis_pool_size": pool_size,
                    "redis_health_check_interval_seconds": 60,
                }),
                &http,
                algorithm,
            )
            .expect("failover backend");
        assert!(matches!(backend, RateLimitBackend::Failover(_)));
        assert_eq!(
            backend.redis_pool_size_for_test(),
            Some(pool_size),
            "{plugin_name}: RateLimitBackend must retain redis_pool_size"
        );
    }

    let local: RateLimitBackend<String, DynamicHttpRateLimitAlgorithm> =
        RateLimitBackend::from_plugin_config(
            "rate_limiting",
            &json!({"sync_mode": "local"}),
            &http,
            algorithm,
        )
        .expect("local backend");
    assert_eq!(local.redis_pool_size_for_test(), None);
}
