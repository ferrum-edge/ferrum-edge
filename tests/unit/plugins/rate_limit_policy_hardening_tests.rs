//! Rate-limit policy hardening coverage for three advisories:
//!
//! * GHSA-q3p3-94cj-8wh6 — rate-limiter plugins silently ignored top-level
//!   policy typos, so a misspelled synchronization/identity/Redis key let a
//!   security-relevant default replace the intended policy.
//! * GHSA-jjjw-rqjm-fvf3 — unbounded window/request specifications underflowed
//!   monotonic subtraction, wrapped signed Redis TTLs into a counter-deleting
//!   expiry, or allowed request-controlled per-key memory growth.
//! * GHSA-gr3x-g777-hm78 — every instance of one plugin type in a namespace
//!   received the same default Redis prefix, so independent policies
//!   incremented and rejected against each other's counters.

use std::time::{Duration, Instant};

use ferrum_edge::_test_support::{
    create_rate_limit_plugin_with_config_id, rate_limit_redis_key_prefix,
};
use ferrum_edge::plugins::utils::rate_limit::{
    AiRateLimitOp, AiTokenRateAlgorithm, DynamicHttpRateLimitAlgorithm, DynamicRateLimitOp,
    LOCAL_TOKEN_BUCKET_MAX_WINDOW_SECONDS, LocalLimiter, LocalWindowAlgorithm,
    MAX_RATE_LIMIT_MAX_REQUESTS, MAX_RATE_LIMIT_WINDOW_SECONDS, RateLimitAlgorithm,
    RateLimitWindowSpec, RedisLimiter, SLIDING_WINDOW_BUCKET_COUNT, SlidingWindow, TokenBucket,
    UdpRateLimitAlgorithm, UdpRateLimitOp, WS_FRAME_REDIS_MAX_WINDOW_SECONDS, WsFrameRateAlgorithm,
    local_window_algorithm, parse_redis_failure_policy, single_window_ttl_seconds,
    two_window_ttl_seconds, validate_max_requests, validate_window_seconds,
    validate_ws_frame_rate_params,
};
use ferrum_edge::plugins::{PluginHttpClient, create_plugin};
use ferrum_edge::startup::render_startup_error;
use serde_json::{Value, json};

const OVER_WINDOW: u64 = MAX_RATE_LIMIT_WINDOW_SECONDS + 1;
const OVER_REQUESTS: u64 = MAX_RATE_LIMIT_MAX_REQUESTS + 1;

#[test]
fn shared_rate_limit_bounds_keep_schema_fields_and_withhold_values_and_labels() {
    let label = "grpc_method_router: method_rate_limits[''UNREGISTERED_METHOD\"\\\n`host`']";
    for (error, expected) in [
        (
            validate_window_seconds(label, "limits[2].window_seconds", u64::MAX).unwrap_err(),
            format!(
                "<redacted scalar>: `limits[2].window_seconds` must be <= \
                 {MAX_RATE_LIMIT_WINDOW_SECONDS} seconds, got: <redacted scalar>"
            ),
        ),
        (
            validate_max_requests(label, "limits[2].max_requests", u64::MAX).unwrap_err(),
            format!(
                "<redacted scalar>: `limits[2].max_requests` must be <= \
                 {MAX_RATE_LIMIT_MAX_REQUESTS}, got: <redacted scalar>"
            ),
        ),
        (
            validate_window_seconds(label, "window_seconds", 0).unwrap_err(),
            "<redacted scalar>: `window_seconds` must be greater than zero".to_string(),
        ),
        (
            validate_max_requests(label, "max_requests", 0).unwrap_err(),
            "<redacted scalar>: `max_requests` must be greater than zero".to_string(),
        ),
    ] {
        assert_eq!(
            render_startup_error(anyhow::Error::msg(error), &[]),
            expected
        );
    }
}

#[test]
fn rendered_http_rate_bounds_preserve_the_real_nonzero_rule_ordinal() {
    for (field, maximum) in [
        ("window_seconds", MAX_RATE_LIMIT_WINDOW_SECONDS),
        ("max_requests", MAX_RATE_LIMIT_MAX_REQUESTS),
        ("requests_per_second", MAX_RATE_LIMIT_MAX_REQUESTS),
        ("requests_per_minute", MAX_RATE_LIMIT_MAX_REQUESTS),
        ("requests_per_hour", MAX_RATE_LIMIT_MAX_REQUESTS),
    ] {
        for supplied in [0, maximum + 1] {
            let mut rule = json!({
                "scope": "consumers",
                "consumers": ["UNREGISTERED_CONSUMER"],
            });
            if field == "window_seconds" || field == "max_requests" {
                rule["window_seconds"] = json!(1);
                rule["max_requests"] = json!(1);
            }
            rule[field] = json!(supplied);
            let error = rate_limiting(json!({
                "limit_by": "consumer",
                "limits": [
                    {"scope": "default", "requests_per_second": 10},
                    rule,
                ],
            }))
            .expect_err("the second rule must retain the shared bound rejection");
            let rendered = render_startup_error(anyhow::Error::msg(error), &[]);
            let reason = if supplied == 0 {
                "must be greater than zero".to_string()
            } else if field == "window_seconds" {
                format!("must be <= {maximum} seconds, got: <redacted scalar>")
            } else {
                format!("must be <= {maximum}, got: <redacted scalar>")
            };
            assert_eq!(
                rendered,
                format!("rate_limiting: `limits[1]`: <redacted scalar>: `{field}` {reason}")
            );
        }
    }
}

#[test]
fn rendered_graphql_rate_bounds_preserve_the_schema_parent_without_operation_keys() {
    for (parent, key) in [
        ("type_rate_limits", "query"),
        ("operation_rate_limits", "UNREGISTERED_OPERATION"),
    ] {
        for (field, supplied) in [
            ("max_requests", OVER_REQUESTS),
            ("window_seconds", OVER_WINDOW),
        ] {
            let mut spec = json!({"max_requests": 1, "window_seconds": 1});
            spec[field] = json!(supplied);
            let error = graphql(json!({(parent): {(key): spec}}))
                .expect_err("the actual GraphQL constructor must reject the bound");
            let rendered = render_startup_error(anyhow::Error::msg(error), &[]);
            assert!(
                rendered.starts_with(&format!("graphql: `{parent}`: <redacted scalar>: ")),
                "{rendered}"
            );
            assert!(
                rendered.contains(&format!("`{field}` must be <=")),
                "{rendered}"
            );
            assert!(!rendered.contains(key), "{rendered}");
            assert!(!rendered.contains(&supplied.to_string()), "{rendered}");
        }
    }
}

#[test]
fn shared_rate_limit_diagnostics_withhold_method_keys_from_real_callers() {
    let method = "'UNREGISTERED_METHOD\"\\\n`method_rate_limits`";
    for spec in [
        json!({"max_requests": OVER_REQUESTS, "window_seconds": 1}),
        json!({"max_requests": 1, "window_seconds": OVER_WINDOW}),
        json!({"max_requests": 1, "window_seconds": 1, "max_requets": false}),
    ] {
        let field = if spec.get("max_requets").is_some() {
            "did you mean `max_requests`?"
        } else if spec["max_requests"] == json!(OVER_REQUESTS) {
            "`max_requests` must be <="
        } else {
            "`window_seconds` must be <="
        };
        let error = grpc_method_router(json!({"method_rate_limits": {(method): spec}}))
            .expect_err("invalid method rate specifications must fail admission");
        let rendered = render_startup_error(anyhow::Error::msg(error), &[]);
        assert!(rendered.contains(field), "{rendered}");
        for withheld in [
            "UNREGISTERED_METHOD".to_string(),
            "max_requets".to_string(),
            "false".to_string(),
            OVER_REQUESTS.to_string(),
            OVER_WINDOW.to_string(),
        ] {
            assert!(!rendered.contains(&withheld), "{rendered}");
        }
    }
}

#[test]
fn shared_redis_failure_policy_diagnostics_keep_fixed_choices_without_values() {
    for supplied in [
        json!("'UNREGISTERED_POLICY\"\\\n`redis_failure_policy`"),
        json!(true),
        json!(987654321),
        json!({"'UNREGISTERED_KEY": "UNREGISTERED_VALUE"}),
    ] {
        let reason = if supplied.is_string() {
            "must be exactly `fail_closed` or `local_fallback`"
        } else {
            "must be a string (`fail_closed` or `local_fallback`)"
        };
        let error =
            parse_redis_failure_policy("rate_limiting", &json!({"redis_failure_policy": supplied}))
                .unwrap_err();
        assert_eq!(
            render_startup_error(anyhow::Error::msg(error), &[]),
            format!("rate limiting: `redis_failure_policy` {reason}")
        );
    }
}

#[test]
fn shared_redis_identity_diagnostics_withhold_invalid_names_and_ids() {
    let supplied = "'UNREGISTERED_ID\"\\\n`namespace`";
    for (plugin_name, config_id, reason) in [
        (supplied, "config-id", "invalid canonical plugin name"),
        ("ws_rate_limiting", supplied, "invalid plugin config id"),
    ] {
        let error = RedisLimiter::new_with_config_id(
            plugin_name,
            config_id,
            &json!({}),
            &PluginHttpClient::default(),
            WsFrameRateAlgorithm::new(1.0, 1.0),
        )
        .err()
        .expect("invalid identities must fail before Redis construction");
        let rendered = render_startup_error(anyhow::Error::msg(error), &[]);
        assert!(rendered.contains(reason), "{rendered}");
        assert!(
            rendered.contains("must start with an alphanumeric"),
            "{rendered}"
        );
        assert!(!rendered.contains("UNREGISTERED_ID"), "{rendered}");
    }
}

#[test]
fn shared_ws_rate_diagnostics_keep_bounds_and_relations_without_supplied_numbers() {
    for (frames_per_second, burst_size, expected) in [
        (
            0,
            61,
            "`frames_per_second` must be greater than zero".to_string(),
        ),
        (61, 0, "`burst_size` must be greater than zero".to_string()),
        (
            OVER_REQUESTS,
            61,
            format!(
                "`frames_per_second` must be <= {MAX_RATE_LIMIT_MAX_REQUESTS}, \
                 got: <redacted scalar>"
            ),
        ),
        (
            61,
            OVER_REQUESTS,
            format!(
                "`burst_size` must be <= {MAX_RATE_LIMIT_MAX_REQUESTS}, got: <redacted scalar>"
            ),
        ),
        (
            57,
            19,
            "`burst_size` must be >= `frames_per_second`".to_string(),
        ),
        (
            13,
            27,
            "`burst_size` must be an integer multiple of `frames_per_second` \
             so Redis and local sustained rates match"
                .to_string(),
        ),
        (
            2,
            8642,
            format!(
                "`burst_size` / `frames_per_second` refill window exceeds the \
                 Redis-representable maximum of {WS_FRAME_REDIS_MAX_WINDOW_SECONDS} seconds"
            ),
        ),
    ] {
        let error = validate_ws_frame_rate_params(frames_per_second, burst_size).unwrap_err();
        assert_eq!(
            render_startup_error(anyhow::Error::msg(error), &[]),
            format!("ws_rate_limiting: {expected}")
        );
    }
}

fn rate_limiting(config: Value) -> Result<(), String> {
    ferrum_edge::plugins::rate_limiting::RateLimiting::new(&config, PluginHttpClient::default())
        .map(|_| ())
}

fn grpc_method_router(config: Value) -> Result<(), String> {
    create_plugin("grpc_method_router", &config).map(|_| ())
}

fn graphql(config: Value) -> Result<(), String> {
    create_plugin("graphql", &config).map(|_| ())
}

fn udp_rate_limiting(config: Value) -> Result<(), String> {
    create_plugin("udp_rate_limiting", &config).map(|_| ())
}

fn valid_rate_limiting_rule() -> Value {
    json!([{"scope": "default", "requests_per_second": 10}])
}

// ── GHSA-q3p3-94cj-8wh6: strict unknown-key rejection ───────────────────────

#[test]
fn rate_limiting_rejects_misspelled_sync_mode_even_with_a_valid_rule() {
    // The advisory's core scenario: a valid rule made construction succeed, so
    // `sync_mdoe` was dropped and every process enforced its own local budget.
    let error = rate_limiting(json!({
        "limits": valid_rate_limiting_rule(),
        "sync_mdoe": "redis",
        "redis_url": "redis://127.0.0.1:6379/0",
    }))
    .expect_err("misspelled sync_mode must fail admission");
    assert!(error.contains("unknown configuration key(s)"), "{error}");
    assert!(error.contains("config.sync_mdoe"), "{error}");
    assert!(error.contains("sync_mode"), "suggestion missing: {error}");
}

#[test]
fn rate_limiting_rejects_misspelled_identity_and_redis_keys() {
    for key in [
        "limit_byy",
        "redis_tsl",
        "redis_key_prefx",
        "expose_header",
        "redis_pool_sze",
    ] {
        let mut config = serde_json::Map::new();
        config.insert("limits".to_string(), valid_rate_limiting_rule());
        config.insert(key.to_string(), json!("consumer"));
        let error = rate_limiting(Value::Object(config))
            .expect_err("a misspelled root key must fail admission");
        assert!(error.contains(key), "{error}");
    }
}

#[test]
fn rate_limiting_accepts_every_documented_root_key() {
    rate_limiting(json!({
        "limit_by": "consumer",
        "expose_headers": true,
        "limits": [{"scope": "default", "window_seconds": 60, "max_requests": 100}],
        "sync_mode": "redis",
        "redis_url": "redis://127.0.0.1:6379/0",
        "redis_tls": false,
        "redis_key_prefix": "explicit:prefix",
        "redis_pool_size": 4,
        "redis_connect_timeout_seconds": 5,
        "redis_health_check_interval_seconds": 5,
        "redis_username": "user",
        "redis_password": "pass",
        "redis_failure_policy": "local_fallback",
    }))
    .expect("the documented root key set must remain accepted");
}

#[test]
fn grpc_method_router_rejects_misspelled_root_keys_behind_a_valid_method_rule() {
    for key in ["sync_mdoe", "limit_byy", "redis_key_prefx"] {
        let mut config = serde_json::Map::new();
        config.insert(
            "method_rate_limits".to_string(),
            json!({"/pkg.Svc/Method": {"max_requests": 10, "window_seconds": 1}}),
        );
        config.insert(key.to_string(), json!("redis"));
        let error = grpc_method_router(Value::Object(config))
            .expect_err("a valid method rule must not mask an unknown root key");
        assert!(error.contains("unknown configuration key(s)"), "{error}");
        assert!(error.contains(key), "{error}");
    }
}

#[test]
fn grpc_method_router_rejects_unknown_keys_inside_one_method_rate_limit() {
    let error = grpc_method_router(json!({
        "method_rate_limits": {
            "/pkg.Svc/Method": {"max_requests": 10, "window_seconds": 1, "max_requets": 5}
        }
    }))
    .expect_err("unknown per-method spec keys must fail admission");
    assert!(error.contains("max_requets"), "{error}");
}

#[test]
fn grpc_method_router_accepts_every_documented_root_key() {
    grpc_method_router(json!({
        "allow_methods": ["/pkg.Svc/Method"],
        "deny_methods": ["/pkg.Svc/Blocked"],
        "method_rate_limits": {"/pkg.Svc/Method": {"max_requests": 10, "window_seconds": 1}},
        "limit_by": "consumer",
        "sync_mode": "redis",
        "redis_url": "redis://127.0.0.1:6379/0",
        "redis_tls": false,
        "redis_key_prefix": "explicit:prefix",
        "redis_pool_size": 4,
        "redis_connect_timeout_seconds": 5,
        "redis_health_check_interval_seconds": 5,
        "redis_username": "user",
        "redis_password": "pass",
        "redis_failure_policy": "local_fallback",
    }))
    .expect("the documented root key set must remain accepted");
}

#[test]
fn udp_rate_limiting_rejects_misspelled_root_keys() {
    let error = udp_rate_limiting(json!({
        "datagrams_per_second": 100,
        "bytes_per_secnod": 1024,
    }))
    .expect_err("a misspelled byte limit must not load as datagram-only policy");
    assert!(error.contains("bytes_per_secnod"), "{error}");
}

#[test]
fn udp_rate_limiting_accepts_every_documented_root_key() {
    udp_rate_limiting(json!({
        "datagrams_per_second": 100,
        "bytes_per_second": 65536,
        "window_seconds": 5,
        "sync_mode": "redis",
        "redis_url": "redis://127.0.0.1:6379/0",
        "redis_tls": false,
        "redis_key_prefix": "explicit:prefix",
        "redis_pool_size": 4,
        "redis_connect_timeout_seconds": 5,
        "redis_health_check_interval_seconds": 5,
        "redis_username": "user",
        "redis_password": "pass",
        "redis_failure_policy": "local_fallback",
    }))
    .expect("the documented root key set must remain accepted");
}

#[test]
fn ws_rate_limiting_rejects_misspelled_frame_and_redis_keys() {
    let fps_error = create_plugin("ws_rate_limiting", &json!({"frames_per_secod": 1}))
        .err()
        .expect("misspelled frames_per_second must fail admission");
    assert!(
        fps_error.contains("unknown configuration key(s)"),
        "{fps_error}"
    );
    assert!(fps_error.contains("frames_per_secod"), "{fps_error}");
    assert!(fps_error.contains("frames_per_second"), "{fps_error}");

    for key in [
        "sync_mdoe",
        "redis_tsl",
        "redis_key_prefx",
        "redis_pool_sze",
        "redis_connect_timeout_second",
        "redis_health_check_interval_second",
        "redis_usernam",
        "redis_passwrd",
    ] {
        let mut config = serde_json::Map::new();
        config.insert("frames_per_second".to_string(), json!(10));
        config.insert(key.to_string(), json!("redis"));
        let error = create_plugin("ws_rate_limiting", &Value::Object(config))
            .err()
            .expect("a misspelled root key must fail admission");
        assert!(error.contains("unknown configuration key(s)"), "{error}");
        assert!(error.contains(key), "{error}");
    }
}

#[test]
fn ws_rate_limiting_accepts_every_documented_root_key() {
    create_plugin(
        "ws_rate_limiting",
        &json!({
            "frames_per_second": 10,
            "burst_size": 20,
            "close_reason": "slow down",
            "sync_mode": "redis",
            "redis_url": "redis://127.0.0.1:6379/0",
            "redis_tls": false,
            "redis_key_prefix": "explicit:prefix",
            "redis_pool_size": 4,
            "redis_connect_timeout_seconds": 5,
            "redis_health_check_interval_seconds": 5,
            "redis_username": "user",
            "redis_password": "pass",
            "redis_failure_policy": "local_fallback",
        }),
    )
    .expect("the documented root key set must remain accepted");
}

#[test]
fn ai_rate_limiter_rejects_misspelled_sync_mode_even_with_valid_token_limit() {
    let error = create_plugin(
        "ai_rate_limiter",
        &json!({
            "token_limit": 1000,
            "sync_mdoe": "redis",
            "redis_url": "redis://127.0.0.1:6379/0",
        }),
    )
    .err()
    .expect("misspelled sync_mode must fail admission");
    assert!(error.contains("unknown configuration key(s)"), "{error}");
    assert!(error.contains("config.sync_mdoe"), "{error}");
    assert!(error.contains("sync_mode"), "suggestion missing: {error}");
}

#[test]
fn ai_rate_limiter_rejects_misspelled_enforcement_and_redis_keys() {
    for key in [
        "on_unmetered_responce",
        "count_mdoe",
        "limit_byy",
        "provder",
        "expose_header",
        "redis_tsl",
        "redis_key_prefx",
        "redis_pool_sze",
    ] {
        let mut config = serde_json::Map::new();
        config.insert("token_limit".to_string(), json!(1000));
        config.insert(key.to_string(), json!("consumer"));
        let error = create_plugin("ai_rate_limiter", &Value::Object(config))
            .err()
            .expect("a misspelled root key must fail admission");
        assert!(error.contains(key), "{error}");
    }
}

#[test]
fn ai_rate_limiter_accepts_every_documented_root_key() {
    create_plugin(
        "ai_rate_limiter",
        &json!({
            "token_limit": 1000,
            "window_seconds": 60,
            "count_mode": "total_tokens",
            "limit_by": "consumer",
            "expose_headers": true,
            "provider": "openai",
            "on_unmetered_response": "reject",
            "consumer_limits": {"tier-paid": 10_000_000},
            "model_limits": {"o1": 100_000},
            "media_token_estimate": 765,
            "sync_mode": "redis",
            "redis_url": "redis://127.0.0.1:6379/0",
            "redis_tls": false,
            "redis_key_prefix": "explicit:prefix",
            "redis_pool_size": 4,
            "redis_connect_timeout_seconds": 5,
            "redis_health_check_interval_seconds": 5,
            "redis_username": "user",
            "redis_password": "pass",
            "redis_failure_policy": "local_fallback",
        }),
    )
    .expect("the documented root key set must remain accepted");
}

// ── GHSA-jjjw-rqjm-fvf3: bounded numeric configuration ──────────────────────

#[test]
fn rate_limiting_rejects_unbounded_custom_window_and_cap() {
    let error = rate_limiting(json!({
        "limits": [{"scope": "default", "window_seconds": u64::MAX, "max_requests": 1}]
    }))
    .expect_err("u64::MAX window must fail admission");
    assert!(error.contains("window_seconds"), "{error}");

    let error = rate_limiting(json!({
        "limits": [{"scope": "default", "window_seconds": OVER_WINDOW, "max_requests": 1}]
    }))
    .expect_err("one second past the cap must fail admission");
    assert!(error.contains("window_seconds"), "{error}");

    let error = rate_limiting(json!({
        "limits": [{"scope": "default", "window_seconds": 60, "max_requests": OVER_REQUESTS}]
    }))
    .expect_err("an unbounded request cap must fail admission");
    assert!(error.contains("max_requests"), "{error}");
}

#[test]
fn rate_limiting_accepts_the_exact_boundary_values() {
    rate_limiting(json!({
        "limits": [{
            "scope": "default",
            "window_seconds": MAX_RATE_LIMIT_WINDOW_SECONDS,
            "max_requests": MAX_RATE_LIMIT_MAX_REQUESTS,
        }]
    }))
    .expect("the documented maxima must remain configurable");
}

#[test]
fn rate_limiting_rejects_unbounded_preset_windows() {
    for field in [
        "requests_per_second",
        "requests_per_minute",
        "requests_per_hour",
    ] {
        let mut rule = serde_json::Map::new();
        rule.insert("scope".to_string(), json!("default"));
        rule.insert(field.to_string(), json!(OVER_REQUESTS));
        let error = rate_limiting(json!({"limits": [Value::Object(rule)]}))
            .expect_err("an unbounded preset window must fail admission");
        assert!(error.contains(field), "{error}");
    }
}

#[test]
fn rate_limiting_still_rejects_zero_windows_and_caps() {
    assert!(
        rate_limiting(json!({
            "limits": [{"scope": "default", "window_seconds": 0, "max_requests": 1}]
        }))
        .is_err()
    );
    assert!(
        rate_limiting(json!({
            "limits": [{"scope": "default", "window_seconds": 60, "max_requests": 0}]
        }))
        .is_err()
    );
}

#[test]
fn graphql_rejects_unbounded_type_and_operation_rate_specs() {
    let error = graphql(json!({
        "type_rate_limits": {"query": {"max_requests": 1, "window_seconds": u64::MAX}}
    }))
    .expect_err("u64::MAX GraphQL window must fail admission");
    assert!(error.contains("window_seconds"), "{error}");

    let error = graphql(json!({
        "operation_rate_limits": {"GetUser": {"max_requests": OVER_REQUESTS, "window_seconds": 60}}
    }))
    .expect_err("an unbounded GraphQL request cap must fail admission");
    assert!(error.contains("max_requests"), "{error}");

    graphql(json!({
        "type_rate_limits": {
            "query": {
                "max_requests": MAX_RATE_LIMIT_MAX_REQUESTS,
                "window_seconds": MAX_RATE_LIMIT_WINDOW_SECONDS,
            }
        }
    }))
    .expect("the documented maxima must remain configurable");
}

#[test]
fn grpc_method_router_rejects_unbounded_method_rate_specs() {
    let error = grpc_method_router(json!({
        "method_rate_limits": {"/pkg.Svc/M": {"max_requests": 1, "window_seconds": u64::MAX}}
    }))
    .expect_err("u64::MAX gRPC method window must fail admission");
    assert!(error.contains("window_seconds"), "{error}");

    let error = grpc_method_router(json!({
        "method_rate_limits": {"/pkg.Svc/M": {"max_requests": OVER_REQUESTS, "window_seconds": 60}}
    }))
    .expect_err("an unbounded gRPC method request cap must fail admission");
    assert!(error.contains("max_requests"), "{error}");
}

#[test]
fn udp_rate_limiting_rejects_the_extreme_window_that_survived_checked_multiplication() {
    // `rate = 1, window = u64::MAX` passed `rate * window` but wrapped
    // `window + 1` (Redis TTL) and `window * 2` (retention) to zero.
    let error = udp_rate_limiting(json!({
        "datagrams_per_second": 1,
        "window_seconds": u64::MAX,
    }))
    .expect_err("u64::MAX UDP window must fail admission");
    assert!(error.contains("window_seconds"), "{error}");

    udp_rate_limiting(json!({
        "datagrams_per_second": 1,
        "window_seconds": MAX_RATE_LIMIT_WINDOW_SECONDS,
    }))
    .expect("the documented maximum must remain configurable");
}

#[test]
fn ai_rate_limiter_rejects_unbounded_window() {
    let config = json!({"token_limit": 10, "window_seconds": u64::MAX});
    let error = create_plugin("ai_rate_limiter", &config)
        .err()
        .expect("u64::MAX AI token window must fail admission");
    assert!(error.contains("window_seconds"), "{error}");
}

#[test]
fn redis_ttl_helpers_saturate_instead_of_wrapping_into_a_deleting_expiry() {
    // A wrapped TTL became zero or negative, and Redis treats that as DEL — the
    // counter deleted itself on every increment.
    assert_eq!(two_window_ttl_seconds(10), 21);
    assert_eq!(single_window_ttl_seconds(10), 11);
    for window in [u64::MAX, u64::MAX - 1, i64::MAX as u64 + 1] {
        assert!(two_window_ttl_seconds(window) > 0);
        assert!(two_window_ttl_seconds(window) <= i64::MAX as u64);
        assert!(single_window_ttl_seconds(window) > 0);
        assert!(single_window_ttl_seconds(window) <= i64::MAX as u64);
    }
}

// ── GHSA-gr3x-g777-hm78: policy-isolated default Redis keys ─────────────────

fn redis_config_for(plugin_name: &str) -> Value {
    let mut config = match plugin_name {
        "rate_limiting" => json!({"limits": valid_rate_limiting_rule()}),
        "graphql" => json!({
            "type_rate_limits": {"query": {"max_requests": 10, "window_seconds": 1}}
        }),
        "grpc_method_router" => json!({
            "method_rate_limits": {"/pkg.Svc/M": {"max_requests": 10, "window_seconds": 1}}
        }),
        "udp_rate_limiting" => json!({"datagrams_per_second": 10}),
        other => panic!("unsupported plugin in this fixture: {other}"),
    };
    let object = config.as_object_mut().expect("fixture is an object");
    object.insert("sync_mode".to_string(), json!("redis"));
    object.insert("redis_url".to_string(), json!("redis://127.0.0.1:6379/0"));
    config
}

#[test]
fn independent_policies_of_one_plugin_type_no_longer_share_a_default_prefix() {
    for plugin_name in [
        "rate_limiting",
        "graphql",
        "grpc_method_router",
        "udp_rate_limiting",
    ] {
        let config = redis_config_for(plugin_name);
        let a = rate_limit_redis_key_prefix(plugin_name, &config, "policy-a")
            .expect("policy-a admits")
            .expect("redis mode yields a prefix");
        let b = rate_limit_redis_key_prefix(plugin_name, &config, "policy-b")
            .expect("policy-b admits")
            .expect("redis mode yields a prefix");
        assert_ne!(
            a, b,
            "{plugin_name}: two independent policies must not share counters"
        );
        assert!(a.ends_with(":policy-a"), "{plugin_name}: {a}");
        assert!(
            a.contains(plugin_name),
            "{plugin_name}: prefix must stay plugin-scoped: {a}"
        );
    }
}

#[test]
fn replicas_of_the_same_policy_still_share_one_distributed_budget() {
    // Cross-data-plane sharing is the property the fix must preserve: the same
    // configured resource id must resolve to the same key space.
    let config = redis_config_for("rate_limiting");
    let first = rate_limit_redis_key_prefix("rate_limiting", &config, "rl-public-api")
        .expect("admits")
        .expect("redis mode yields a prefix");
    let second = rate_limit_redis_key_prefix("rate_limiting", &config, "rl-public-api")
        .expect("admits")
        .expect("redis mode yields a prefix");
    assert_eq!(first, second);
}

#[test]
fn an_explicit_prefix_remains_the_shared_budget_opt_in() {
    let mut config = redis_config_for("rate_limiting");
    config
        .as_object_mut()
        .expect("fixture is an object")
        .insert("redis_key_prefix".to_string(), json!("team:shared-budget"));
    let a = rate_limit_redis_key_prefix("rate_limiting", &config, "policy-a")
        .expect("admits")
        .expect("redis mode yields a prefix");
    let b = rate_limit_redis_key_prefix("rate_limiting", &config, "policy-b")
        .expect("admits")
        .expect("redis mode yields a prefix");
    assert_eq!(a, "team:shared-budget");
    assert_eq!(a, b);
}

#[test]
fn local_mode_reports_no_redis_prefix() {
    let config = json!({"limits": valid_rate_limiting_rule()});
    assert_eq!(
        rate_limit_redis_key_prefix("rate_limiting", &config, "policy-a").expect("admits"),
        None
    );
}

#[test]
fn the_production_factory_threads_the_config_id_into_every_rate_limit_plugin() {
    // A blank id must fail closed: it would otherwise collapse sibling policies
    // back onto one shared default key space. Reaching this error at all proves
    // the factory passed the id through to the constructor.
    let method_rate_limits = json!({
        "method_rate_limits": {"/pkg.Svc/M": {"max_requests": 10, "window_seconds": 1}}
    });
    for (plugin_name, config) in [
        (
            "rate_limiting",
            json!({"limits": valid_rate_limiting_rule()}),
        ),
        (
            "graphql",
            json!({"type_rate_limits": {"query": {"max_requests": 10, "window_seconds": 1}}}),
        ),
        ("grpc_method_router", method_rate_limits),
        ("udp_rate_limiting", json!({"datagrams_per_second": 10})),
        ("ws_rate_limiting", json!({"frames_per_second": 10})),
        (
            "ai_rate_limiter",
            json!({"token_limit": 100, "window_seconds": 60}),
        ),
    ] {
        create_rate_limit_plugin_with_config_id(plugin_name, &config, Some("  "))
            .expect_err(&format!("{plugin_name}: blank config id must fail closed"));
        create_rate_limit_plugin_with_config_id(plugin_name, &config, Some("policy:shared"))
            .expect_err(&format!(
                "{plugin_name}: delimiter-bearing config id must fail closed"
            ));
        create_rate_limit_plugin_with_config_id(plugin_name, &config, Some("policy-a"))
            .unwrap_or_else(|error| panic!("{plugin_name}: valid config id must admit: {error}"));
        create_rate_limit_plugin_with_config_id(plugin_name, &config, None)
            .unwrap_or_else(|error| panic!("{plugin_name}: standalone id must admit: {error}"));
    }
}

// ── GHSA-jjjw-rqjm-fvf3: bounded aggregate local sliding window ─────────────

#[test]
fn sliding_window_retained_state_is_fixed_under_sustained_hot_key() {
    // The advisory's residual: one Instant per admission let a hot key grow
    // with max_requests. Aggregate buckets stay at SLIDING_WINDOW_BUCKET_COUNT.
    let mut window = SlidingWindow::new(250_000, Duration::from_secs(60));
    let now = Instant::now();
    for i in 0..200_000u64 {
        assert!(window.would_allow(now), "hot-key admission {i} must pass");
        window.increment(now);
        assert_eq!(
            window.retained_buckets(),
            SLIDING_WINDOW_BUCKET_COUNT,
            "retained bucket slots must not grow with admissions"
        );
    }
    assert_eq!(window.counted_requests(), 200_000);
    assert_eq!(window.retained_buckets(), SlidingWindow::bucket_capacity());
}

#[test]
fn sliding_window_enforces_configured_boundary() {
    let mut window = SlidingWindow::new(4, Duration::from_secs(30));
    let now = Instant::now();
    for _ in 0..4 {
        assert!(window.would_allow(now));
        window.increment(now);
    }
    assert!(!window.would_allow(now), "limit+1 must deny");
    assert_eq!(window.remaining(), 0);
    assert_eq!(window.retained_buckets(), SLIDING_WINDOW_BUCKET_COUNT);
}

#[test]
fn sliding_window_does_not_drop_the_oldest_bucket_at_the_window_boundary() {
    // One 63-second window spans 63 sub-intervals. At exactly one window,
    // requests at the inclusive cutoff are still live. The prior 64-interval
    // indexing reused slot zero here and under-counted the window.
    let mut window = SlidingWindow::new(1, Duration::from_secs(63));
    let start = Instant::now();
    assert!(window.would_allow(start));
    window.increment(start);

    let at_cutoff = start
        .checked_add(Duration::from_secs(63))
        .expect("test Instant supports a 63-second offset");
    assert!(
        !window.would_allow(at_cutoff),
        "the inclusive oldest bucket must remain counted"
    );
    assert!(window.has_recent_activity(at_cutoff));

    let conservative_horizon = start
        .checked_add(Duration::from_secs(64))
        .expect("test Instant supports a 64-second offset");
    assert!(
        window.would_allow(conservative_horizon),
        "over-count must end within one sub-interval"
    );
    assert!(!window.has_recent_activity(conservative_horizon));
}

#[test]
fn token_bucket_ignores_reverse_ordered_concurrent_timestamps() {
    // `LocalLimiter::check` captures time before locking a key, so another
    // request can update the bucket first with a later timestamp. Rewinding
    // last_refill would credit the same interval twice.
    let mut bucket = TokenBucket::from_rate(1.0, 1.0);
    let base = Instant::now();
    bucket.consume(1);

    let future = base
        .checked_add(Duration::from_secs(1))
        .expect("test Instant supports a one-second offset");
    assert!(bucket.would_allow(future, 1));
    bucket.consume(1);
    assert!(!bucket.would_allow(base, 1));

    let half_second_later = future
        .checked_add(Duration::from_millis(500))
        .expect("test Instant supports a subsecond offset");
    assert!(
        !bucket.would_allow(half_second_later, 1),
        "reverse timestamps must not create duplicate refill credit"
    );
}

#[test]
fn sliding_window_reverse_arrival_keeps_live_state_through_cleanup() {
    // Newer sample lands first; an older pre-lock sample follows. The activity
    // watermark must stay at the newer instant so a sweep past the older
    // sample's retention horizon cannot evict still-live aggregate usage.
    let op = DynamicRateLimitOp::new(vec![RateLimitWindowSpec {
        limit: 100,
        duration: Duration::from_secs(60),
    }]);
    let limiter = LocalLimiter::new(DynamicHttpRateLimitAlgorithm::new(), 2);
    let t0 = Instant::now();
    let t_newer = t0
        .checked_add(Duration::from_secs(1))
        .expect("test Instant supports a one-second offset");

    assert!(
        limiter
            .check_at("live-key".to_string(), &op, t_newer)
            .allowed
    );
    assert!(limiter.check_at("live-key".to_string(), &op, t0).allowed);
    assert_eq!(limiter.tracked_keys_count(), 1);

    // For a 60s window, retention is ceil(60*64/63) ≈ 60.95s. A sweep at
    // t0+61s would treat last_activity=t0 as idle, but last_activity=t_newer
    // (t0+1s) is still inside the retention horizon.
    let sweep = t0
        .checked_add(Duration::from_secs(61))
        .expect("test Instant supports a 61-second offset");
    limiter.prune_stale_at(sweep);
    assert!(
        limiter.contains_key(&"live-key".to_string()),
        "reverse-ordered older sample must not rewind activity and prune live state"
    );
    assert_eq!(limiter.tracked_keys_count(), 1);

    // Direct window: older sample after newer must not move the watermark back.
    let mut window = SlidingWindow::new(10, Duration::from_secs(60));
    assert!(window.would_allow(t_newer));
    window.increment(t_newer);
    assert!(window.would_allow(t0));
    window.increment(t0);
    assert!(
        window.has_recent_activity(sweep),
        "activity watermark must remain at the newer admission"
    );
    assert_eq!(window.retained_buckets(), SLIDING_WINDOW_BUCKET_COUNT);
}

#[test]
fn udp_reverse_arrival_keeps_live_state_through_cleanup() {
    let epoch = Instant::now();
    let algorithm = UdpRateLimitAlgorithm::new(Some(1_000), None, 1, epoch);
    let limiter = LocalLimiter::new(algorithm, 2);
    let op = UdpRateLimitOp { datagram_size: 1 };
    let t_newer = epoch
        .checked_add(Duration::from_secs(5))
        .expect("test Instant supports a five-second offset");
    let t_older = epoch
        .checked_add(Duration::from_secs(1))
        .expect("test Instant supports a one-second offset");

    assert!(
        limiter
            .check_at("10.0.0.9".to_string(), &op, t_newer)
            .allowed
    );
    assert!(
        limiter
            .check_at("10.0.0.9".to_string(), &op, t_older)
            .allowed
    );

    // Idle threshold is max(window*2, 10) == 10s. With last_check wrongly
    // rewound to 1s, a sweep at epoch+12s looks idle (11s); with a forward
    // watermark at 5s it is still live (7s).
    let sweep = epoch
        .checked_add(Duration::from_secs(12))
        .expect("test Instant supports a 12-second offset");
    limiter.prune_stale_at(sweep);
    assert!(
        limiter.contains_key(&"10.0.0.9".to_string()),
        "UDP last_check_secs must not move backward under reverse arrival"
    );
}

#[test]
fn ai_token_window_reverse_arrival_keeps_live_state_through_cleanup() {
    let algorithm = AiTokenRateAlgorithm::new(1_000, 60);
    let limiter = LocalLimiter::new(algorithm, 2);
    let t0 = Instant::now();
    let t_newer = t0
        .checked_add(Duration::from_secs(1))
        .expect("test Instant supports a one-second offset");
    let reserve = AiRateLimitOp::Reserve { tokens: 10 };

    assert!(
        limiter
            .check_at("consumer:a".to_string(), &reserve, t_newer)
            .allowed
    );
    assert!(
        limiter
            .check_at("consumer:a".to_string(), &reserve, t0)
            .allowed
    );

    // Activity uses a < window_duration check. At exactly t0+60s an activity
    // marker of t0 looks idle, while a forward marker of t_newer remains live.
    let sweep = t0
        .checked_add(Duration::from_secs(60))
        .expect("test Instant supports a 60-second offset");
    limiter.prune_stale_at(sweep);
    assert!(
        limiter.contains_key(&"consumer:a".to_string()),
        "AI TokenUsageWindow activity must not follow a reverse-ordered back entry"
    );
}

#[test]
fn ai_maximum_window_uses_checked_instant_arithmetic() {
    let algorithm = AiTokenRateAlgorithm::new(10, MAX_RATE_LIMIT_WINDOW_SECONDS);
    let mut state = algorithm.new_state();
    let now = Instant::now();
    let outcome = algorithm.check_local(&mut state, &AiRateLimitOp::Reserve { tokens: 1 }, now);
    assert!(outcome.allowed);
    assert!(algorithm.is_state_active(&state, now));
}

#[test]
fn udp_local_counters_saturate_instead_of_wrapping() {
    let now = Instant::now();
    let algorithm = UdpRateLimitAlgorithm::new(None, Some(u64::MAX - 1), 1, now);
    let mut state = algorithm.new_state();
    let op = UdpRateLimitOp {
        datagram_size: u64::MAX,
    };

    assert!(!algorithm.check_local(&mut state, &op, now).allowed);
    assert!(
        !algorithm.check_local(&mut state, &op, now).allowed,
        "overflow must stay denied rather than wrap below the byte limit"
    );
}

#[test]
fn http_graphql_grpc_shared_windows_select_bounded_sliding_aggregate() {
    // Ordinary HTTP / GraphQL / gRPC-method windows > 5s all route through
    // `new_http_window_states` → SlidingWindow. Prove the shared selector and
    // that construction still admits those plugins onto the shared path.
    let sliding = Duration::from_secs(LOCAL_TOKEN_BUCKET_MAX_WINDOW_SECONDS + 1);
    assert_eq!(
        local_window_algorithm(sliding),
        LocalWindowAlgorithm::SlidingAggregate
    );
    assert_eq!(
        local_window_algorithm(Duration::from_secs(LOCAL_TOKEN_BUCKET_MAX_WINDOW_SECONDS)),
        LocalWindowAlgorithm::TokenBucket
    );

    rate_limiting(json!({
        "limits": [{"scope": "default", "window_seconds": 60, "max_requests": 1000}]
    }))
    .expect("HTTP rate_limiting must construct sliding-window specs");
    graphql(json!({
        "type_rate_limits": {"query": {"max_requests": 1000, "window_seconds": 60}}
    }))
    .expect("graphql must construct shared dynamic HTTP sliding windows");
    grpc_method_router(json!({
        "method_rate_limits": {"/pkg.Svc/M": {"max_requests": 1000, "window_seconds": 60}}
    }))
    .expect("grpc_method_router must construct shared dynamic HTTP sliding windows");
    udp_rate_limiting(json!({"datagrams_per_second": 10, "window_seconds": 60}))
        .expect("udp_rate_limiting still constructs through shared bounds/helpers");

    // Shared limiter path: DynamicHttpRateLimitAlgorithm + SlidingAggregate
    // admits up to the configured boundary and then denies, without depending
    // on per-request timestamp growth.
    let op = DynamicRateLimitOp::new(vec![RateLimitWindowSpec {
        limit: 5,
        duration: Duration::from_secs(60),
    }]);
    let limiter = LocalLimiter::new(DynamicHttpRateLimitAlgorithm::new(), 2);
    let now = Instant::now();
    for i in 0..5 {
        let outcome = limiter.check_at("hot-key".to_string(), &op, now);
        assert!(outcome.allowed, "shared admission {i} must pass");
    }
    let denied = limiter.check_at("hot-key".to_string(), &op, now);
    assert!(!denied.allowed, "shared path must enforce the boundary");
}

#[test]
fn http_windows_charge_only_admissions_under_sustained_overload() {
    for seconds in [1, 6] {
        let algorithm = DynamicHttpRateLimitAlgorithm::new();
        let mut state = algorithm.new_state();
        let op = DynamicRateLimitOp::new(vec![
            RateLimitWindowSpec {
                limit: 5,
                duration: Duration::from_secs(seconds),
            },
            RateLimitWindowSpec {
                limit: 12,
                duration: Duration::from_secs(60),
            },
        ]);
        let start = Instant::now();
        let mut admitted = 0;
        for tick in 0..400 {
            let now = start + Duration::from_millis(tick * 50);
            let outcome = algorithm.check_local(&mut state, &op, now);
            if outcome.allowed {
                admitted += 1;
            }
        }
        assert_eq!(
            admitted, 12,
            "window={seconds}: denials must consume no budget"
        );
    }
}
