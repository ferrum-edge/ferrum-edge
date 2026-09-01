//! Tests for connection pool configuration

use chrono::Utc;
use ferrum_edge::config::EnvConfig;
use ferrum_edge::config::PoolConfig;
use ferrum_edge::config::conf_file::ConfFile;
use ferrum_edge::config::pool_config::{MAX_IDLE_PER_HOST, MIN_IDLE_PER_HOST};
use ferrum_edge::config::types::{
    AuthMode, BackendScheme, DispatchKind, MAX_HTTP2_MAX_FRAME_SIZE, MAX_HTTP2_WINDOW_SIZE,
    MIN_HTTP2_MAX_FRAME_SIZE, MIN_HTTP2_WINDOW_SIZE, Proxy,
};

use crate::unit::env_lock::ENV_LOCK;

const POOL_ENV_VARS: &[&str] = &[
    "FERRUM_POOL_MAX_IDLE_PER_HOST",
    "FERRUM_POOL_IDLE_TIMEOUT_SECONDS",
    "FERRUM_POOL_ENABLE_HTTP_KEEP_ALIVE",
    "FERRUM_POOL_ENABLE_HTTP2",
    "FERRUM_POOL_HTTP2_CONNECTIONS_PER_HOST",
    "FERRUM_POOL_TCP_KEEPALIVE_SECONDS",
    "FERRUM_POOL_HTTP2_KEEP_ALIVE_INTERVAL_SECONDS",
    "FERRUM_POOL_HTTP2_KEEP_ALIVE_TIMEOUT_SECONDS",
    "FERRUM_POOL_HTTP2_INITIAL_STREAM_WINDOW_SIZE",
    "FERRUM_POOL_HTTP2_INITIAL_CONNECTION_WINDOW_SIZE",
    "FERRUM_POOL_HTTP2_ADAPTIVE_WINDOW",
    "FERRUM_POOL_HTTP2_MAX_FRAME_SIZE",
    "FERRUM_POOL_HTTP2_MAX_CONCURRENT_STREAMS",
];

fn with_env_vars<F: FnOnce()>(vars: &[(&str, &str)], f: F) {
    let _guard = ENV_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    for key in POOL_ENV_VARS {
        // SAFETY: We hold ENV_LOCK preventing concurrent env access.
        unsafe {
            std::env::remove_var(key);
        }
    }
    for (k, v) in vars {
        // SAFETY: We hold ENV_LOCK preventing concurrent env access.
        unsafe {
            std::env::set_var(k, v);
        }
    }
    f();
    for (k, _) in vars {
        // SAFETY: We hold ENV_LOCK preventing concurrent env access.
        unsafe {
            std::env::remove_var(k);
        }
    }
    for key in POOL_ENV_VARS {
        // SAFETY: We hold ENV_LOCK preventing concurrent env access.
        unsafe {
            std::env::remove_var(key);
        }
    }
}

fn parse_pool() -> Result<PoolConfig, String> {
    PoolConfig::from_env_with_conf(&ConfFile::default())
}

fn create_test_proxy() -> Proxy {
    Proxy {
        id: "test".to_string(),
        namespace: ferrum_edge::config::types::default_namespace(),
        name: None,
        hosts: vec![],
        listen_path: Some("/test".to_string()),
        backend_scheme: Some(BackendScheme::Http),
        dispatch_kind: DispatchKind::from(BackendScheme::Http),
        backend_host: "localhost".to_string(),
        backend_port: 3000,
        backend_path: None,
        strip_listen_path: true,
        preserve_host_header: false,
        backend_connect_timeout_ms: 5000,
        backend_read_timeout_ms: 30000,
        backend_write_timeout_ms: 30000,
        backend_tls_client_cert_path: None,
        backend_tls_client_key_path: None,
        backend_tls_verify_server_cert: true,
        backend_tls_server_ca_cert_path: None,
        resolved_tls: Default::default(),
        dispatch_port_overrides: None,
        dispatch_port_override_fallback: None,
        dns_override: None,
        dns_cache_ttl_seconds: None,
        auth_mode: AuthMode::Single,
        plugins: vec![],

        pool_idle_timeout_seconds: None,
        pool_enable_http_keep_alive: None,
        pool_enable_http2: None,
        pool_tcp_keepalive_seconds: None,
        pool_http2_keep_alive_interval_seconds: None,
        pool_http2_keep_alive_timeout_seconds: None,
        pool_http2_initial_stream_window_size: None,
        pool_http2_initial_connection_window_size: None,
        pool_http2_adaptive_window: None,
        pool_http2_max_frame_size: None,
        pool_http2_max_concurrent_streams: None,
        pool_http3_connections_per_backend: None,
        h2_upgrade_policy: None,
        pool_max_requests_per_connection: None,
        pool_http1_max_pending_requests: None,
        upstream_id: None,
        upstream_subset: None,
        api_spec_id: None,
        circuit_breaker: None,
        retry: None,
        response_body_mode: Default::default(),
        listen_port: None,
        frontend_tls: false,
        passthrough: false,
        udp_idle_timeout_seconds: 60,
        tcp_idle_timeout_seconds: Some(300),
        websocket_idle_timeout_seconds: None,
        allowed_methods: None,
        allowed_ws_origins: vec![],
        udp_max_response_amplification_factor: None,
        stream_proxy_protocol: None,
        backend_proxy_protocol: None,
        stream_match: None,
        compiled_stream_match: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
        pending_limit_scope: None,
    }
}

#[test]
fn test_default_config() {
    let config = PoolConfig::default();
    assert_eq!(config.max_idle_per_host, 64);
    assert_eq!(config.idle_timeout_seconds, 90);
    assert_eq!(config.tcp_keepalive_seconds, 60);
    assert_eq!(config.http2_keep_alive_interval_seconds, 30);
    assert_eq!(config.http2_keep_alive_timeout_seconds, 45);
    assert!(config.http2_adaptive_window);
    assert_eq!(config.http2_initial_stream_window_size, 8_388_608);
    assert_eq!(config.http2_initial_connection_window_size, 33_554_432);
    assert_eq!(config.http2_max_frame_size, 1_048_576);
    assert!(config.enable_http_keep_alive);
    assert!(config.enable_http2);
}

#[test]
fn test_from_env_default_keeps_adaptive_window() {
    // No window/adaptive env overrides: shipped adaptive-on contract stays intact.
    with_env_vars(&[], || {
        let config = parse_pool().expect("unset pool settings must parse");
        assert_eq!(config, PoolConfig::default());
        assert!(config.http2_adaptive_window);
        assert_eq!(config.http2_initial_stream_window_size, 8_388_608);
        assert_eq!(config.http2_initial_connection_window_size, 33_554_432);
    });
}

#[test]
fn test_from_env_explicit_stream_window_disables_inherited_adaptive() {
    // Explicit global window without an explicit adaptive setting must not stay
    // inert under the shipped adaptive-on default.
    with_env_vars(
        &[("FERRUM_POOL_HTTP2_INITIAL_STREAM_WINDOW_SIZE", "16777216")],
        || {
            let config = parse_pool().expect("valid stream window");
            assert_eq!(config.http2_initial_stream_window_size, 16_777_216);
            assert!(!config.http2_adaptive_window);
        },
    );
}

#[test]
fn test_from_env_explicit_connection_window_disables_inherited_adaptive() {
    with_env_vars(
        &[(
            "FERRUM_POOL_HTTP2_INITIAL_CONNECTION_WINDOW_SIZE",
            "67108864",
        )],
        || {
            let config = parse_pool().expect("valid connection window");
            assert_eq!(config.http2_initial_connection_window_size, 67_108_864);
            assert!(!config.http2_adaptive_window);
        },
    );
}

#[test]
fn test_from_env_explicit_adaptive_remains_authoritative_with_windows() {
    // Explicit adaptive=true alongside window overrides keeps BDP probing on.
    with_env_vars(
        &[
            ("FERRUM_POOL_HTTP2_INITIAL_STREAM_WINDOW_SIZE", "16777216"),
            (
                "FERRUM_POOL_HTTP2_INITIAL_CONNECTION_WINDOW_SIZE",
                "67108864",
            ),
            ("FERRUM_POOL_HTTP2_ADAPTIVE_WINDOW", "true"),
        ],
        || {
            let config = parse_pool().expect("valid adaptive+windows");
            assert_eq!(config.http2_initial_stream_window_size, 16_777_216);
            assert_eq!(config.http2_initial_connection_window_size, 67_108_864);
            assert!(config.http2_adaptive_window);
        },
    );
}

#[test]
fn test_from_env_explicit_adaptive_false_with_windows() {
    with_env_vars(
        &[
            ("FERRUM_POOL_HTTP2_INITIAL_STREAM_WINDOW_SIZE", "16777216"),
            ("FERRUM_POOL_HTTP2_ADAPTIVE_WINDOW", "false"),
        ],
        || {
            let config = parse_pool().expect("valid adaptive=false");
            assert_eq!(config.http2_initial_stream_window_size, 16_777_216);
            assert!(!config.http2_adaptive_window);
        },
    );
}

#[test]
fn test_from_env_unparseable_adaptive_window_is_an_error() {
    with_env_vars(
        &[
            ("FERRUM_POOL_HTTP2_INITIAL_STREAM_WINDOW_SIZE", "16777216"),
            ("FERRUM_POOL_HTTP2_ADAPTIVE_WINDOW", "yes"),
        ],
        || {
            let err = parse_pool().expect_err("yes is not a boolean");
            assert!(
                err.contains("FERRUM_POOL_HTTP2_ADAPTIVE_WINDOW"),
                "error must name the variable: {err}"
            );
            assert!(err.contains("yes"), "error must name the value: {err}");
        },
    );
}

#[test]
fn test_proxy_overrides() {
    let global = PoolConfig::default();
    let mut proxy = create_test_proxy();

    // Apply overrides
    proxy.pool_enable_http2 = Some(false);
    proxy.pool_tcp_keepalive_seconds = Some(30);
    proxy.pool_http2_keep_alive_interval_seconds = Some(15);
    proxy.pool_http2_keep_alive_timeout_seconds = Some(45);

    let config = global.for_proxy(&proxy);
    assert_eq!(config.max_idle_per_host, 64); // unchanged (global-only)
    assert_eq!(config.idle_timeout_seconds, 90); // unchanged
    assert_eq!(config.tcp_keepalive_seconds, 30); // overridden
    assert_eq!(config.http2_keep_alive_interval_seconds, 15); // overridden
    assert_eq!(config.http2_keep_alive_timeout_seconds, 45); // overridden
    assert!(config.enable_http_keep_alive); // unchanged
    assert!(!config.enable_http2); // overridden
}

#[test]
fn test_no_overrides() {
    let global = PoolConfig::default();
    let proxy = create_test_proxy();

    let config = global.for_proxy(&proxy);
    assert_eq!(config.max_idle_per_host, global.max_idle_per_host);
    assert_eq!(config.idle_timeout_seconds, global.idle_timeout_seconds);
    assert_eq!(config.tcp_keepalive_seconds, global.tcp_keepalive_seconds);
    assert_eq!(
        config.http2_keep_alive_interval_seconds,
        global.http2_keep_alive_interval_seconds
    );
    assert_eq!(
        config.http2_keep_alive_timeout_seconds,
        global.http2_keep_alive_timeout_seconds
    );
    assert_eq!(config.enable_http_keep_alive, global.enable_http_keep_alive);
    assert_eq!(config.enable_http2, global.enable_http2);
    assert_eq!(config.http2_adaptive_window, global.http2_adaptive_window);
}

#[test]
fn test_proxy_explicit_stream_window_disables_inherited_adaptive() {
    // Global adaptive default true + per-proxy window override → adaptive off.
    let global = PoolConfig::default();
    assert!(global.http2_adaptive_window);
    let mut proxy = create_test_proxy();
    proxy.pool_http2_initial_stream_window_size = Some(16_777_216);

    let config = global.for_proxy(&proxy);
    assert_eq!(config.http2_initial_stream_window_size, 16_777_216);
    assert!(!config.http2_adaptive_window);
}

#[test]
fn test_proxy_explicit_connection_window_disables_inherited_adaptive() {
    let global = PoolConfig::default();
    let mut proxy = create_test_proxy();
    proxy.pool_http2_initial_connection_window_size = Some(67_108_864);

    let config = global.for_proxy(&proxy);
    assert_eq!(config.http2_initial_connection_window_size, 67_108_864);
    assert!(!config.http2_adaptive_window);
}

#[test]
fn test_proxy_explicit_adaptive_remains_authoritative_with_windows() {
    let global = PoolConfig::default();
    let mut proxy = create_test_proxy();
    proxy.pool_http2_initial_stream_window_size = Some(16_777_216);
    proxy.pool_http2_initial_connection_window_size = Some(67_108_864);
    proxy.pool_http2_adaptive_window = Some(true);

    let config = global.for_proxy(&proxy);
    assert_eq!(config.http2_initial_stream_window_size, 16_777_216);
    assert_eq!(config.http2_initial_connection_window_size, 67_108_864);
    assert!(config.http2_adaptive_window);
}

#[test]
fn test_proxy_explicit_adaptive_false_overrides_global_default() {
    let global = PoolConfig::default();
    let mut proxy = create_test_proxy();
    proxy.pool_http2_adaptive_window = Some(false);

    let config = global.for_proxy(&proxy);
    assert!(!config.http2_adaptive_window);
}

#[test]
fn test_proxy_window_override_disables_even_when_global_adaptive_was_explicit() {
    // Per-proxy explicit window without per-proxy adaptive must not stay inert
    // under a globally explicit adaptive-on setting.
    let global = PoolConfig {
        http2_adaptive_window: true,
        ..PoolConfig::default()
    };
    let mut proxy = create_test_proxy();
    proxy.pool_http2_initial_stream_window_size = Some(4_194_304);

    let config = global.for_proxy(&proxy);
    assert_eq!(config.http2_initial_stream_window_size, 4_194_304);
    assert!(!config.http2_adaptive_window);
}

#[test]
fn test_proxy_overrides_apply_all_h2_bounds_defensively() {
    let global = PoolConfig::default();
    let mut proxy = create_test_proxy();
    proxy.pool_idle_timeout_seconds = Some(12);
    proxy.pool_enable_http_keep_alive = Some(false);
    proxy.pool_enable_http2 = Some(false);
    proxy.pool_tcp_keepalive_seconds = Some(13);
    proxy.pool_http2_keep_alive_interval_seconds = Some(14);
    proxy.pool_http2_keep_alive_timeout_seconds = Some(15);
    proxy.pool_http2_initial_stream_window_size = Some(MIN_HTTP2_WINDOW_SIZE - 1);
    proxy.pool_http2_initial_connection_window_size = Some(MAX_HTTP2_WINDOW_SIZE + 1);
    proxy.pool_http2_adaptive_window = Some(false);
    proxy.pool_http2_max_frame_size = Some(MIN_HTTP2_MAX_FRAME_SIZE - 1);
    proxy.pool_http2_max_concurrent_streams = Some(0);

    let config = global.for_proxy(&proxy);

    assert_eq!(config.max_idle_per_host, global.max_idle_per_host);
    assert_eq!(config.idle_timeout_seconds, 12);
    assert!(!config.enable_http_keep_alive);
    assert!(!config.enable_http2);
    assert_eq!(config.tcp_keepalive_seconds, 13);
    assert_eq!(config.http2_keep_alive_interval_seconds, 14);
    assert_eq!(config.http2_keep_alive_timeout_seconds, 15);
    assert_eq!(
        config.http2_initial_stream_window_size,
        MIN_HTTP2_WINDOW_SIZE
    );
    assert_eq!(
        config.http2_initial_connection_window_size,
        MAX_HTTP2_WINDOW_SIZE
    );
    assert!(!config.http2_adaptive_window);
    assert_eq!(config.http2_max_frame_size, MIN_HTTP2_MAX_FRAME_SIZE);
    assert_eq!(config.http2_max_concurrent_streams, Some(1));
    assert_eq!(
        global.effective_http2_max_concurrent_streams(&proxy),
        config.http2_max_concurrent_streams,
        "the allocation-free helper must match for_proxy"
    );
}

#[test]
fn test_proxy_overrides_clamp_h2_max_frame_high_boundary() {
    let global = PoolConfig::default();
    let mut proxy = create_test_proxy();
    proxy.pool_http2_max_frame_size = Some(MAX_HTTP2_MAX_FRAME_SIZE + 1);

    let config = global.for_proxy(&proxy);

    assert_eq!(config.http2_max_frame_size, MAX_HTTP2_MAX_FRAME_SIZE);
}

#[test]
fn test_effective_http2_max_concurrent_streams_matches_for_proxy() {
    let mut global = PoolConfig::default();
    let inherit = create_test_proxy();
    assert!(inherit.pool_http2_max_concurrent_streams.is_none());

    let mut explicit_global = create_test_proxy();
    explicit_global.pool_http2_max_concurrent_streams = global.http2_max_concurrent_streams;

    assert_eq!(
        global.effective_http2_max_concurrent_streams(&inherit),
        Some(1000)
    );
    assert_eq!(
        global.effective_http2_max_concurrent_streams(&inherit),
        global.for_proxy(&inherit).http2_max_concurrent_streams
    );
    assert_eq!(
        global.effective_http2_max_concurrent_streams(&inherit),
        global.effective_http2_max_concurrent_streams(&explicit_global)
    );

    global.http2_max_concurrent_streams = None;
    assert_eq!(
        global.effective_http2_max_concurrent_streams(&inherit),
        None
    );
    assert_eq!(
        global.effective_http2_max_concurrent_streams(&inherit),
        global.for_proxy(&inherit).http2_max_concurrent_streams
    );
}

#[test]
fn test_validate_clamps_too_low() {
    let result = PoolConfig::validate_max_idle_per_host(1, "test");
    assert_eq!(result, MIN_IDLE_PER_HOST);
}

#[test]
fn test_validate_clamps_too_high() {
    let result = PoolConfig::validate_max_idle_per_host(5000, "test");
    assert_eq!(result, MAX_IDLE_PER_HOST);
}

#[test]
fn test_validate_accepts_valid_value() {
    let result = PoolConfig::validate_max_idle_per_host(100, "test");
    assert_eq!(result, 100);
}

#[test]
fn test_validate_accepts_boundary_values() {
    assert_eq!(
        PoolConfig::validate_max_idle_per_host(MIN_IDLE_PER_HOST, "test"),
        MIN_IDLE_PER_HOST
    );
    assert_eq!(
        PoolConfig::validate_max_idle_per_host(MAX_IDLE_PER_HOST, "test"),
        MAX_IDLE_PER_HOST
    );
}

#[test]
fn test_append_reqwest_client_behavior_pool_key_adaptive_precedence() {
    let global = PoolConfig::default();
    let mut adaptive = create_test_proxy();
    adaptive.pool_http2_adaptive_window = Some(true);
    adaptive.pool_http2_initial_stream_window_size = Some(65_535);

    let mut buf = String::new();
    global.append_reqwest_client_behavior_pool_key(&adaptive, &mut buf);
    assert_eq!(buf, "|rcfg=i90;ka60;h2=1;h2i30;h2t45;aw1;mf1048576");
    assert!(
        !buf.contains(";sw"),
        "adaptive on must omit fixed windows: {buf}"
    );

    let mut fixed = create_test_proxy();
    fixed.pool_http2_adaptive_window = Some(false);
    fixed.pool_http2_initial_stream_window_size = Some(65_535);
    fixed.pool_http2_initial_connection_window_size = Some(131_072);

    buf.clear();
    global.append_reqwest_client_behavior_pool_key(&fixed, &mut buf);
    assert_eq!(
        buf,
        "|rcfg=i90;ka60;h2=1;h2i30;h2t45;aw0;sw65535;cw131072;mf1048576"
    );
}

#[test]
fn test_append_reqwest_client_behavior_pool_key_keepalive_disabled() {
    let global = PoolConfig::default();
    let mut proxy = create_test_proxy();
    proxy.pool_enable_http_keep_alive = Some(false);
    proxy.pool_tcp_keepalive_seconds = Some(15);
    proxy.pool_enable_http2 = Some(false);

    let mut buf = String::new();
    global.append_reqwest_client_behavior_pool_key(&proxy, &mut buf);
    assert_eq!(buf, "|rcfg=i90;ka0;h2=0");
}

#[test]
fn test_from_env_explicit_defaults_match_today() {
    // Setting every field to the value Default already uses must be a no-op
    // for those fields. http2_connections_per_host is left unset because its
    // default is host-dependent (CPU cores clamped to 2-8).
    with_env_vars(
        &[
            ("FERRUM_POOL_MAX_IDLE_PER_HOST", "64"),
            ("FERRUM_POOL_IDLE_TIMEOUT_SECONDS", "90"),
            ("FERRUM_POOL_ENABLE_HTTP_KEEP_ALIVE", "true"),
            ("FERRUM_POOL_ENABLE_HTTP2", "true"),
            ("FERRUM_POOL_TCP_KEEPALIVE_SECONDS", "60"),
            ("FERRUM_POOL_HTTP2_KEEP_ALIVE_INTERVAL_SECONDS", "30"),
            ("FERRUM_POOL_HTTP2_KEEP_ALIVE_TIMEOUT_SECONDS", "45"),
            ("FERRUM_POOL_HTTP2_INITIAL_STREAM_WINDOW_SIZE", "8388608"),
            (
                "FERRUM_POOL_HTTP2_INITIAL_CONNECTION_WINDOW_SIZE",
                "33554432",
            ),
            ("FERRUM_POOL_HTTP2_ADAPTIVE_WINDOW", "true"),
            ("FERRUM_POOL_HTTP2_MAX_FRAME_SIZE", "1048576"),
            ("FERRUM_POOL_HTTP2_MAX_CONCURRENT_STREAMS", "1000"),
        ],
        || {
            let parsed = parse_pool().expect("documented defaults must parse");
            let default = PoolConfig::default();
            assert_eq!(parsed.max_idle_per_host, default.max_idle_per_host);
            assert_eq!(parsed.idle_timeout_seconds, default.idle_timeout_seconds);
            assert_eq!(
                parsed.enable_http_keep_alive,
                default.enable_http_keep_alive
            );
            assert_eq!(parsed.enable_http2, default.enable_http2);
            assert_eq!(
                parsed.http2_connections_per_host,
                default.http2_connections_per_host
            );
            assert_eq!(parsed.tcp_keepalive_seconds, default.tcp_keepalive_seconds);
            assert_eq!(
                parsed.http2_keep_alive_interval_seconds,
                default.http2_keep_alive_interval_seconds
            );
            assert_eq!(
                parsed.http2_keep_alive_timeout_seconds,
                default.http2_keep_alive_timeout_seconds
            );
            assert_eq!(
                parsed.http2_initial_stream_window_size,
                default.http2_initial_stream_window_size
            );
            assert_eq!(
                parsed.http2_initial_connection_window_size,
                default.http2_initial_connection_window_size
            );
            assert_eq!(parsed.http2_adaptive_window, default.http2_adaptive_window);
            assert_eq!(parsed.http2_max_frame_size, default.http2_max_frame_size);
            assert_eq!(
                parsed.http2_max_concurrent_streams,
                default.http2_max_concurrent_streams
            );
        },
    );
}

#[test]
fn test_from_env_valid_non_default_overlay() {
    with_env_vars(
        &[
            ("FERRUM_POOL_MAX_IDLE_PER_HOST", "8"),
            ("FERRUM_POOL_IDLE_TIMEOUT_SECONDS", "120"),
            ("FERRUM_POOL_ENABLE_HTTP_KEEP_ALIVE", "false"),
            ("FERRUM_POOL_ENABLE_HTTP2", "false"),
            ("FERRUM_POOL_HTTP2_CONNECTIONS_PER_HOST", "2"),
            ("FERRUM_POOL_TCP_KEEPALIVE_SECONDS", "30"),
            ("FERRUM_POOL_HTTP2_KEEP_ALIVE_INTERVAL_SECONDS", "15"),
            ("FERRUM_POOL_HTTP2_KEEP_ALIVE_TIMEOUT_SECONDS", "20"),
            ("FERRUM_POOL_HTTP2_INITIAL_STREAM_WINDOW_SIZE", "65535"),
            ("FERRUM_POOL_HTTP2_INITIAL_CONNECTION_WINDOW_SIZE", "65535"),
            ("FERRUM_POOL_HTTP2_ADAPTIVE_WINDOW", "false"),
            ("FERRUM_POOL_HTTP2_MAX_FRAME_SIZE", "16384"),
            ("FERRUM_POOL_HTTP2_MAX_CONCURRENT_STREAMS", "1"),
        ],
        || {
            let config = parse_pool().expect("valid overlay");
            assert_eq!(config.max_idle_per_host, 8);
            assert_eq!(config.idle_timeout_seconds, 120);
            assert!(!config.enable_http_keep_alive);
            assert!(!config.enable_http2);
            assert_eq!(config.http2_connections_per_host, 2);
            assert_eq!(config.tcp_keepalive_seconds, 30);
            assert_eq!(config.http2_keep_alive_interval_seconds, 15);
            assert_eq!(config.http2_keep_alive_timeout_seconds, 20);
            assert_eq!(config.http2_initial_stream_window_size, 65_535);
            assert_eq!(config.http2_initial_connection_window_size, 65_535);
            assert!(!config.http2_adaptive_window);
            assert_eq!(config.http2_max_frame_size, 16_384);
            assert_eq!(config.http2_max_concurrent_streams, Some(1));
        },
    );
}

#[test]
fn test_from_env_bool_one_and_zero_match_env_config() {
    with_env_vars(
        &[
            ("FERRUM_POOL_ENABLE_HTTP2", "0"),
            ("FERRUM_POOL_ENABLE_HTTP_KEEP_ALIVE", "1"),
        ],
        || {
            let config = parse_pool().expect("0/1 are valid booleans");
            assert!(!config.enable_http2);
            assert!(config.enable_http_keep_alive);
        },
    );
}

#[test]
fn test_from_env_malformed_values_name_the_variable() {
    let cases: &[(&str, &str)] = &[
        ("FERRUM_POOL_MAX_IDLE_PER_HOST", "not-a-number"),
        ("FERRUM_POOL_MAX_IDLE_PER_HOST", ""),
        ("FERRUM_POOL_IDLE_TIMEOUT_SECONDS", "90s"),
        ("FERRUM_POOL_ENABLE_HTTP_KEEP_ALIVE", "flase"),
        ("FERRUM_POOL_ENABLE_HTTP2", "flase"),
        ("FERRUM_POOL_ENABLE_HTTP2", "yes"),
        ("FERRUM_POOL_ENABLE_HTTP2", "2"),
        ("FERRUM_POOL_HTTP2_CONNECTIONS_PER_HOST", "x"),
        ("FERRUM_POOL_TCP_KEEPALIVE_SECONDS", "-1"),
        ("FERRUM_POOL_HTTP2_KEEP_ALIVE_INTERVAL_SECONDS", "1.5"),
        ("FERRUM_POOL_HTTP2_KEEP_ALIVE_TIMEOUT_SECONDS", "abc"),
        ("FERRUM_POOL_HTTP2_INITIAL_STREAM_WINDOW_SIZE", "8MiB"),
        ("FERRUM_POOL_HTTP2_INITIAL_CONNECTION_WINDOW_SIZE", "none"),
        ("FERRUM_POOL_HTTP2_ADAPTIVE_WINDOW", "yes"),
        ("FERRUM_POOL_HTTP2_MAX_FRAME_SIZE", "1MB"),
        ("FERRUM_POOL_HTTP2_MAX_CONCURRENT_STREAMS", "unlimited"),
    ];
    for (key, value) in cases {
        with_env_vars(&[(*key, *value)], || {
            let err = parse_pool().unwrap_err();
            assert!(
                err.contains(key),
                "malformed {key}={value:?} must name the variable: {err}"
            );
            if !value.is_empty() {
                assert!(
                    err.contains(value),
                    "malformed {key}={value:?} must name the value: {err}"
                );
            }
        });
    }
}

#[test]
fn test_from_env_range_boundaries() {
    let accept: &[(&str, &str)] = &[
        ("FERRUM_POOL_MAX_IDLE_PER_HOST", "4"),
        ("FERRUM_POOL_MAX_IDLE_PER_HOST", "1024"),
        ("FERRUM_POOL_HTTP2_CONNECTIONS_PER_HOST", "1"),
        ("FERRUM_POOL_HTTP2_MAX_CONCURRENT_STREAMS", "1"),
        ("FERRUM_POOL_HTTP2_INITIAL_STREAM_WINDOW_SIZE", "65535"),
        ("FERRUM_POOL_HTTP2_INITIAL_CONNECTION_WINDOW_SIZE", "65535"),
        ("FERRUM_POOL_HTTP2_INITIAL_STREAM_WINDOW_SIZE", "134217728"),
        (
            "FERRUM_POOL_HTTP2_INITIAL_CONNECTION_WINDOW_SIZE",
            "134217728",
        ),
        ("FERRUM_POOL_HTTP2_MAX_FRAME_SIZE", "16384"),
        ("FERRUM_POOL_HTTP2_MAX_FRAME_SIZE", "1048576"),
        ("FERRUM_POOL_IDLE_TIMEOUT_SECONDS", "0"),
        ("FERRUM_POOL_TCP_KEEPALIVE_SECONDS", "0"),
        ("FERRUM_POOL_HTTP2_KEEP_ALIVE_INTERVAL_SECONDS", "0"),
        ("FERRUM_POOL_HTTP2_KEEP_ALIVE_TIMEOUT_SECONDS", "0"),
        ("FERRUM_POOL_HTTP2_KEEP_ALIVE_TIMEOUT_SECONDS", "9"),
    ];
    for (key, value) in accept {
        with_env_vars(&[(*key, *value)], || {
            parse_pool()
                .unwrap_or_else(|err| panic!("boundary {key}={value} must be accepted: {err}"));
        });
    }

    let reject: &[(&str, &str, &str)] = &[
        ("FERRUM_POOL_MAX_IDLE_PER_HOST", "3", "3"),
        ("FERRUM_POOL_MAX_IDLE_PER_HOST", "1025", "1025"),
        ("FERRUM_POOL_HTTP2_CONNECTIONS_PER_HOST", "0", "0"),
        ("FERRUM_POOL_HTTP2_MAX_CONCURRENT_STREAMS", "0", "0"),
        (
            "FERRUM_POOL_HTTP2_INITIAL_STREAM_WINDOW_SIZE",
            "65534",
            "65534",
        ),
        (
            "FERRUM_POOL_HTTP2_INITIAL_CONNECTION_WINDOW_SIZE",
            "65534",
            "65534",
        ),
        (
            "FERRUM_POOL_HTTP2_INITIAL_STREAM_WINDOW_SIZE",
            "134217729",
            "134217729",
        ),
        (
            "FERRUM_POOL_HTTP2_INITIAL_CONNECTION_WINDOW_SIZE",
            "134217729",
            "134217729",
        ),
        ("FERRUM_POOL_HTTP2_MAX_FRAME_SIZE", "16383", "16383"),
        ("FERRUM_POOL_HTTP2_MAX_FRAME_SIZE", "1048577", "1048577"),
    ];
    for (key, value, shown) in reject {
        with_env_vars(&[(*key, *value)], || {
            let err = parse_pool().unwrap_err();
            assert!(
                err.contains(key),
                "out-of-range {key}={value} must name the variable: {err}"
            );
            assert!(
                err.contains(shown),
                "out-of-range {key}={value} must name the value: {err}"
            );
            assert!(
                err.contains("must be"),
                "out-of-range {key}={value} must be a range error: {err}"
            );
        });
    }

    with_env_vars(&[("FERRUM_POOL_MAX_IDLE_PER_HOST", "4")], || {
        assert_eq!(
            parse_pool().expect("min idle").max_idle_per_host,
            MIN_IDLE_PER_HOST
        );
    });
    with_env_vars(&[("FERRUM_POOL_MAX_IDLE_PER_HOST", "1024")], || {
        assert_eq!(
            parse_pool().expect("max idle").max_idle_per_host,
            MAX_IDLE_PER_HOST
        );
    });
    with_env_vars(
        &[("FERRUM_POOL_HTTP2_INITIAL_STREAM_WINDOW_SIZE", "65535")],
        || {
            assert_eq!(
                parse_pool()
                    .expect("min stream window")
                    .http2_initial_stream_window_size,
                MIN_HTTP2_WINDOW_SIZE
            );
        },
    );
    with_env_vars(&[("FERRUM_POOL_HTTP2_MAX_FRAME_SIZE", "16384")], || {
        assert_eq!(
            parse_pool().expect("min frame").http2_max_frame_size,
            MIN_HTTP2_MAX_FRAME_SIZE
        );
    });
    with_env_vars(&[("FERRUM_POOL_HTTP2_MAX_FRAME_SIZE", "1048576")], || {
        assert_eq!(
            parse_pool().expect("max frame").http2_max_frame_size,
            MAX_HTTP2_MAX_FRAME_SIZE
        );
    });
}

#[test]
fn test_from_env_conf_file_value_is_honored() {
    let conf = ConfFile::parse("FERRUM_POOL_MAX_IDLE_PER_HOST = 32\n").expect("conf parses");
    with_env_vars(&[], || {
        let config = PoolConfig::from_env_with_conf(&conf).expect("conf pool");
        assert_eq!(config.max_idle_per_host, 32);
    });
}

#[test]
fn test_from_env_env_overrides_conf_file() {
    let conf = ConfFile::parse("FERRUM_POOL_MAX_IDLE_PER_HOST = 32\n").expect("conf parses");
    with_env_vars(&[("FERRUM_POOL_MAX_IDLE_PER_HOST", "16")], || {
        let config = PoolConfig::from_env_with_conf(&conf).expect("env wins");
        assert_eq!(config.max_idle_per_host, 16);
    });
}

#[test]
fn test_env_config_rejects_flase_http2_flag() {
    // Regression for the issue #4428 reproduction: a typo used to silently
    // enable HTTP/2 and `ferrum-edge validate` still exited 0.
    let conf =
        ConfFile::parse("FERRUM_MODE = file\nFERRUM_FILE_CONFIG_PATH = /tmp/ferrum-test.yaml\n")
            .expect("conf parses");
    with_env_vars(&[("FERRUM_POOL_ENABLE_HTTP2", "flase")], || {
        let err =
            EnvConfig::from_env_with_conf(&conf).expect_err("flase must fail settings validation");
        assert!(
            err.contains("FERRUM_POOL_ENABLE_HTTP2"),
            "validate error must name the variable: {err}"
        );
        assert!(
            err.contains("flase"),
            "validate error must name the value: {err}"
        );
    });
}
