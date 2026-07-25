//! Tests for connection pool configuration

use chrono::Utc;
use ferrum_edge::config::PoolConfig;
use ferrum_edge::config::pool_config::{MAX_IDLE_PER_HOST, MIN_IDLE_PER_HOST};
use ferrum_edge::config::types::{
    AuthMode, BackendScheme, DispatchKind, MAX_HTTP2_MAX_FRAME_SIZE, MAX_HTTP2_WINDOW_SIZE,
    MIN_HTTP2_MAX_FRAME_SIZE, MIN_HTTP2_WINDOW_SIZE, Proxy,
};

use crate::unit::env_lock::ENV_LOCK;

const POOL_H2_WINDOW_ENV_VARS: &[&str] = &[
    "FERRUM_POOL_HTTP2_INITIAL_STREAM_WINDOW_SIZE",
    "FERRUM_POOL_HTTP2_INITIAL_CONNECTION_WINDOW_SIZE",
    "FERRUM_POOL_HTTP2_ADAPTIVE_WINDOW",
];

fn with_env_vars<F: FnOnce()>(vars: &[(&str, &str)], f: F) {
    let _guard = ENV_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    for key in POOL_H2_WINDOW_ENV_VARS {
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
    for key in POOL_H2_WINDOW_ENV_VARS {
        // SAFETY: We hold ENV_LOCK preventing concurrent env access.
        unsafe {
            std::env::remove_var(key);
        }
    }
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
        created_at: Utc::now(),
        updated_at: Utc::now(),
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
        let config = PoolConfig::from_env();
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
            let config = PoolConfig::from_env();
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
            let config = PoolConfig::from_env();
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
            let config = PoolConfig::from_env();
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
            let config = PoolConfig::from_env();
            assert_eq!(config.http2_initial_stream_window_size, 16_777_216);
            assert!(!config.http2_adaptive_window);
        },
    );
}

#[test]
fn test_from_env_unparseable_adaptive_window_does_not_suppress_auto_disable() {
    // A typo like "yes" must not count as explicit adaptive intent; fixed windows
    // must still take effect.
    with_env_vars(
        &[
            ("FERRUM_POOL_HTTP2_INITIAL_STREAM_WINDOW_SIZE", "16777216"),
            ("FERRUM_POOL_HTTP2_ADAPTIVE_WINDOW", "yes"),
        ],
        || {
            let config = PoolConfig::from_env();
            assert_eq!(config.http2_initial_stream_window_size, 16_777_216);
            assert!(!config.http2_adaptive_window);
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
