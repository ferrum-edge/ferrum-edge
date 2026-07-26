use chrono::Utc;
use ferrum_edge::config::types::{
    ActiveHealthCheck, AuthMode, BackendScheme, BackoffStrategy, CircuitBreakerConfig,
    ConsulConfig, Consumer, DispatchKind, GatewayConfig, HealthCheckConfig, KubernetesConfig,
    LoadBalancerAlgorithm, MAX_BACKEND_HOST_LENGTH, MAX_BACKEND_PATH_LENGTH,
    MAX_BACKEND_TLS_SAN_ALLOW_LIST_ENTRIES, MAX_BACKEND_TLS_SAN_ALLOW_LIST_ENTRY_LENGTH,
    MAX_CREDENTIAL_VALUE_LENGTH, MAX_CREDENTIALS_SIZE, MAX_FILE_PATH_LENGTH, MAX_HOSTS_PER_PROXY,
    MAX_HTTP2_MAX_FRAME_SIZE, MAX_HTTP3_CONNECTIONS_PER_BACKEND, MAX_LISTEN_PATH_LENGTH,
    MAX_NAME_LENGTH, MAX_PLUGIN_CONFIG_SIZE, MAX_POOL_SQL_INTEGER_VALUE, MAX_SD_STRING_LENGTH,
    MAX_TARGETS_PER_UPSTREAM, MAX_TIMEOUT_MS, MAX_USERNAME_LENGTH, MAX_WEBSOCKET_IDLE_TIMEOUT,
    MIN_HTTP2_MAX_FRAME_SIZE, MIN_HTTP2_WINDOW_SIZE, MeshSdConfig, PassiveHealthCheck,
    PluginConfig, PluginScope, Proxy, RetryConfig, SdProvider, ServiceDiscoveryConfig,
    SubsetDefinition, SubsetTrafficPolicy, Upstream, UpstreamTarget,
    validate_basic_auth_hmac_secret,
};
use ferrum_edge::modes::mesh::config::MeshTrafficPolicyTls;
use std::collections::HashMap;

/// Helper to create a minimal valid proxy.
fn make_proxy(id: &str, listen_path: &str) -> Proxy {
    Proxy {
        id: id.into(),
        namespace: ferrum_edge::config::types::default_namespace(),
        name: None,
        hosts: vec![],
        listen_path: Some(listen_path.to_string()),
        backend_scheme: Some(BackendScheme::Http),
        dispatch_kind: DispatchKind::from(BackendScheme::Http),
        backend_host: "localhost".into(),
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
        pool_tcp_keepalive_seconds: None,
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

fn make_consumer(id: &str, username: &str) -> Consumer {
    Consumer {
        id: id.into(),
        namespace: ferrum_edge::config::types::default_namespace(),
        username: username.into(),
        custom_id: None,
        credentials: HashMap::new(),
        acl_groups: Vec::new(),
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

fn make_upstream(id: &str) -> Upstream {
    Upstream {
        id: id.into(),
        namespace: ferrum_edge::config::types::default_namespace(),
        name: None,
        targets: vec![UpstreamTarget {
            host: "localhost".into(),
            port: 3000,
            service_port_policy_key: None,
            weight: 1,
            tags: HashMap::new(),
            locality: None,
            path: None,
        }],
        algorithm: LoadBalancerAlgorithm::RoundRobin,
        hash_on: None,
        hash_on_cookie_config: None,
        health_checks: None,
        service_discovery: None,
        subsets: None,
        port_overrides: HashMap::new(),
        source_locality: None,
        locality_lb_strict: false,
        locality_lb_setting: None,
        backend_tls_client_cert_path: None,
        backend_tls_client_key_path: None,
        backend_tls_verify_server_cert: true,
        backend_tls_server_ca_cert_path: None,
        backend_tls_sni: None,
        backend_tls_san_allow_list: Vec::new(),
        resolved_subset_tls: HashMap::new(),
        dispatch_port_override_fallback: None,
        api_spec_id: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

fn make_plugin_config(id: &str) -> PluginConfig {
    PluginConfig {
        id: id.into(),
        namespace: ferrum_edge::config::types::default_namespace(),
        plugin_name: "cors".into(),
        config: serde_json::json!({"allowed_origins": ["*"]}),
        scope: PluginScope::Global,
        proxy_id: None,
        enabled: true,
        priority_override: None,
        api_spec_id: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

// ---- Proxy field validation tests ----

#[test]
fn test_proxy_valid_fields_passes() {
    let proxy = make_proxy("test", "/api");
    assert!(proxy.validate_fields().is_ok());
}

#[test]
fn test_proxy_stream_proxy_protocol_rejected_on_http_proxy() {
    // Per-proxy admin writes (POST/PUT /proxies) validate via
    // `validate_fields`; the TCP-only PROXY protocol check must run there
    // too, or a bad row persists and wedges the next full-config load.
    let mut proxy = make_proxy("test", "/api");
    proxy.stream_proxy_protocol = Some(true);
    let errs = proxy.validate_fields().unwrap_err();
    assert!(
        errs.iter()
            .any(|e| e.contains("stream_proxy_protocol") && e.contains("tcp")),
        "expected TCP-only rejection, got: {errs:?}"
    );
}

#[test]
fn test_proxy_stream_proxy_protocol_rejected_on_udp_proxy() {
    let mut proxy = make_proxy("test", "/api");
    proxy.listen_path = None;
    proxy.backend_scheme = Some(BackendScheme::Udp);
    proxy.listen_port = Some(5353);
    proxy.stream_proxy_protocol = Some(true);
    let errs = proxy.validate_fields().unwrap_err();
    assert!(
        errs.iter()
            .any(|e| e.contains("stream_proxy_protocol") && e.contains("TCP-borne")),
        "expected TCP-only rejection, got: {errs:?}"
    );
}

#[test]
fn test_proxy_stream_proxy_protocol_accepted_on_tcp_proxy() {
    let mut proxy = make_proxy("test", "/api");
    proxy.listen_path = None;
    proxy.backend_scheme = Some(BackendScheme::Tcp);
    proxy.listen_port = Some(5432);
    proxy.stream_proxy_protocol = Some(true);
    assert!(
        proxy.validate_fields().is_ok(),
        "tcp stream proxy must accept stream_proxy_protocol: {:?}",
        proxy.validate_fields()
    );
}

#[test]
fn test_proxy_name_too_long() {
    let mut proxy = make_proxy("test", "/api");
    proxy.name = Some("a".repeat(MAX_NAME_LENGTH + 1));
    let errs = proxy.validate_fields().unwrap_err();
    assert!(
        errs.iter()
            .any(|e| e.contains("name") && e.contains("exceed"))
    );
}

#[test]
fn test_proxy_backend_host_too_long() {
    let mut proxy = make_proxy("test", "/api");
    proxy.backend_host = "a".repeat(MAX_BACKEND_HOST_LENGTH + 1);
    let errs = proxy.validate_fields().unwrap_err();
    assert!(
        errs.iter()
            .any(|e| e.contains("backend_host") && e.contains("exceed"))
    );
}

#[test]
fn test_proxy_backend_host_contains_scheme() {
    let mut proxy = make_proxy("test", "/api");
    proxy.backend_host = "http://example.com".into();
    let errs = proxy.validate_fields().unwrap_err();
    assert!(errs.iter().any(|e| e.contains("scheme")));
}

#[test]
fn test_proxy_backend_path_too_long() {
    let mut proxy = make_proxy("test", "/api");
    proxy.backend_path = Some("a".repeat(MAX_BACKEND_PATH_LENGTH + 1));
    let errs = proxy.validate_fields().unwrap_err();
    assert!(
        errs.iter()
            .any(|e| e.contains("backend_path") && e.contains("exceed"))
    );
}

#[test]
fn test_proxy_listen_path_too_long() {
    let mut proxy = make_proxy("test", "/api");
    proxy.listen_path = Some(format!("/{}", "a".repeat(MAX_LISTEN_PATH_LENGTH)));
    let errs = proxy.validate_fields().unwrap_err();
    assert!(
        errs.iter()
            .any(|e| e.contains("listen_path") && e.contains("exceed"))
    );
}

#[test]
fn test_proxy_listen_path_control_chars() {
    let mut proxy = make_proxy("test", "/api");
    proxy.listen_path = Some("/api\x00test".into());
    let errs = proxy.validate_fields().unwrap_err();
    assert!(
        errs.iter()
            .any(|e| e.contains("listen_path") && e.contains("control"))
    );
}

#[test]
fn test_proxy_http_listen_path_must_start_with_slash_or_regex_prefix() {
    let proxy = make_proxy("test", "api");
    let errs = proxy.validate_fields().unwrap_err();
    assert!(
        errs.iter()
            .any(|e| e.contains("listen_path must start with '/', '~' (regex), or '=/' (exact)"))
    );
}

#[test]
fn test_proxy_listen_path_rejects_non_canonical_policy_paths() {
    const MARKER: &str = "canonical policy path";

    // Prefix form, uppercase / lowercase single-encoded separator.
    let mut proxy = make_proxy("test", "/api");
    for path in ["/api%2Fadmin", "/api%2fadmin"] {
        proxy.listen_path = Some(path.into());
        let errs = proxy.validate_fields().unwrap_err();
        assert!(
            errs.iter().any(|e| e.contains(MARKER)),
            "expected encoded-separator rejection for {path:?}, got {errs:?}"
        );
    }

    // Prefix form, uppercase / lowercase double-encoded.
    for path in ["/api%252Fadmin", "/api%252fadmin"] {
        proxy.listen_path = Some(path.into());
        let errs = proxy.validate_fields().unwrap_err();
        assert!(
            errs.iter().any(|e| e.contains(MARKER)),
            "expected double-encoding rejection for {path:?}, got {errs:?}"
        );
    }

    // Escapes of characters that are legal literally in a path decode during
    // canonicalization, so `/%61dmin` is a different (unreachable) spelling of
    // `/admin` rather than a stricter one. Admission must refuse it.
    proxy.listen_path = Some("/%61dmin".into());
    let errs = proxy.validate_fields().unwrap_err();
    assert!(
        errs.iter().any(|e| e.contains(MARKER)),
        "expected ordinary-single-encoding rejection, got {errs:?}"
    );

    // Encoded backslash, encoded dot segment, encoded NUL, and a truncated
    // escape are all refused for the same reason.
    for path in ["/api%5Cadmin", "/api/%2e%2e/admin", "/api%00", "/api%2"] {
        proxy.listen_path = Some(path.into());
        let errs = proxy.validate_fields().unwrap_err();
        assert!(
            errs.iter().any(|e| e.contains(MARKER)),
            "expected non-canonical rejection for {path:?}, got {errs:?}"
        );
    }

    // Exact (`=/…`) form is also rejected.
    proxy.listen_path = Some("=/api%2Fadmin".into());
    let errs = proxy.validate_fields().unwrap_err();
    assert!(
        errs.iter().any(|e| e.contains(MARKER)),
        "expected exact-form rejection, got {errs:?}"
    );

    // Regex (`~…`) form is also rejected — request paths are canonicalized
    // before regex evaluation, so a pattern with `%2F` could never match.
    proxy.listen_path = Some("~/api%2F.*".into());
    let errs = proxy.validate_fields().unwrap_err();
    assert!(
        errs.iter().any(|e| e.contains(MARKER)),
        "expected regex-form rejection, got {errs:?}"
    );

    // An escape of a byte outside the `pchar` decode set (`%20` for space,
    // `%7B` for a brace, `%C3%A9` for `é`) can neither be retained nor decoded
    // into the forwarded target, so the runtime refuses those request paths
    // outright and such a listen_path is dead config.
    for path in ["/api%20name", "/api/%7Bid%7D", "/caf%C3%A9"] {
        proxy.listen_path = Some(path.into());
        let errs = proxy.validate_fields().unwrap_err();
        assert!(
            errs.iter().any(|e| e.contains(MARKER)),
            "expected unrepresentable-escape rejection for {path:?}, got {errs:?}"
        );
    }

    // A literal dot segment or backslash is refused too: every RFC 3986 /
    // WHATWG normalizer removes dot segments and the `url` parser treats `\`
    // as a separator, so neither can appear in a canonical request path and
    // neither is reachable as a literal listen_path.
    for path in [
        "/api/../admin",
        "/api/./admin",
        "/api/..",
        "/api\\admin",
        "=/api/../admin",
    ] {
        proxy.listen_path = Some(path.into());
        let errs = proxy.validate_fields().unwrap_err();
        assert!(
            errs.iter().any(|e| e.contains(MARKER)),
            "expected literal-structure rejection for {path:?}, got {errs:?}"
        );
    }

    // Negative: a `~regex` listen_path is a pattern, not a literal path. `\`
    // and `.` are regex syntax there, and the canonical path it is matched
    // against already cannot contain a dot segment or a backslash, so holding
    // the pattern to the literal rules would kill a working route without
    // closing anything.
    for path in [r"~^/v1\.0/.*", "~^/api/v[0-9]+", "~(?i:/Api.*)"] {
        proxy.listen_path = Some(path.into());
        if let Err(errs) = proxy.validate_fields() {
            assert!(
                !errs.iter().any(|e| e.contains(MARKER)),
                "did not expect a canonical-path rejection for pattern {path:?}, got {errs:?}"
            );
        }
    }

    // A `.` inside a segment is an ordinary path character and stays valid.
    proxy.listen_path = Some("/v1.0/reports".into());
    if let Err(errs) = proxy.validate_fields() {
        assert!(
            !errs.iter().any(|e| e.contains(MARKER)),
            "did not expect a canonical-path rejection for `/v1.0/reports`, got {errs:?}"
        );
    }
}

#[test]
fn test_stream_proxy_requires_listen_path_none() {
    // Stream proxies route on listen_port and must have listen_path == None.
    // A populated listen_path is now a hard error (breaking change).
    let mut proxy = make_proxy("test", "/ignored");
    proxy.backend_scheme = Some(BackendScheme::Tcp);
    proxy.dispatch_kind = DispatchKind::from(BackendScheme::Tcp);
    proxy.listen_port = Some(5432);
    let errs = proxy.validate_fields().unwrap_err();
    assert!(
        errs.iter()
            .any(|e| e.contains("stream") && e.contains("listen_path")),
        "Expected error about stream proxy not setting listen_path, got: {:?}",
        errs
    );

    // With listen_path = None it validates.
    proxy.listen_path = None;
    assert!(
        proxy.validate_fields().is_ok(),
        "Stream proxy with listen_path=None and listen_port set should be valid: {:?}",
        proxy.validate_fields()
    );
}

#[test]
fn test_stream_proxy_rejects_empty_string_listen_path() {
    // Empty-string listen_path is invalid input — stream proxies must use
    // None, not "". This catches mis-written fixtures loudly.
    let mut proxy = make_proxy("test", "");
    proxy.backend_scheme = Some(BackendScheme::Tcp);
    proxy.dispatch_kind = DispatchKind::from(BackendScheme::Tcp);
    proxy.listen_port = Some(5432);
    let result = proxy.validate_fields();
    assert!(
        result.is_err(),
        "Stream proxy with listen_path=Some(\"\") should be rejected"
    );
}

#[test]
fn test_proxy_backend_host_control_chars() {
    let mut proxy = make_proxy("test", "/api");
    proxy.backend_host = "localhost\x00evil".into();
    let errs = proxy.validate_fields().unwrap_err();
    assert!(
        errs.iter()
            .any(|e| e.contains("backend_host") && e.contains("control"))
    );
}

#[test]
fn test_proxy_too_many_hosts() {
    let mut proxy = make_proxy("test", "/api");
    proxy.hosts = (0..MAX_HOSTS_PER_PROXY + 1)
        .map(|i| format!("host{}.example.com", i))
        .collect();
    let errs = proxy.validate_fields().unwrap_err();
    assert!(errs.iter().any(|e| e.contains("hosts")));
}

#[test]
fn test_proxy_overlong_unicode_host_reports_error_without_panicking() {
    let mut proxy = make_proxy("test", "/api");
    proxy.hosts = vec!["€".repeat(90)];

    let errs = proxy.validate_fields().unwrap_err();
    assert!(
        errs.iter()
            .any(|e| e.contains("host entry") && e.contains("must not exceed"))
    );
}

#[test]
fn test_proxy_timeout_zero_rejected() {
    let mut proxy = make_proxy("test", "/api");
    proxy.backend_connect_timeout_ms = 0;
    let errs = proxy.validate_fields().unwrap_err();
    assert!(
        errs.iter()
            .any(|e| e.contains("backend_connect_timeout_ms"))
    );
}

#[test]
fn test_proxy_timeout_too_large_rejected() {
    let mut proxy = make_proxy("test", "/api");
    proxy.backend_read_timeout_ms = MAX_TIMEOUT_MS + 1;
    let errs = proxy.validate_fields().unwrap_err();
    assert!(errs.iter().any(|e| e.contains("backend_read_timeout_ms")));
}

#[test]
fn test_proxy_backend_rw_timeout_zero_allowed() {
    let mut proxy = make_proxy("test", "/api");
    proxy.backend_read_timeout_ms = 0;
    proxy.backend_write_timeout_ms = 0;
    assert!(proxy.validate_fields().is_ok());
}

#[test]
fn test_proxy_pool_timeout_validated() {
    let mut proxy = make_proxy("test", "/api");
    proxy.pool_idle_timeout_seconds = Some(0);
    let errs = proxy.validate_fields().unwrap_err();
    assert!(errs.iter().any(|e| e.contains("pool_idle_timeout_seconds")));
}

#[test]
fn test_proxy_circuit_breaker_validated() {
    let mut proxy = make_proxy("test", "/api");
    proxy.circuit_breaker = Some(CircuitBreakerConfig {
        failure_threshold: 0, // Invalid: must be >= 1
        success_threshold: 3,
        timeout_seconds: 30,
        failure_status_codes: vec![500],
        half_open_max_requests: 1,
        trip_on_connection_errors: true,
    });
    let errs = proxy.validate_fields().unwrap_err();
    assert!(
        errs.iter()
            .any(|e| e.contains("circuit_breaker.failure_threshold"))
    );
}

#[test]
fn test_proxy_retry_validated() {
    let mut proxy = make_proxy("test", "/api");
    proxy.retry = Some(RetryConfig {
        max_retries: 200, // Invalid: exceeds MAX_RETRIES (100)
        retryable_status_codes: vec![502],
        retryable_methods: vec!["GET".into()],
        backoff: BackoffStrategy::Fixed { delay_ms: 100 },
        retry_on_connect_failure: true,
    });
    let errs = proxy.validate_fields().unwrap_err();
    assert!(errs.iter().any(|e| e.contains("retry.max_retries")));
}

#[test]
fn test_proxy_retry_backoff_base_exceeds_max() {
    let mut proxy = make_proxy("test", "/api");
    proxy.retry = Some(RetryConfig {
        max_retries: 3,
        retryable_status_codes: vec![502],
        retryable_methods: vec!["GET".into()],
        backoff: BackoffStrategy::Exponential {
            base_ms: 5000,
            max_ms: 1000, // Invalid: base > max
        },
        retry_on_connect_failure: true,
    });
    let errs = proxy.validate_fields().unwrap_err();
    assert!(
        errs.iter()
            .any(|e| e.contains("base_ms") && e.contains("must not exceed"))
    );
}

#[test]
fn test_proxy_circuit_breaker_invalid_status_codes() {
    let mut proxy = make_proxy("test", "/api");
    proxy.circuit_breaker = Some(CircuitBreakerConfig {
        failure_threshold: 5,
        success_threshold: 3,
        timeout_seconds: 30,
        failure_status_codes: vec![999], // Invalid HTTP status code
        half_open_max_requests: 1,
        trip_on_connection_errors: true,
    });
    let errs = proxy.validate_fields().unwrap_err();
    assert!(
        errs.iter()
            .any(|e| e.contains("failure_status_codes") && e.contains("999"))
    );
}

// ---- Consumer field validation tests ----

#[test]
fn test_consumer_valid_fields_passes() {
    let consumer = make_consumer("test", "alice");
    assert!(consumer.validate_fields().is_ok());
}

#[test]
fn test_consumer_username_too_long() {
    let consumer = make_consumer("test", &"a".repeat(MAX_USERNAME_LENGTH + 1));
    let errs = consumer.validate_fields().unwrap_err();
    assert!(errs.iter().any(|e| e.contains("username")));
}

#[test]
fn test_consumer_username_control_chars() {
    let consumer = make_consumer("test", "alice\x00evil");
    let errs = consumer.validate_fields().unwrap_err();
    assert!(
        errs.iter()
            .any(|e| e.contains("username") && e.contains("control"))
    );
}

#[test]
fn test_consumer_custom_id_too_long() {
    let mut consumer = make_consumer("test", "alice");
    consumer.custom_id = Some("a".repeat(256));
    let errs = consumer.validate_fields().unwrap_err();
    assert!(errs.iter().any(|e| e.contains("custom_id")));
}

#[test]
fn test_consumer_username_empty_rejected() {
    let consumer = make_consumer("test", "   ");
    let errs = consumer.validate_fields().unwrap_err();
    assert!(
        errs.iter()
            .any(|e| e.contains("username must not be empty"))
    );
}

#[test]
fn test_consumer_credential_value_too_long() {
    let mut consumer = make_consumer("test", "alice");
    consumer.credentials.insert(
        "keyauth".into(),
        serde_json::json!([{"key": "a".repeat(MAX_CREDENTIAL_VALUE_LENGTH + 1)}]),
    );
    let errs = consumer.validate_fields().unwrap_err();
    assert!(
        errs.iter()
            .any(|e| e.contains("credentials.keyauth[0].key") && e.contains("exceed"))
    );
}

#[test]
fn test_consumer_credential_control_chars() {
    let mut consumer = make_consumer("test", "alice");
    consumer
        .credentials
        .insert("keyauth".into(), serde_json::json!([{"key": "abc\x00def"}]));
    let errs = consumer.validate_fields().unwrap_err();
    assert!(
        errs.iter()
            .any(|e| e.contains("credentials.keyauth[0].key") && e.contains("control"))
    );
}

#[test]
fn test_consumer_basicauth_accepts_one_plaintext_or_canonical_hash() {
    for credential in [
        serde_json::json!({"password": "admin-write-password"}),
        serde_json::json!({"password_hash": format!("hmac_sha256:{}", "a".repeat(64))}),
    ] {
        let mut consumer = make_consumer("test", "alice");
        consumer
            .credentials
            .insert("basicauth".into(), serde_json::json!([credential]));
        assert!(consumer.validate_fields().is_ok());
    }
}

#[test]
fn test_consumer_basicauth_rejects_unusable_entries() {
    let invalid_credentials = [
        serde_json::json!({}),
        serde_json::json!({"password": "secret", "password_hash": format!("hmac_sha256:{}", "a".repeat(64))}),
        serde_json::json!({"password": "secret", "unexpected": true}),
        serde_json::json!({"password": ""}),
        serde_json::json!({"password": "embedded\0null"}),
        serde_json::json!({"password": 42}),
        serde_json::json!({"password_hash": "hmac_sha256:not-hex"}),
        serde_json::json!({"password_hash": format!("hmac_sha256:{}", "A".repeat(64))}),
        serde_json::json!({"password_hash": 42}),
    ];

    for credential in invalid_credentials {
        let mut consumer = make_consumer("test", "alice");
        consumer
            .credentials
            .insert("basicauth".into(), serde_json::json!([credential]));
        let errors = consumer.validate_fields().unwrap_err();
        assert!(
            errors
                .iter()
                .any(|error| error.contains("credentials.basicauth[0]")),
            "unexpected errors: {errors:?}"
        );
    }
}

#[test]
fn test_basic_auth_hmac_secret_requires_32_bytes() {
    assert!(validate_basic_auth_hmac_secret(&"x".repeat(31)).is_err());
    assert!(validate_basic_auth_hmac_secret(&"x".repeat(32)).is_ok());
}

#[test]
fn test_consumer_keyauth_requires_nonempty_string_key() {
    for credential in [
        serde_json::json!({}),
        serde_json::json!({"kee": "misspelled"}),
        serde_json::json!({"key": 42}),
        serde_json::json!({"key": ""}),
        serde_json::json!({"key": "   "}),
    ] {
        let mut consumer = make_consumer("test", "alice");
        consumer
            .credentials
            .insert("keyauth".into(), serde_json::json!([credential]));

        let errors = consumer
            .validate_fields()
            .expect_err("malformed keyauth credentials must fail closed");
        assert!(
            errors
                .iter()
                .any(|error| error.contains("credentials.keyauth[0].key")),
            "unexpected errors: {errors:?}"
        );
    }
}

#[test]
fn test_consumer_keyauth_accepts_valid_rotation_array() {
    let mut consumer = make_consumer("test", "alice");
    consumer.credentials.insert(
        "keyauth".into(),
        serde_json::json!([{"key": "current-key"}, {"key": "next-key"}]),
    );

    assert!(consumer.validate_fields().is_ok());
}

#[test]
fn test_consumer_credentials_total_size_limit() {
    let mut consumer = make_consumer("test", "alice");
    // Create a single credential value that exceeds 64KB
    let big_value = "a".repeat(MAX_CREDENTIALS_SIZE + 1);
    consumer
        .credentials
        .insert("keyauth".into(), serde_json::json!([{"key": big_value}]));
    let errs = consumer.validate_fields().unwrap_err();
    assert!(
        errs.iter()
            .any(|e| e.contains("credentials JSON") && e.contains("exceed"))
    );
}

#[test]
fn test_consumer_acl_groups_valid() {
    let mut consumer = make_consumer("test", "alice");
    consumer.acl_groups = vec!["engineering".into(), "platform".into()];
    assert!(consumer.validate_fields().is_ok());
}

#[test]
fn test_consumer_acl_groups_empty_entry_rejected() {
    let mut consumer = make_consumer("test", "alice");
    consumer.acl_groups = vec!["engineering".into(), "".into()];
    let errs = consumer.validate_fields().unwrap_err();
    assert!(errs.iter().any(|e| e.contains("acl_groups[1]")));
}

#[test]
fn test_consumer_acl_groups_too_many_rejected() {
    let mut consumer = make_consumer("test", "alice");
    consumer.acl_groups = (0..501).map(|i| format!("group-{}", i)).collect();
    let errs = consumer.validate_fields().unwrap_err();
    assert!(
        errs.iter()
            .any(|e| e.contains("acl_groups") && e.contains("500"))
    );
}

#[test]
fn test_consumer_acl_groups_entry_too_long_rejected() {
    let mut consumer = make_consumer("test", "alice");
    consumer.acl_groups = vec!["a".repeat(256)];
    let errs = consumer.validate_fields().unwrap_err();
    assert!(
        errs.iter()
            .any(|e| e.contains("acl_groups entry") && e.contains("255"))
    );
}

#[test]
fn test_consumer_acl_groups_control_chars_rejected() {
    let mut consumer = make_consumer("test", "alice");
    consumer.acl_groups = vec!["group\x00evil".into()];
    let errs = consumer.validate_fields().unwrap_err();
    assert!(
        errs.iter()
            .any(|e| e.contains("acl_groups entry") && e.contains("control"))
    );
}

// ---- Upstream field validation tests ----

#[test]
fn test_upstream_valid_fields_passes() {
    let upstream = make_upstream("test");
    assert!(upstream.validate_fields().is_ok());
}

#[test]
fn test_upstream_backend_tls_sni_validated() {
    let mut upstream = make_upstream("test");
    upstream.backend_tls_sni = Some("http://reviews.mesh.internal".into());
    let errs = upstream.validate_fields().unwrap_err();
    assert!(
        errs.iter()
            .any(|e| e.contains("backend_tls_sni") && e.contains("scheme"))
    );

    let mut upstream = make_upstream("test");
    upstream.backend_tls_sni = Some("*.mesh.internal".into());
    let errs = upstream.validate_fields().unwrap_err();
    assert!(
        errs.iter()
            .any(|e| e.contains("backend_tls_sni") && e.contains("exact hostname"))
    );
}

#[test]
fn test_upstream_backend_tls_sni_rejects_ip_literals() {
    // RFC 6066 §3: SNI host_name must not be an IP address.
    let mut upstream = make_upstream("test");
    upstream.backend_tls_sni = Some("10.0.0.8".into());
    let errs = upstream.validate_fields().unwrap_err();
    assert!(
        errs.iter()
            .any(|e| e.contains("backend_tls_sni") && e.contains("IP address")),
        "got: {errs:?}"
    );

    upstream.backend_tls_sni = Some("2001:db8::1".into());
    let errs = upstream.validate_fields().unwrap_err();
    assert!(
        errs.iter()
            .any(|e| e.contains("backend_tls_sni") && e.contains("IP address")),
        "got: {errs:?}"
    );
}

#[test]
fn test_upstream_backend_tls_san_allow_list_validated() {
    let mut upstream = make_upstream("test");
    upstream.backend_tls_san_allow_list = vec![
        "reviews.mesh.internal".into(),
        "spiffe://cluster.local/ns/default/sa/reviews".into(),
        "10.0.0.8".into(),
    ];
    assert!(upstream.validate_fields().is_ok());

    upstream.backend_tls_san_allow_list.push(String::new());
    let errs = upstream.validate_fields().unwrap_err();
    assert!(
        errs.iter()
            .any(|e| e.contains("backend_tls_san_allow_list[3]") && e.contains("empty"))
    );
}

#[test]
fn test_upstream_backend_tls_san_allow_list_limit() {
    let mut upstream = make_upstream("test");
    upstream.backend_tls_san_allow_list = (0..=MAX_BACKEND_TLS_SAN_ALLOW_LIST_ENTRIES)
        .map(|i| format!("san-{i}.mesh.internal"))
        .collect();
    let errs = upstream.validate_fields().unwrap_err();
    assert!(
        errs.iter()
            .any(|e| e.contains("backend_tls_san_allow_list") && e.contains("more than"))
    );
}

#[test]
fn test_upstream_backend_tls_san_allow_list_entry_length_limit() {
    let mut upstream = make_upstream("test");
    upstream.backend_tls_san_allow_list = vec![format!(
        "{}.mesh.internal",
        "a".repeat(MAX_BACKEND_TLS_SAN_ALLOW_LIST_ENTRY_LENGTH)
    )];
    let errs = upstream.validate_fields().unwrap_err();
    assert!(
        errs.iter()
            .any(|e| e.contains("backend_tls_san_allow_list[0]") && e.contains("must not exceed"))
    );
}

#[test]
fn test_upstream_backend_tls_san_allow_list_rejects_spiffe_without_path() {
    let mut upstream = make_upstream("test");
    upstream.backend_tls_san_allow_list = vec!["spiffe://cluster.local".into()];
    let errs = upstream.validate_fields().unwrap_err();
    assert!(
        errs.iter()
            .any(|e| e.contains("backend_tls_san_allow_list[0]") && e.contains("non-empty path"))
    );

    upstream.backend_tls_san_allow_list = vec!["spiffe://cluster.local/".into()];
    let errs = upstream.validate_fields().unwrap_err();
    assert!(
        errs.iter()
            .any(|e| e.contains("backend_tls_san_allow_list[0]") && e.contains("non-empty path"))
    );

    upstream.backend_tls_san_allow_list =
        vec!["spiffe://cluster.local/ns/default/sa/reviews".into()];
    assert!(upstream.validate_fields().is_ok());
}

#[test]
fn test_upstream_requires_targets_or_service_discovery() {
    let mut upstream = make_upstream("test");
    upstream.targets.clear();
    upstream.service_discovery = None;
    let errs = upstream.validate_fields().unwrap_err();
    assert!(
        errs.iter()
            .any(|e| e.contains("must have at least one target or service_discovery"))
    );
}

#[test]
fn test_upstream_name_too_long() {
    let mut upstream = make_upstream("test");
    upstream.name = Some("a".repeat(MAX_NAME_LENGTH + 1));
    let errs = upstream.validate_fields().unwrap_err();
    assert!(
        errs.iter()
            .any(|e| e.contains("name") && e.contains("exceed"))
    );
}

#[test]
fn test_upstream_too_many_targets() {
    let mut upstream = make_upstream("test");
    upstream.targets = (0..MAX_TARGETS_PER_UPSTREAM + 1)
        .map(|i| UpstreamTarget {
            host: format!("host{}.example.com", i),
            port: 3000,
            service_port_policy_key: None,
            weight: 1,
            tags: HashMap::new(),
            locality: None,
            path: None,
        })
        .collect();
    let errs = upstream.validate_fields().unwrap_err();
    assert!(errs.iter().any(|e| e.contains("targets")));
}

#[test]
fn test_upstream_target_empty_host() {
    let mut upstream = make_upstream("test");
    upstream.targets[0].host = "".into();
    let errs = upstream.validate_fields().unwrap_err();
    assert!(
        errs.iter()
            .any(|e| e.contains("targets[0].host") && e.contains("empty"))
    );
}

#[test]
fn test_upstream_target_host_too_long() {
    let mut upstream = make_upstream("test");
    upstream.targets[0].host = "a".repeat(MAX_BACKEND_HOST_LENGTH + 1);
    let errs = upstream.validate_fields().unwrap_err();
    assert!(
        errs.iter()
            .any(|e| e.contains("targets[0].host") && e.contains("exceed"))
    );
}

#[test]
fn test_upstream_target_port_zero() {
    let mut upstream = make_upstream("test");
    upstream.targets[0].port = 0;
    let errs = upstream.validate_fields().unwrap_err();
    assert!(errs.iter().any(|e| e.contains("targets[0].port")));
}

#[test]
fn test_upstream_target_weight_zero() {
    let mut upstream = make_upstream("test");
    upstream.targets[0].weight = 0;
    let errs = upstream.validate_fields().unwrap_err();
    assert!(errs.iter().any(|e| e.contains("targets[0].weight")));
}

#[test]
fn test_upstream_target_weight_too_large() {
    let mut upstream = make_upstream("test");
    upstream.targets[0].weight = 70000;
    let errs = upstream.validate_fields().unwrap_err();
    assert!(errs.iter().any(|e| e.contains("targets[0].weight")));
}

#[test]
fn test_upstream_target_path_too_long() {
    let mut upstream = make_upstream("test");
    upstream.targets[0].path = Some("a".repeat(MAX_BACKEND_PATH_LENGTH + 1));
    let errs = upstream.validate_fields().unwrap_err();
    assert!(
        errs.iter()
            .any(|e| e.contains("targets[0].path") && e.contains("exceed"))
    );
}

#[test]
fn test_upstream_target_path_control_chars() {
    let mut upstream = make_upstream("test");
    upstream.targets[0].path = Some("/api\x00evil".into());
    let errs = upstream.validate_fields().unwrap_err();
    assert!(
        errs.iter()
            .any(|e| e.contains("targets[0].path") && e.contains("control"))
    );
}

#[test]
fn test_upstream_target_path_valid() {
    let mut upstream = make_upstream("test");
    upstream.targets[0].path = Some("/api/v1/service".into());
    assert!(upstream.validate_fields().is_ok());
}

#[test]
fn test_upstream_target_locality_valid_forms_accepted() {
    for value in [
        "us-west",
        "us-west/us-west-1",
        "us-west/us-west-1/a",
        " us-west / us-west-1 / a ",
    ] {
        let mut upstream = make_upstream("test");
        upstream.targets[0].locality = Some(value.into());
        assert!(
            upstream.validate_fields().is_ok(),
            "valid locality '{value}' should pass validation"
        );
    }
}

#[test]
fn test_upstream_target_locality_rejects_malformed() {
    for bad in ["", "   ", "/zone/a", "/", "  /  "] {
        let mut upstream = make_upstream("test");
        upstream.targets[0].locality = Some(bad.into());
        let errs = upstream
            .validate_fields()
            .expect_err("malformed locality must be rejected");
        assert!(
            errs.iter().any(|e| e.contains("targets[0].locality")),
            "expected locality rejection for '{bad}', got: {errs:?}"
        );
    }
}

#[test]
fn test_upstream_target_locality_too_long() {
    use ferrum_edge::config::types::MAX_LOCALITY_LENGTH;

    let mut upstream = make_upstream("test");
    upstream.targets[0].locality = Some("a".repeat(MAX_LOCALITY_LENGTH + 1));
    let errs = upstream.validate_fields().unwrap_err();
    assert!(
        errs.iter()
            .any(|e| e.contains("targets[0].locality") && e.contains("exceed"))
    );
}

#[test]
fn test_upstream_source_locality_rejected_by_admin_api() {
    let mut upstream = make_upstream("test");
    upstream.source_locality = Some("us-west/us-west-1/a".into());
    // The projected-field rejection is scoped to the admin write path
    // (`validate_operator_provided_fields`), NOT `validate_fields` (which also runs on
    // the runtime mesh-apply path, where the field is legitimately projected).
    let errs = upstream
        .validate_operator_provided_fields()
        .expect_err("source_locality must be rejected on the admin write path");
    assert!(
        errs.iter().any(|e| e.contains("source_locality")
            && e.contains("cannot be set directly via the admin API")),
        "expected source_locality admin-API rejection, got: {errs:?}"
    );
    // Runtime apply must NOT reject (no false "misconfigured" warning).
    assert!(
        upstream.validate_fields().is_ok(),
        "validate_fields must not reject a mesh-projected source_locality on the runtime path"
    );
}

#[test]
fn test_upstream_locality_lb_strict_rejected_by_admin_api() {
    let mut upstream = make_upstream("test");
    upstream.locality_lb_strict = true;
    let errs = upstream
        .validate_operator_provided_fields()
        .expect_err("locality_lb_strict must be rejected on the admin write path");
    assert!(
        errs.iter().any(|e| e.contains("locality_lb_strict")
            && e.contains("cannot be set directly via the admin API")),
        "expected locality_lb_strict admin-API rejection, got: {errs:?}"
    );
    // Runtime apply (mesh slice prep SETS this) must NOT reject.
    assert!(
        upstream.validate_fields().is_ok(),
        "validate_fields must not reject a mesh-projected locality_lb_strict on the runtime path"
    );
}

#[test]
fn test_upstream_locality_lb_setting_rejected_by_admin_api() {
    use std::collections::BTreeMap;

    use ferrum_edge::config::types::{
        LocalityDistribute, LocalityFailover, UpstreamLocalityLbSetting,
    };

    let mut upstream = make_upstream("test");
    upstream.locality_lb_setting = Some(UpstreamLocalityLbSetting {
        enabled: true,
        distribute: vec![LocalityDistribute {
            from: "us-west/us-west-1/a".to_string(),
            to: BTreeMap::from([("us-west".to_string(), 100u32)]),
        }],
        failover: vec![LocalityFailover {
            from: "us-west".to_string(),
            to: "us-east".to_string(),
        }],
    });
    let errs = upstream
        .validate_operator_provided_fields()
        .expect_err("locality_lb_setting must be rejected on the admin write path");
    assert!(
        errs.iter().any(|e| e.contains("locality_lb_setting")
            && e.contains("cannot be set directly via the admin API")),
        "expected locality_lb_setting admin-API rejection, got: {errs:?}"
    );
    // Runtime apply must NOT reject.
    assert!(
        upstream.validate_fields().is_ok(),
        "validate_fields must not reject a mesh-projected locality_lb_setting on the runtime path"
    );
}

#[test]
fn test_upstream_mesh_projected_subset_fields_rejected_by_admin_api() {
    let mut upstream = make_upstream("test");
    upstream.subsets = Some(vec![SubsetDefinition {
        name: "v1".to_string(),
        labels: HashMap::from([("version".to_string(), "v1".to_string())]),
        traffic_policy: Some(SubsetTrafficPolicy {
            load_balancer_algorithm: None,
            hash_on: None,
            tls: Some(MeshTrafficPolicyTls::default()),
            connect_timeout_ms: Some(1_000),
            passive_health_check: Some(PassiveHealthCheck::default()),
        }),
    }]);

    let errors = upstream
        .validate_operator_provided_fields()
        .expect_err("mesh-projected subset fields must be rejected on operator writes");
    for field in ["tls", "connect_timeout_ms", "passive_health_check"] {
        assert!(
            errors.iter().any(|error| {
                error.contains("subsets[0].traffic_policy")
                    && error.contains(field)
                    && error.contains("cannot be set directly via the admin API")
            }),
            "expected an operator-write rejection for {field}, got: {errors:?}"
        );
    }

    assert!(
        upstream.validate_fields().is_ok(),
        "runtime mesh apply must continue accepting its projected subset fields"
    );
}

#[test]
fn test_upstream_health_check_validated() {
    let mut upstream = make_upstream("test");
    upstream.health_checks = Some(HealthCheckConfig {
        active: Some(ActiveHealthCheck {
            interval_seconds: 0, // Invalid: must be >= 1
            ..Default::default()
        }),
        passive: None,
    });
    let errs = upstream.validate_fields().unwrap_err();
    assert!(
        errs.iter()
            .any(|e| e.contains("health_checks.active.interval_seconds"))
    );
}

#[test]
fn test_upstream_passive_health_check_validated() {
    let mut upstream = make_upstream("test");
    upstream.health_checks = Some(HealthCheckConfig {
        active: None,
        passive: Some(PassiveHealthCheck {
            unhealthy_threshold: 0, // Invalid: must be >= 1
            ..Default::default()
        }),
    });
    let errs = upstream.validate_fields().unwrap_err();
    assert!(
        errs.iter()
            .any(|e| e.contains("health_checks.passive.unhealthy_threshold"))
    );
}

#[test]
fn test_upstream_passive_health_threshold_above_recent_failures_cap_rejected() {
    use ferrum_edge::config::types::MAX_RECENT_FAILURES_PER_TARGET;

    let mut upstream = make_upstream("test");
    upstream.health_checks = Some(HealthCheckConfig {
        active: None,
        passive: Some(PassiveHealthCheck {
            unhealthy_threshold: MAX_RECENT_FAILURES_PER_TARGET as u32 + 1,
            ..Default::default()
        }),
    });
    let errs = upstream.validate_fields().unwrap_err();
    assert!(
        errs.iter()
            .any(|e| e.contains("health_checks.passive.unhealthy_threshold")),
        "expected rejection when threshold exceeds recent-failures cap, got: {:?}",
        errs
    );

    // Exactly at the cap should be accepted
    let mut upstream2 = make_upstream("test2");
    upstream2.health_checks = Some(HealthCheckConfig {
        active: None,
        passive: Some(PassiveHealthCheck {
            unhealthy_threshold: MAX_RECENT_FAILURES_PER_TARGET as u32,
            ..Default::default()
        }),
    });
    assert!(upstream2.validate_fields().is_ok());
}

#[test]
fn test_upstream_service_discovery_dns_sd_validated() {
    let mut upstream = make_upstream("test");
    upstream.service_discovery = Some(ServiceDiscoveryConfig {
        provider: ferrum_edge::config::types::SdProvider::DnsSd,
        dns_sd: None, // Missing required config
        kubernetes: None,
        consul: None,
        mesh: None,
        default_weight: 1,
    });
    let errs = upstream.validate_fields().unwrap_err();
    assert!(errs.iter().any(|e| e.contains("dns_sd config is required")));
}

#[test]
fn test_upstream_service_discovery_mesh_validated() {
    let mut upstream = make_upstream("test");
    upstream.service_discovery = Some(ServiceDiscoveryConfig {
        provider: SdProvider::Mesh,
        dns_sd: None,
        kubernetes: None,
        consul: None,
        mesh: None,
        default_weight: 1,
    });
    let errs = upstream.validate_fields().unwrap_err();
    assert!(errs.iter().any(|e| e.contains("mesh config is required")));
}

#[test]
fn test_mesh_sd_namespace_must_match_upstream_namespace() {
    let mut upstream = make_upstream("test");
    upstream.namespace = "prod".to_string();
    upstream.service_discovery = Some(ServiceDiscoveryConfig {
        provider: SdProvider::Mesh,
        dns_sd: None,
        kubernetes: None,
        consul: None,
        mesh: Some(MeshSdConfig {
            service_name: "my-svc".to_string(),
            namespace: Some("staging".to_string()),
            port: None,
            poll_interval_seconds: 30,
            topology: Default::default(),
        }),
        default_weight: 1,
    });
    let errs = upstream.validate_fields().unwrap_err();
    assert!(
        errs.iter()
            .any(|e| e.contains("must match the upstream's namespace")),
        "cross-namespace mesh SD should be rejected: {:?}",
        errs
    );
}

#[test]
fn test_mesh_sd_namespace_matching_upstream_passes() {
    let mut upstream = make_upstream("test");
    upstream.namespace = "prod".to_string();
    upstream.service_discovery = Some(ServiceDiscoveryConfig {
        provider: SdProvider::Mesh,
        dns_sd: None,
        kubernetes: None,
        consul: None,
        mesh: Some(MeshSdConfig {
            service_name: "my-svc".to_string(),
            namespace: Some("prod".to_string()),
            port: None,
            poll_interval_seconds: 30,
            topology: Default::default(),
        }),
        default_weight: 1,
    });
    assert!(upstream.validate_fields().is_ok());
}

#[test]
fn test_mesh_sd_namespace_omitted_passes() {
    let mut upstream = make_upstream("test");
    upstream.service_discovery = Some(ServiceDiscoveryConfig {
        provider: SdProvider::Mesh,
        dns_sd: None,
        kubernetes: None,
        consul: None,
        mesh: Some(MeshSdConfig {
            service_name: "my-svc".to_string(),
            namespace: None,
            port: None,
            poll_interval_seconds: 30,
            topology: Default::default(),
        }),
        default_weight: 1,
    });
    assert!(upstream.validate_fields().is_ok());
}

// ---- PluginConfig field validation tests ----

#[test]
fn test_plugin_config_valid_fields_passes() {
    let pc = make_plugin_config("test");
    assert!(pc.validate_fields().is_ok());
}

#[test]
fn test_plugin_config_json_too_large() {
    let mut pc = make_plugin_config("test");
    // Create a large JSON config
    let big_value = "a".repeat(MAX_PLUGIN_CONFIG_SIZE);
    pc.config = serde_json::json!({"data": big_value});
    let errs = pc.validate_fields().unwrap_err();
    assert!(
        errs.iter()
            .any(|e| e.contains("config JSON") && e.contains("exceed"))
    );
}

#[test]
fn test_plugin_config_deeply_nested_json() {
    let mut pc = make_plugin_config("test");
    // Build a deeply nested JSON value (depth > 10)
    let mut val = serde_json::json!("leaf");
    for _ in 0..15 {
        val = serde_json::json!({"nested": val});
    }
    pc.config = val;
    let errs = pc.validate_fields().unwrap_err();
    assert!(errs.iter().any(|e| e.contains("nesting depth")));
}

#[test]
fn test_plugin_config_proxy_scope_requires_proxy_id() {
    let mut pc = make_plugin_config("test");
    pc.scope = PluginScope::Proxy;
    let errs = pc.validate_fields().unwrap_err();
    assert!(
        errs.iter()
            .any(|e| e.contains("scope 'proxy' requires proxy_id"))
    );
}

// ---- GatewayConfig.validate_all_fields() tests ----

#[test]
fn test_validate_all_fields_catches_proxy_errors() {
    let config = GatewayConfig {
        proxies: vec![{
            let mut p = make_proxy("test", "/api");
            p.backend_connect_timeout_ms = 0; // Invalid
            p
        }],
        consumers: vec![],
        plugin_configs: vec![],
        upstreams: vec![],
        ..Default::default()
    };
    let errs = config.validate_all_fields(30).unwrap_err();
    assert!(
        errs.iter()
            .any(|e| e.contains("Proxy 'test'") && e.contains("backend_connect_timeout_ms"))
    );
}

#[test]
fn test_validate_all_fields_catches_consumer_errors() {
    let config = GatewayConfig {
        proxies: vec![],
        consumers: vec![make_consumer("test", &"a".repeat(MAX_USERNAME_LENGTH + 1))],
        plugin_configs: vec![],
        upstreams: vec![],
        ..Default::default()
    };
    let errs = config.validate_all_fields(30).unwrap_err();
    assert!(
        errs.iter()
            .any(|e| e.contains("Consumer 'test'") && e.contains("username"))
    );
}

#[test]
fn test_validate_all_fields_catches_upstream_errors() {
    let config = GatewayConfig {
        proxies: vec![],
        consumers: vec![],
        plugin_configs: vec![],
        upstreams: vec![{
            let mut u = make_upstream("test");
            u.targets[0].port = 0; // Invalid
            u
        }],
        ..Default::default()
    };
    let errs = config.validate_all_fields(30).unwrap_err();
    assert!(
        errs.iter()
            .any(|e| e.contains("Upstream 'test'") && e.contains("targets[0].port"))
    );
}

#[test]
fn test_validate_all_fields_valid_config_passes() {
    let config = GatewayConfig {
        proxies: vec![make_proxy("p1", "/api")],
        consumers: vec![make_consumer("c1", "alice")],
        plugin_configs: vec![make_plugin_config("pc1")],
        upstreams: vec![make_upstream("u1")],
        ..Default::default()
    };
    assert!(config.validate_all_fields(30).is_ok());
}

// ---- CircuitBreakerConfig validation tests ----

#[test]
fn test_circuit_breaker_valid() {
    let cb = CircuitBreakerConfig::default();
    assert!(cb.validate_fields().is_ok());
}

#[test]
fn test_circuit_breaker_timeout_zero() {
    let cb = CircuitBreakerConfig {
        timeout_seconds: 0,
        ..Default::default()
    };
    let errs = cb.validate_fields().unwrap_err();
    assert!(errs.iter().any(|e| e.contains("timeout_seconds")));
}

// ---- RetryConfig validation tests ----

#[test]
fn test_retry_config_valid() {
    let retry = RetryConfig::default();
    assert!(retry.validate_fields().is_ok());
}

#[test]
fn test_retry_backoff_too_large() {
    let retry = RetryConfig {
        max_retries: 3,
        retryable_status_codes: vec![502],
        retryable_methods: vec!["GET".into()],
        backoff: BackoffStrategy::Fixed { delay_ms: 999_999 },
        retry_on_connect_failure: true,
    };
    let errs = retry.validate_fields().unwrap_err();
    assert!(errs.iter().any(|e| e.contains("delay_ms")));
}

// ---- HTTP/2 flow control validation tests ----

#[test]
fn test_proxy_http2_stream_window_too_small() {
    let mut proxy = make_proxy("test", "/api");
    proxy.pool_http2_initial_stream_window_size = Some(MIN_HTTP2_WINDOW_SIZE - 1);
    let errs = proxy.validate_fields().unwrap_err();
    assert!(
        errs.iter()
            .any(|e| e.contains("pool_http2_initial_stream_window_size"))
    );
}

#[test]
fn test_proxy_http2_stream_window_valid_min() {
    let mut proxy = make_proxy("test", "/api");
    proxy.pool_http2_initial_stream_window_size = Some(MIN_HTTP2_WINDOW_SIZE);
    assert!(proxy.validate_fields().is_ok());
}

#[test]
fn test_proxy_http2_connection_window_too_small() {
    let mut proxy = make_proxy("test", "/api");
    proxy.pool_http2_initial_connection_window_size = Some(1000);
    let errs = proxy.validate_fields().unwrap_err();
    assert!(
        errs.iter()
            .any(|e| e.contains("pool_http2_initial_connection_window_size"))
    );
}

#[test]
fn test_proxy_http2_max_frame_size_too_small() {
    let mut proxy = make_proxy("test", "/api");
    proxy.pool_http2_max_frame_size = Some(MIN_HTTP2_MAX_FRAME_SIZE - 1);
    let errs = proxy.validate_fields().unwrap_err();
    assert!(errs.iter().any(|e| e.contains("pool_http2_max_frame_size")));
}

#[test]
fn test_proxy_http2_max_frame_size_too_large() {
    let mut proxy = make_proxy("test", "/api");
    proxy.pool_http2_max_frame_size = Some(MAX_HTTP2_MAX_FRAME_SIZE + 1);
    let errs = proxy.validate_fields().unwrap_err();
    assert!(errs.iter().any(|e| e.contains("pool_http2_max_frame_size")));
}

#[test]
fn test_proxy_http2_max_frame_size_valid_range() {
    let mut proxy = make_proxy("test", "/api");
    proxy.pool_http2_max_frame_size = Some(MIN_HTTP2_MAX_FRAME_SIZE);
    assert!(proxy.validate_fields().is_ok());
    proxy.pool_http2_max_frame_size = Some(MAX_HTTP2_MAX_FRAME_SIZE);
    assert!(proxy.validate_fields().is_ok());
}

#[test]
fn test_proxy_http2_max_concurrent_streams_zero() {
    let mut proxy = make_proxy("test", "/api");
    proxy.pool_http2_max_concurrent_streams = Some(0);
    let errs = proxy.validate_fields().unwrap_err();
    assert!(
        errs.iter()
            .any(|e| e.contains("pool_http2_max_concurrent_streams"))
    );
}

#[test]
fn test_proxy_http2_max_concurrent_streams_above_sql_integer_limit() {
    let mut proxy = make_proxy("test", "/api");
    proxy.pool_http2_max_concurrent_streams = Some(MAX_POOL_SQL_INTEGER_VALUE as u32 + 1);
    let errs = proxy.validate_fields().unwrap_err();
    assert!(
        errs.iter()
            .any(|e| e.contains("pool_http2_max_concurrent_streams"))
    );
}

#[test]
fn test_proxy_http2_max_concurrent_streams_valid() {
    let mut proxy = make_proxy("test", "/api");
    proxy.pool_http2_max_concurrent_streams = Some(1000);
    assert!(proxy.validate_fields().is_ok());
    proxy.pool_http2_max_concurrent_streams = Some(MAX_POOL_SQL_INTEGER_VALUE as u32);
    assert!(proxy.validate_fields().is_ok());
}

#[test]
fn test_proxy_pool_max_requests_per_connection_above_sql_integer_limit() {
    let mut proxy = make_proxy("test", "/api");
    proxy.pool_max_requests_per_connection = Some(MAX_POOL_SQL_INTEGER_VALUE + 1);
    let errs = proxy.validate_fields().unwrap_err();
    assert!(
        errs.iter()
            .any(|e| e.contains("pool_max_requests_per_connection"))
    );
}

#[test]
fn test_proxy_pool_max_requests_per_connection_valid_bounds() {
    let mut proxy = make_proxy("test", "/api");
    proxy.pool_max_requests_per_connection = Some(0);
    assert!(proxy.validate_fields().is_ok());
    proxy.pool_max_requests_per_connection = Some(MAX_POOL_SQL_INTEGER_VALUE);
    assert!(proxy.validate_fields().is_ok());
}

// ---- HTTP/3 connections per backend tests ----

#[test]
fn test_proxy_http3_connections_zero() {
    let mut proxy = make_proxy("test", "/api");
    proxy.pool_http3_connections_per_backend = Some(0);
    let errs = proxy.validate_fields().unwrap_err();
    assert!(
        errs.iter()
            .any(|e| e.contains("pool_http3_connections_per_backend"))
    );
}

#[test]
fn test_proxy_http3_connections_too_large() {
    let mut proxy = make_proxy("test", "/api");
    proxy.pool_http3_connections_per_backend = Some(MAX_HTTP3_CONNECTIONS_PER_BACKEND + 1);
    let errs = proxy.validate_fields().unwrap_err();
    assert!(
        errs.iter()
            .any(|e| e.contains("pool_http3_connections_per_backend"))
    );
}

#[test]
fn test_proxy_http3_connections_valid() {
    let mut proxy = make_proxy("test", "/api");
    proxy.pool_http3_connections_per_backend = Some(4);
    assert!(proxy.validate_fields().is_ok());
}

// ---- TLS file path validation tests ----

#[test]
fn test_frontend_tls_cert_path_too_long() {
    let mut proxy = make_proxy("test", "/api");
    proxy.backend_tls_client_cert_path = Some("a".repeat(MAX_FILE_PATH_LENGTH + 1));
    let errs = proxy.validate_fields().unwrap_err();
    assert!(
        errs.iter()
            .any(|e| e.contains("backend_tls_client_cert_path"))
    );
}

#[test]
fn test_frontend_tls_key_path_too_long() {
    let mut proxy = make_proxy("test", "/api");
    proxy.backend_tls_client_key_path = Some("a".repeat(MAX_FILE_PATH_LENGTH + 1));
    let errs = proxy.validate_fields().unwrap_err();
    assert!(
        errs.iter()
            .any(|e| e.contains("backend_tls_client_key_path"))
    );
}

#[test]
fn test_proxy_tls_ca_path_too_long() {
    let mut proxy = make_proxy("test", "/api");
    proxy.backend_tls_server_ca_cert_path = Some("a".repeat(MAX_FILE_PATH_LENGTH + 1));
    let errs = proxy.validate_fields().unwrap_err();
    assert!(
        errs.iter()
            .any(|e| e.contains("backend_tls_server_ca_cert_path"))
    );
}

#[test]
fn test_proxy_tls_paths_control_chars() {
    let mut proxy = make_proxy("test", "/api");
    proxy.backend_tls_client_cert_path = Some("/certs/\x00evil.pem".into());
    let errs = proxy.validate_fields().unwrap_err();
    assert!(
        errs.iter()
            .any(|e| e.contains("backend_tls_client_cert_path") && e.contains("control"))
    );
}

// ---- TLS cert file content validation tests ----

#[test]
fn test_proxy_tls_cert_file_not_found() {
    let mut proxy = make_proxy("test", "/api");
    // TLS-enabled scheme so the cert/key paths are valid to set; isolates the
    // file-loading failure this test asserts on from the scheme-mismatch check.
    proxy.backend_scheme = Some(BackendScheme::Https);
    proxy.backend_tls_client_cert_path = Some("/nonexistent/cert.pem".into());
    proxy.backend_tls_client_key_path = Some("/nonexistent/key.pem".into());
    let errs = proxy.validate_fields().unwrap_err();
    assert!(
        errs.iter()
            .any(|e| e.contains("backend_tls_client_cert_path")
                && e.contains("failed to read TLS material")),
        "Expected cert file-not-found error, got: {:?}",
        errs
    );
    assert!(
        errs.iter()
            .any(|e| e.contains("backend_tls_client_key_path")
                && e.contains("failed to read TLS material")),
        "Expected key file-not-found error, got: {:?}",
        errs
    );
}

#[test]
fn test_proxy_tls_ca_cert_file_not_found() {
    let mut proxy = make_proxy("test", "/api");
    proxy.backend_scheme = Some(BackendScheme::Https);
    proxy.backend_tls_server_ca_cert_path = Some("/nonexistent/ca.pem".into());
    let errs = proxy.validate_fields().unwrap_err();
    assert!(
        errs.iter()
            .any(|e| e.contains("backend_tls_server_ca_cert_path")
                && e.contains("failed to read TLS material")),
        "Expected CA file-not-found error, got: {:?}",
        errs
    );
}

#[test]
fn test_proxy_tls_cert_file_invalid_pem() {
    use std::io::Write;
    let cert_file = tempfile::NamedTempFile::new().unwrap();
    let key_file = tempfile::NamedTempFile::new().unwrap();
    // Write garbage, not valid PEM
    write!(&cert_file, "not a valid PEM certificate").unwrap();
    write!(&key_file, "not a valid PEM key").unwrap();

    let mut proxy = make_proxy("test", "/api");
    proxy.backend_scheme = Some(BackendScheme::Https);
    proxy.backend_tls_client_cert_path = Some(cert_file.path().to_str().unwrap().to_string());
    proxy.backend_tls_client_key_path = Some(key_file.path().to_str().unwrap().to_string());
    let errs = proxy.validate_fields().unwrap_err();
    assert!(
        errs.iter()
            .any(|e| e.contains("backend_tls_client_cert_path")
                && e.contains("no valid PEM certificates")),
        "Expected invalid PEM cert error, got: {:?}",
        errs
    );
    assert!(
        errs.iter()
            .any(|e| e.contains("backend_tls_client_key_path")
                && e.contains("no valid private keys")),
        "Expected invalid PEM key error, got: {:?}",
        errs
    );
}

#[test]
fn test_proxy_tls_cert_without_key_pairing_error() {
    let mut proxy = make_proxy("test", "/api");
    proxy.backend_tls_client_cert_path = Some("/some/cert.pem".into());
    // key_path intentionally not set
    let errs = proxy.validate_fields().unwrap_err();
    assert!(
        errs.iter()
            .any(|e| e.contains("backend_tls_client_key_path is missing")),
        "Expected cert/key pairing error, got: {:?}",
        errs
    );
}

#[test]
fn test_proxy_tls_key_without_cert_pairing_error() {
    let mut proxy = make_proxy("test", "/api");
    proxy.backend_tls_client_key_path = Some("/some/key.pem".into());
    // cert_path intentionally not set
    let errs = proxy.validate_fields().unwrap_err();
    assert!(
        errs.iter()
            .any(|e| e.contains("backend_tls_client_cert_path is missing")),
        "Expected cert/key pairing error, got: {:?}",
        errs
    );
}

#[test]
fn test_proxy_tls_valid_cert_files_pass() {
    let cert_path = std::fs::canonicalize("tests/certs/server.crt")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    let key_path = std::fs::canonicalize("tests/certs/server.key")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();

    let mut proxy = make_proxy("test", "/api");
    proxy.backend_scheme = Some(BackendScheme::Https);
    proxy.dispatch_kind = DispatchKind::from(BackendScheme::Https);
    proxy.backend_tls_client_cert_path = Some(cert_path.clone());
    proxy.backend_tls_client_key_path = Some(key_path);
    proxy.backend_tls_server_ca_cert_path = Some(cert_path);
    assert!(proxy.validate_fields().is_ok());
}

#[test]
fn test_proxy_tls_fields_rejected_on_plaintext_backend() {
    let cert_path = std::fs::canonicalize("tests/certs/server.crt")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    let key_path = std::fs::canonicalize("tests/certs/server.key")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();

    // HTTP backend with TLS cert fields should be rejected
    let mut proxy = make_proxy("test", "/api");
    proxy.backend_tls_client_cert_path = Some(cert_path.clone());
    proxy.backend_tls_client_key_path = Some(key_path.clone());
    let errs = proxy.validate_fields().unwrap_err();
    assert!(
        errs.iter()
            .any(|e| e.contains("backend_tls_client_cert_path") && e.contains("http"))
    );
    assert!(
        errs.iter()
            .any(|e| e.contains("backend_tls_client_key_path") && e.contains("http"))
    );

    // HTTP backend with CA cert should be rejected
    let mut proxy = make_proxy("test", "/api");
    proxy.backend_tls_server_ca_cert_path = Some(cert_path.clone());
    let errs = proxy.validate_fields().unwrap_err();
    assert!(
        errs.iter()
            .any(|e| e.contains("backend_tls_server_ca_cert_path") && e.contains("http"))
    );

    // HTTP backend with verify=false should be rejected
    let mut proxy = make_proxy("test", "/api");
    proxy.backend_tls_verify_server_cert = false;
    let errs = proxy.validate_fields().unwrap_err();
    assert!(
        errs.iter()
            .any(|e| e.contains("backend_tls_verify_server_cert") && e.contains("http"))
    );

    // Other plaintext schemes: http (covers former ws/grpc), tcp, udp
    for scheme in [BackendScheme::Http, BackendScheme::Tcp, BackendScheme::Udp] {
        let mut proxy = make_proxy("test", "/api");
        proxy.backend_scheme = Some(scheme);
        proxy.dispatch_kind = DispatchKind::from(scheme);
        if scheme.is_stream() {
            proxy.listen_port = Some(19000);
        }
        proxy.backend_tls_client_cert_path = Some(cert_path.clone());
        proxy.backend_tls_client_key_path = Some(key_path.clone());
        let errs = proxy.validate_fields().unwrap_err();
        assert!(
            errs.iter()
                .any(|e| e.contains("backend_tls_client_cert_path")),
            "Expected rejection for {:?}",
            proxy.backend_scheme
        );
    }

    // TLS schemes should allow cert fields. Https covers former wss/grpcs/h3.
    // Stream TLS variants are validated in stream_proxy_config_tests.rs.
    let scheme = BackendScheme::Https;
    let mut proxy = make_proxy("test", "/api");
    proxy.backend_scheme = Some(scheme);
    proxy.dispatch_kind = DispatchKind::from(scheme);
    proxy.backend_tls_client_cert_path = Some(cert_path.clone());
    proxy.backend_tls_client_key_path = Some(key_path.clone());
    proxy.backend_tls_server_ca_cert_path = Some(cert_path.clone());
    assert!(
        proxy.validate_fields().is_ok(),
        "Should pass for scheme={:?}",
        proxy.backend_scheme,
    );
}

// ---- Allowed methods validation tests ----

#[test]
fn test_proxy_allowed_methods_invalid() {
    let mut proxy = make_proxy("test", "/api");
    proxy.allowed_methods = Some(vec!["GET".into(), "GETT".into()]);
    let errs = proxy.validate_fields().unwrap_err();
    assert!(
        errs.iter()
            .any(|e| e.contains("allowed_methods") && e.contains("GETT"))
    );
}

#[test]
fn test_proxy_allowed_methods_valid() {
    let mut proxy = make_proxy("test", "/api");
    proxy.allowed_methods = Some(vec!["GET".into(), "POST".into(), "put".into()]);
    assert!(proxy.validate_fields().is_ok());
}

// ---- Allowed WebSocket origins validation tests ----

#[test]
fn test_proxy_allowed_ws_origins_empty_is_valid() {
    let mut proxy = make_proxy("test", "/api");
    proxy.allowed_ws_origins = vec![];
    assert!(proxy.validate_fields().is_ok());
}

#[test]
fn test_proxy_allowed_ws_origins_valid_entries() {
    let mut proxy = make_proxy("test", "/api");
    proxy.allowed_ws_origins = vec![
        "https://example.com".into(),
        "https://app.example.com".into(),
    ];
    assert!(proxy.validate_fields().is_ok());
}

#[test]
fn test_proxy_allowed_ws_origins_rejects_empty_string() {
    let mut proxy = make_proxy("test", "/api");
    proxy.allowed_ws_origins = vec!["https://example.com".into(), "".into()];
    let errs = proxy.validate_fields().unwrap_err();
    assert!(
        errs.iter()
            .any(|e| e.contains("allowed_ws_origins") && e.contains("must not be empty"))
    );
}

#[test]
fn test_proxy_allowed_ws_origins_rejects_whitespace_only() {
    let mut proxy = make_proxy("test", "/api");
    proxy.allowed_ws_origins = vec!["   ".into()];
    let errs = proxy.validate_fields().unwrap_err();
    assert!(
        errs.iter()
            .any(|e| e.contains("allowed_ws_origins") && e.contains("must not be empty"))
    );
}

// ---- Retryable methods validation tests ----

#[test]
fn test_retry_invalid_method_name() {
    let retry = RetryConfig {
        max_retries: 3,
        retryable_status_codes: vec![502],
        retryable_methods: vec!["GET".into(), "FAKE".into()],
        backoff: BackoffStrategy::Fixed { delay_ms: 100 },
        retry_on_connect_failure: true,
    };
    let errs = retry.validate_fields().unwrap_err();
    assert!(
        errs.iter()
            .any(|e| e.contains("retryable_methods") && e.contains("FAKE"))
    );
}

#[test]
fn test_retry_valid_methods() {
    let retry = RetryConfig {
        max_retries: 3,
        retryable_status_codes: vec![502],
        retryable_methods: vec!["GET".into(), "post".into(), "HEAD".into()],
        backoff: BackoffStrategy::Fixed { delay_ms: 100 },
        retry_on_connect_failure: true,
    };
    assert!(retry.validate_fields().is_ok());
}

// ---- Service discovery optional field validation tests ----

#[test]
fn test_k8s_port_name_too_long() {
    let mut upstream = make_upstream("test");
    upstream.service_discovery = Some(ServiceDiscoveryConfig {
        provider: SdProvider::Kubernetes,
        dns_sd: None,
        kubernetes: Some(KubernetesConfig {
            namespace: "default".into(),
            service_name: "my-svc".into(),
            port_name: Some("a".repeat(MAX_SD_STRING_LENGTH + 1)),
            label_selector: None,
            poll_interval_seconds: 30,
        }),
        consul: None,
        mesh: None,
        default_weight: 1,
    });
    let errs = upstream.validate_fields().unwrap_err();
    assert!(
        errs.iter()
            .any(|e| e.contains("kubernetes.port_name") && e.contains("exceed"))
    );
}

#[test]
fn test_k8s_label_selector_too_long() {
    let mut upstream = make_upstream("test");
    upstream.service_discovery = Some(ServiceDiscoveryConfig {
        provider: SdProvider::Kubernetes,
        dns_sd: None,
        kubernetes: Some(KubernetesConfig {
            namespace: "default".into(),
            service_name: "my-svc".into(),
            port_name: None,
            label_selector: Some("a".repeat(1025)),
            poll_interval_seconds: 30,
        }),
        consul: None,
        mesh: None,
        default_weight: 1,
    });
    let errs = upstream.validate_fields().unwrap_err();
    assert!(
        errs.iter()
            .any(|e| e.contains("kubernetes.label_selector") && e.contains("exceed"))
    );
}

#[test]
fn test_consul_datacenter_too_long() {
    let mut upstream = make_upstream("test");
    upstream.service_discovery = Some(ServiceDiscoveryConfig {
        provider: SdProvider::Consul,
        dns_sd: None,
        kubernetes: None,
        consul: Some(ConsulConfig {
            address: "http://consul:8500".into(),
            service_name: "my-svc".into(),
            datacenter: Some("a".repeat(MAX_SD_STRING_LENGTH + 1)),
            tag: None,
            healthy_only: true,
            token: None,
            poll_interval_seconds: 30,
        }),
        mesh: None,
        default_weight: 1,
    });
    let errs = upstream.validate_fields().unwrap_err();
    assert!(
        errs.iter()
            .any(|e| e.contains("consul.datacenter") && e.contains("exceed"))
    );
}

#[test]
fn test_consul_tag_too_long() {
    let mut upstream = make_upstream("test");
    upstream.service_discovery = Some(ServiceDiscoveryConfig {
        provider: SdProvider::Consul,
        dns_sd: None,
        kubernetes: None,
        consul: Some(ConsulConfig {
            address: "http://consul:8500".into(),
            service_name: "my-svc".into(),
            datacenter: None,
            tag: Some("a".repeat(MAX_SD_STRING_LENGTH + 1)),
            healthy_only: true,
            token: None,
            poll_interval_seconds: 30,
        }),
        mesh: None,
        default_weight: 1,
    });
    let errs = upstream.validate_fields().unwrap_err();
    assert!(
        errs.iter()
            .any(|e| e.contains("consul.tag") && e.contains("exceed"))
    );
}

#[test]
fn test_consul_token_control_chars() {
    let mut upstream = make_upstream("test");
    upstream.service_discovery = Some(ServiceDiscoveryConfig {
        provider: SdProvider::Consul,
        dns_sd: None,
        kubernetes: None,
        consul: Some(ConsulConfig {
            address: "http://consul:8500".into(),
            service_name: "my-svc".into(),
            datacenter: None,
            tag: None,
            healthy_only: true,
            token: Some("secret\x00token".into()),
            poll_interval_seconds: 30,
        }),
        mesh: None,
        default_weight: 1,
    });
    let errs = upstream.validate_fields().unwrap_err();
    assert!(
        errs.iter()
            .any(|e| e.contains("consul.token") && e.contains("control"))
    );
}

#[test]
fn test_consul_valid_optional_fields() {
    let mut upstream = make_upstream("test");
    upstream.service_discovery = Some(ServiceDiscoveryConfig {
        provider: SdProvider::Consul,
        dns_sd: None,
        kubernetes: None,
        consul: Some(ConsulConfig {
            address: "http://consul:8500".into(),
            service_name: "my-svc".into(),
            datacenter: Some("us-east-1".into()),
            tag: Some("production".into()),
            healthy_only: true,
            token: Some("my-acl-token-abc123".into()),
            poll_interval_seconds: 30,
        }),
        mesh: None,
        default_weight: 1,
    });
    assert!(upstream.validate_fields().is_ok());
}

#[test]
fn test_k8s_valid_optional_fields() {
    let mut upstream = make_upstream("test");
    upstream.service_discovery = Some(ServiceDiscoveryConfig {
        provider: SdProvider::Kubernetes,
        dns_sd: None,
        kubernetes: Some(KubernetesConfig {
            namespace: "production".into(),
            service_name: "my-svc".into(),
            port_name: Some("http".into()),
            label_selector: Some("app=my-svc,env=prod".into()),
            poll_interval_seconds: 30,
        }),
        consul: None,
        mesh: None,
        default_weight: 1,
    });
    assert!(upstream.validate_fields().is_ok());
}

#[test]
fn test_mesh_service_name_required() {
    let mut upstream = make_upstream("test");
    upstream.service_discovery = Some(ServiceDiscoveryConfig {
        provider: SdProvider::Mesh,
        dns_sd: None,
        kubernetes: None,
        consul: None,
        mesh: Some(MeshSdConfig {
            service_name: String::new(),
            namespace: None,
            port: Some(8080),
            poll_interval_seconds: 30,
            topology: Default::default(),
        }),
        default_weight: 1,
    });
    let errs = upstream.validate_fields().unwrap_err();
    assert!(
        errs.iter()
            .any(|e| e.contains("mesh.service_name must not be empty"))
    );
}

#[test]
fn test_mesh_port_zero_rejected() {
    let mut upstream = make_upstream("test");
    upstream.service_discovery = Some(ServiceDiscoveryConfig {
        provider: SdProvider::Mesh,
        dns_sd: None,
        kubernetes: None,
        consul: None,
        mesh: Some(MeshSdConfig {
            service_name: "api".into(),
            namespace: Some("default".into()),
            port: Some(0),
            poll_interval_seconds: 30,
            topology: Default::default(),
        }),
        default_weight: 1,
    });
    let errs = upstream.validate_fields().unwrap_err();
    assert!(errs.iter().any(|e| e.contains("mesh.port")));
}

#[test]
fn test_mesh_valid_optional_fields() {
    let mut upstream = make_upstream("test");
    upstream.namespace = "production".to_string();
    upstream.service_discovery = Some(ServiceDiscoveryConfig {
        provider: SdProvider::Mesh,
        dns_sd: None,
        kubernetes: None,
        consul: None,
        mesh: Some(MeshSdConfig {
            service_name: "api".into(),
            namespace: Some("production".into()),
            port: Some(8080),
            poll_interval_seconds: 30,
            topology: Default::default(),
        }),
        default_weight: 1,
    });
    assert!(upstream.validate_fields().is_ok());
}

// ─── hash_on format validation tests ────────────────────────────────────────

#[test]
fn test_upstream_hash_on_valid_formats() {
    for hash_on in &["ip", "header:x-user-id", "cookie:session"] {
        let mut upstream = make_upstream("u1");
        upstream.hash_on = Some(hash_on.to_string());
        assert!(
            upstream.validate_fields().is_ok(),
            "hash_on '{}' should be valid",
            hash_on
        );
    }
}

#[test]
fn test_upstream_hash_on_invalid_format() {
    let mut upstream = make_upstream("u1");
    upstream.hash_on = Some("random_string".to_string());
    let errs = upstream.validate_fields().unwrap_err();
    assert!(errs.iter().any(|e| e.contains("hash_on must be")));
}

#[test]
fn test_upstream_hash_on_empty_header_name() {
    let mut upstream = make_upstream("u1");
    upstream.hash_on = Some("header:".to_string());
    let errs = upstream.validate_fields().unwrap_err();
    assert!(errs.iter().any(|e| e.contains("non-empty header name")));
}

#[test]
fn test_upstream_hash_on_empty_cookie_name() {
    let mut upstream = make_upstream("u1");
    upstream.hash_on = Some("cookie:".to_string());
    let errs = upstream.validate_fields().unwrap_err();
    assert!(errs.iter().any(|e| e.contains("non-empty cookie name")));
}

#[test]
fn test_upstream_hash_on_cookie_config_validation() {
    use ferrum_edge::config::types::HashOnCookieConfig;

    let mut upstream = make_upstream("u1");
    upstream.hash_on = Some("cookie:session".to_string());
    upstream.hash_on_cookie_config = Some(HashOnCookieConfig {
        path: "/".to_string(),
        ttl_seconds: 3600,
        domain: None,
        http_only: true,
        secure: false,
        same_site: Some("Invalid".to_string()),
    });
    let errs = upstream.validate_fields().unwrap_err();
    assert!(
        errs.iter()
            .any(|e| e.contains("same_site must be 'Strict', 'Lax', or 'None'"))
    );
}

#[test]
fn test_upstream_hash_on_cookie_config_valid() {
    use ferrum_edge::config::types::HashOnCookieConfig;

    let mut upstream = make_upstream("u1");
    upstream.hash_on = Some("cookie:session".to_string());
    upstream.hash_on_cookie_config = Some(HashOnCookieConfig {
        path: "/api".to_string(),
        ttl_seconds: 7200,
        domain: Some("example.com".to_string()),
        http_only: true,
        secure: true,
        same_site: Some("Lax".to_string()),
    });
    assert!(upstream.validate_fields().is_ok());
}

// ---- UDP amplification factor validation tests ----

#[test]
fn test_proxy_udp_amplification_factor_valid() {
    let mut proxy = make_proxy("test", "/api");
    proxy.udp_max_response_amplification_factor = Some(10.0);
    assert!(proxy.validate_fields().is_ok());
}

#[test]
fn test_proxy_udp_amplification_factor_none_is_valid() {
    let mut proxy = make_proxy("test", "/api");
    proxy.udp_max_response_amplification_factor = None;
    assert!(proxy.validate_fields().is_ok());
}

#[test]
fn test_proxy_udp_amplification_factor_zero_rejected() {
    let mut proxy = make_proxy("test", "/api");
    proxy.udp_max_response_amplification_factor = Some(0.0);
    let errs = proxy.validate_fields().unwrap_err();
    assert!(
        errs.iter()
            .any(|e| e.contains("udp_max_response_amplification_factor"))
    );
}

#[test]
fn test_proxy_udp_amplification_factor_negative_rejected() {
    let mut proxy = make_proxy("test", "/api");
    proxy.udp_max_response_amplification_factor = Some(-1.0);
    let errs = proxy.validate_fields().unwrap_err();
    assert!(
        errs.iter()
            .any(|e| e.contains("udp_max_response_amplification_factor"))
    );
}

// ---- SSRF: Backend IP policy validation tests ----

use ferrum_edge::config::{BackendAllowIps, BackendEgressPolicy};

#[test]
fn test_validate_backend_ip_policy_public_denies_private_proxy() {
    let proxy = make_proxy("test", "/api");
    let config = GatewayConfig {
        proxies: vec![Proxy {
            backend_host: "10.0.0.1".to_string(),
            ..proxy
        }],
        ..Default::default()
    };
    let result = config.validate_all_fields_with_ip_policy(
        30,
        &BackendEgressPolicy::from_allow_ips(BackendAllowIps::Public),
    );
    assert!(result.is_err());
    let errs = result.unwrap_err();
    assert!(
        errs.iter()
            .any(|e| e.contains("denied by backend egress policy"))
    );
}

#[test]
fn test_validate_backend_ip_policy_public_allows_public_proxy() {
    let proxy = make_proxy("test", "/api");
    let config = GatewayConfig {
        proxies: vec![Proxy {
            backend_host: "8.8.8.8".to_string(),
            ..proxy
        }],
        ..Default::default()
    };
    assert!(
        config
            .validate_all_fields_with_ip_policy(
                30,
                &BackendEgressPolicy::from_allow_ips(BackendAllowIps::Public)
            )
            .is_ok()
    );
}

#[test]
fn test_validate_backend_ip_policy_public_denies_private_dns_override() {
    let proxy = make_proxy("test", "/api");
    let config = GatewayConfig {
        proxies: vec![Proxy {
            backend_host: "example.com".to_string(),
            dns_override: Some("169.254.169.254".to_string()),
            ..proxy
        }],
        ..Default::default()
    };
    let result = config.validate_all_fields_with_ip_policy(
        30,
        &BackendEgressPolicy::from_allow_ips(BackendAllowIps::Public),
    );
    assert!(result.is_err());
    let errs = result.unwrap_err();
    assert!(
        errs.iter()
            .any(|e| e.contains("dns_override") && e.contains("169.254.169.254"))
    );
}

#[test]
fn test_validate_backend_ip_policy_public_allows_public_dns_override() {
    let proxy = make_proxy("test", "/api");
    let config = GatewayConfig {
        proxies: vec![Proxy {
            backend_host: "example.com".to_string(),
            dns_override: Some("8.8.8.8".to_string()),
            ..proxy
        }],
        ..Default::default()
    };
    assert!(
        config
            .validate_all_fields_with_ip_policy(
                30,
                &BackendEgressPolicy::from_allow_ips(BackendAllowIps::Public)
            )
            .is_ok()
    );
}

#[test]
fn test_validate_backend_ip_policy_private_denies_public_proxy() {
    let proxy = make_proxy("test", "/api");
    let config = GatewayConfig {
        proxies: vec![Proxy {
            backend_host: "8.8.8.8".to_string(),
            ..proxy
        }],
        ..Default::default()
    };
    let result = config.validate_all_fields_with_ip_policy(
        30,
        &BackendEgressPolicy::from_allow_ips(BackendAllowIps::Private),
    );
    assert!(result.is_err());
}

#[test]
fn test_validate_backend_ip_policy_both_allows_everything() {
    let proxy = make_proxy("test", "/api");
    let config = GatewayConfig {
        proxies: vec![Proxy {
            backend_host: "169.254.169.254".to_string(),
            ..proxy
        }],
        ..Default::default()
    };
    assert!(
        config
            .validate_all_fields_with_ip_policy(30, &BackendEgressPolicy::unrestricted())
            .is_ok()
    );
}

#[test]
fn test_validate_backend_ip_policy_default_blocks_metadata_backend_host() {
    // The PRODUCTION default (mode `both` + dangerous-range baseline) must
    // reject a literal cloud-metadata backend_host at config-load time, even
    // though loopback/RFC1918 backends remain allowed.
    let default_policy =
        BackendEgressPolicy::from_env(BackendAllowIps::Both, "", "", true).expect("valid");

    let metadata_cfg = GatewayConfig {
        proxies: vec![Proxy {
            backend_host: "169.254.169.254".to_string(),
            ..make_proxy("meta", "/api")
        }],
        ..Default::default()
    };
    let err = metadata_cfg
        .validate_all_fields_with_ip_policy(30, &default_policy)
        .expect_err("metadata backend must be rejected by default");
    assert!(
        err.iter()
            .any(|e| e.contains("169.254.169.254") && e.contains("backend egress policy"))
    );

    // ...but a loopback / RFC1918 backend still validates under the same default.
    let private_cfg = GatewayConfig {
        proxies: vec![
            Proxy {
                backend_host: "127.0.0.1".to_string(),
                ..make_proxy("loop", "/lo")
            },
            Proxy {
                backend_host: "10.0.0.5".to_string(),
                ..make_proxy("rfc1918", "/internal")
            },
        ],
        ..Default::default()
    };
    assert!(
        private_cfg
            .validate_all_fields_with_ip_policy(30, &default_policy)
            .is_ok()
    );
}

#[test]
fn test_proxy_validate_backend_egress_ips_helper() {
    // The per-resource helper (used by the admin write path) screens
    // backend_host + dns_override under the default policy.
    let default_policy =
        BackendEgressPolicy::from_env(BackendAllowIps::Both, "", "", true).expect("valid");

    let metadata = Proxy {
        backend_host: "169.254.169.254".to_string(),
        ..make_proxy("m", "/a")
    };
    let errs = metadata
        .validate_backend_egress_ips(&default_policy)
        .unwrap_err();
    assert!(errs.iter().any(|e| e.contains("backend_host")
        && e.contains("169.254.169.254")
        && e.contains("backend egress policy")));

    let rebind = Proxy {
        backend_host: "example.com".to_string(),
        dns_override: Some("fd00:ec2::254".to_string()),
        ..make_proxy("r", "/b")
    };
    assert!(
        rebind
            .validate_backend_egress_ips(&default_policy)
            .unwrap_err()
            .iter()
            .any(|e| e.contains("dns_override") && e.contains("fd00:ec2::254"))
    );

    // Loopback / RFC1918 backends still validate.
    let ok = Proxy {
        backend_host: "127.0.0.1".to_string(),
        ..make_proxy("ok", "/c")
    };
    assert!(ok.validate_backend_egress_ips(&default_policy).is_ok());
}

#[test]
fn test_validate_backend_ip_policy_hostname_skipped() {
    // Hostnames can't be checked at config time — only literal IPs are validated
    let proxy = make_proxy("test", "/api");
    let config = GatewayConfig {
        proxies: vec![Proxy {
            backend_host: "internal.evil.com".to_string(),
            ..proxy
        }],
        ..Default::default()
    };
    assert!(
        config
            .validate_all_fields_with_ip_policy(
                30,
                &BackendEgressPolicy::from_allow_ips(BackendAllowIps::Public)
            )
            .is_ok()
    );
}

#[test]
fn test_validate_backend_ip_policy_upstream_target_denied() {
    let upstream = Upstream {
        id: "up1".to_string(),
        namespace: ferrum_edge::config::types::default_namespace(),
        name: Some("test-upstream".to_string()),
        targets: vec![UpstreamTarget {
            host: "169.254.169.254".to_string(),
            port: 80,
            service_port_policy_key: None,
            weight: 100,
            path: None,
            tags: HashMap::new(),
            locality: None,
        }],
        algorithm: LoadBalancerAlgorithm::RoundRobin,
        hash_on: None,
        hash_on_cookie_config: None,
        health_checks: None,
        service_discovery: None,
        subsets: None,
        port_overrides: HashMap::new(),
        source_locality: None,
        locality_lb_strict: false,
        locality_lb_setting: None,
        backend_tls_client_cert_path: None,
        backend_tls_client_key_path: None,
        backend_tls_verify_server_cert: true,
        backend_tls_server_ca_cert_path: None,
        backend_tls_sni: None,
        backend_tls_san_allow_list: Vec::new(),
        resolved_subset_tls: HashMap::new(),
        dispatch_port_override_fallback: None,
        api_spec_id: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };
    let config = GatewayConfig {
        upstreams: vec![upstream],
        ..Default::default()
    };
    let result = config.validate_all_fields_with_ip_policy(
        30,
        &BackendEgressPolicy::from_allow_ips(BackendAllowIps::Public),
    );
    assert!(result.is_err());
    let errs = result.unwrap_err();
    assert!(
        errs.iter()
            .any(|e| e.contains("Upstream") && e.contains("169.254.169.254"))
    );
}

#[test]
fn test_validate_backend_ip_policy_mesh_route_dispatch_trims_direct_ip() {
    let plugin = PluginConfig {
        id: "mrd-private-ip".to_string(),
        plugin_name: "mesh_route_dispatch".to_string(),
        namespace: ferrum_edge::config::types::default_namespace(),
        config: serde_json::json!({
            "rules": [{
                "match": {"methods": ["GET"]},
                "destination": {
                    "backend_host": " 169.254.169.254 ",
                    "backend_port": 8080
                }
            }]
        }),
        scope: PluginScope::Proxy,
        proxy_id: Some("p1".to_string()),
        enabled: true,
        priority_override: None,
        api_spec_id: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };
    let config = GatewayConfig {
        plugin_configs: vec![plugin],
        ..Default::default()
    };

    let result = config.validate_all_fields_with_ip_policy(
        30,
        &BackendEgressPolicy::from_allow_ips(BackendAllowIps::Public),
    );

    assert!(result.is_err());
    let errs = result.unwrap_err();
    assert!(errs.iter().any(|e| {
        e.contains("PluginConfig")
            && e.contains("mesh_route_dispatch")
            && e.contains("169.254.169.254")
            && e.contains("backend egress policy")
    }));
}

// ── WebSocket idle timeout: per-proxy override + validation ──────────────────

#[test]
fn test_proxy_websocket_idle_timeout_none_passes() {
    // None = inherit the global default; always valid.
    let mut proxy = make_proxy("ws", "/ws");
    proxy.websocket_idle_timeout_seconds = None;
    assert!(proxy.validate_fields().is_ok());
}

#[test]
fn test_proxy_websocket_idle_timeout_zero_passes() {
    // Explicit 0 = disabled for this proxy; a deliberate opt-out, not an error.
    let mut proxy = make_proxy("ws", "/ws");
    proxy.websocket_idle_timeout_seconds = Some(0);
    assert!(proxy.validate_fields().is_ok());
}

#[test]
fn test_proxy_websocket_idle_timeout_within_range_passes() {
    let mut proxy = make_proxy("ws", "/ws");
    proxy.websocket_idle_timeout_seconds = Some(600);
    assert!(proxy.validate_fields().is_ok());

    proxy.websocket_idle_timeout_seconds = Some(MAX_WEBSOCKET_IDLE_TIMEOUT);
    assert!(proxy.validate_fields().is_ok());
}

#[test]
fn test_proxy_websocket_idle_timeout_too_large_rejected() {
    let mut proxy = make_proxy("ws", "/ws");
    proxy.websocket_idle_timeout_seconds = Some(MAX_WEBSOCKET_IDLE_TIMEOUT + 1);
    let errs = proxy.validate_fields().unwrap_err();
    assert!(
        errs.iter()
            .any(|e| e.contains("websocket_idle_timeout_seconds") && e.contains("between 0 and")),
        "expected a websocket_idle_timeout_seconds range error, got: {errs:?}"
    );
}

#[test]
fn test_proxy_effective_websocket_idle_timeout_resolution() {
    let mut proxy = make_proxy("ws", "/ws");

    // None -> inherit the global default.
    proxy.websocket_idle_timeout_seconds = None;
    assert_eq!(proxy.effective_websocket_idle_timeout_seconds(300), 300);
    assert_eq!(proxy.effective_websocket_idle_timeout_seconds(0), 0);

    // Some(0) -> explicitly disabled regardless of the global value.
    proxy.websocket_idle_timeout_seconds = Some(0);
    assert_eq!(proxy.effective_websocket_idle_timeout_seconds(300), 0);

    // Some(n) -> per-proxy override wins over the global value.
    proxy.websocket_idle_timeout_seconds = Some(45);
    assert_eq!(proxy.effective_websocket_idle_timeout_seconds(300), 45);
    assert_eq!(proxy.effective_websocket_idle_timeout_seconds(0), 45);
}
