//! Tests for [`ProxyState::apply_incremental`] outcome semantics.
//!
//! Regression guard for the bug where the DB polling loop unconditionally
//! advanced `last_poll_at` after `apply_incremental` returned, even when the
//! patched config was rejected by validation. With the previous boolean
//! return type, callers could not distinguish "nothing to apply" from
//! "rejected by validation", so the cursor advanced past rows that needed
//! retry — and the 1-second `since_safe` margin was too narrow to ever
//! re-fetch them, leaving permanent divergence between DB and in-memory
//! config.
//!
//! These tests assert the three [`ConfigApplyOutcome`] variants are
//! returned correctly, and simulate a `last_poll_at` update logic identical
//! to the polling loop in `src/modes/database.rs` to verify the cursor only
//! advances on `Applied`/`Unchanged`, never on `Rejected`.

use std::collections::HashMap;

use chrono::{Duration, Utc};

use ferrum_edge::config::db_loader::{IncrementalResult, NamespacedResourceId};
use ferrum_edge::config::types::{
    AuthMode, BackendScheme, Consumer, DispatchKind, GatewayConfig, LoadBalancerAlgorithm,
    PluginConfig, PluginScope, Proxy, Upstream, UpstreamTarget,
};
use ferrum_edge::dns::{DnsCache, DnsConfig};
use ferrum_edge::plugins::{PluginResult, ProxyProtocol, RequestContext};
use ferrum_edge::proxy::{ConfigApplyOutcome, ProxyState};

/// Minimal test proxy with safe defaults.
fn test_proxy(id: &str, listen_path: &str) -> Proxy {
    Proxy {
        id: id.to_string(),
        namespace: ferrum_edge::config::types::default_namespace(),
        name: Some(format!("Test Proxy {}", id)),
        hosts: vec![],
        listen_path: Some(listen_path.to_string()),
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

fn test_consumer(id: &str, username: &str) -> Consumer {
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

fn test_plugin_config(id: &str, enabled: bool) -> PluginConfig {
    PluginConfig {
        id: id.to_string(),
        namespace: ferrum_edge::config::types::default_namespace(),
        plugin_name: "stdout_logging".to_string(),
        config: serde_json::Value::Object(serde_json::Map::new()),
        scope: PluginScope::Global,
        proxy_id: None,
        enabled,
        priority_override: None,
        api_spec_id: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

fn test_upstream(id: &str, host: &str, port: u16) -> Upstream {
    Upstream {
        id: id.to_string(),
        namespace: ferrum_edge::config::types::default_namespace(),
        name: None,
        targets: vec![UpstreamTarget {
            host: host.to_string(),
            port,
            service_port_policy_key: None,
            weight: 100,
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

/// Minimal `EnvConfig` for in-process `ProxyState` construction (file mode).
fn test_env_config() -> ferrum_edge::config::EnvConfig {
    ferrum_edge::config::EnvConfig {
        mode: ferrum_edge::config::env_config::OperatingMode::File,
        log_level: "info".into(),
        enable_streaming_latency_tracking: false,
        proxy_http_port: 8000,
        proxy_https_port: 8443,
        frontend_tls_cert_path: None,
        frontend_tls_key_path: None,
        proxy_bind_address: "0.0.0.0".into(),
        admin_http_port: 9000,
        admin_https_port: 9443,
        admin_tls_cert_path: None,
        admin_tls_key_path: None,
        admin_bind_address: "0.0.0.0".into(),
        allow_insecure_admin_http: false,
        admin_jwt_secret: None,
        db_type: None,
        db_url: None,
        db_poll_interval: 30,
        db_rejected_delta_backoff_initial_seconds: 1,
        db_rejected_delta_backoff_max_seconds: 30,
        db_rejected_delta_full_reload_threshold: 3,
        db_tls_mode: None,
        db_tls_ca_cert_path: None,
        db_tls_client_cert_path: None,
        db_tls_client_key_path: None,
        file_config_path: Some("/tmp/test-config.json".into()),
        db_config_backup_path: None,
        db_failover_urls: Vec::new(),
        db_read_replica_url: None,
        cp_grpc_listen_addr: None,
        cp_dp_grpc_jwt_secret: None,
        dp_cp_grpc_urls: Vec::new(),
        dp_cp_failover_primary_retry_secs: 300,
        cp_grpc_tls_cert_path: None,
        cp_grpc_tls_key_path: None,
        cp_grpc_tls_client_ca_path: None,
        dp_grpc_tls_ca_cert_path: None,
        dp_grpc_tls_client_cert_path: None,
        dp_grpc_tls_client_key_path: None,
        dp_grpc_tls_no_verify: false,
        max_header_size_bytes: 32768,
        max_single_header_size_bytes: 16384,
        max_request_body_size_bytes: 10_485_760,
        max_response_body_size_bytes: 10_485_760,
        response_buffer_cutoff_bytes: 65_536,
        h2_coalesce_target_bytes: 131_072,
        dns_ttl_override: None,
        dns_overrides: HashMap::new(),
        dns_resolver_address: None,
        dns_resolver_hosts_file: None,
        dns_order: None,
        dns_min_ttl: 5,
        dns_stale_ttl: 3600,
        dns_error_ttl: 1,
        dns_failed_retry_interval: 10,
        dns_warmup_concurrency: 500,
        backend_allow_ips: ferrum_edge::config::BackendEgressPolicy::unrestricted(),
        tls_ca_bundle_path: None,
        backend_tls_client_cert_path: None,
        backend_tls_client_key_path: None,
        frontend_tls_client_ca_bundle_path: None,
        admin_tls_client_ca_bundle_path: None,
        tls_no_verify: false,
        admin_read_only: false,
        admin_audit_enabled: false,
        admin_tls_no_verify: false,
        enable_http3: false,
        http3_idle_timeout: 30,
        http3_max_streams: 1000,
        http3_stream_receive_window: 8_388_608,
        http3_receive_window: 33_554_432,
        http3_send_window: 8_388_608,
        http3_connections_per_backend: 4,
        http3_pool_idle_timeout_seconds: 120,
        grpc_pool_ready_wait_ms: 1,
        pool_cleanup_interval_seconds: 30,
        tcp_idle_timeout_seconds: 300,
        udp_max_sessions: 10_000,
        udp_cleanup_interval_seconds: 10,
        tls_min_version: "1.2".into(),
        tls_max_version: "1.3".into(),
        tls_cipher_suites: None,
        tls_prefer_server_cipher_order: true,
        tls_curves: None,
        tls_session_cache_size: 4096,
        stream_proxy_bind_address: "0.0.0.0".into(),
        admin_allowed_cidrs: String::new(),
        trusted_proxies: String::new(),
        dns_cache_max_size: 10_000,
        dns_slow_threshold_ms: None,
        real_ip_header: None,
        dtls_cert_path: None,
        dtls_key_path: None,
        dtls_client_ca_cert_path: None,
        plugin_http_slow_threshold_ms: 1000,
        admin_restore_max_body_size_mib: 100,
        migrate_action: "up".into(),
        migrate_dry_run: false,
        worker_threads: None,
        blocking_threads: None,
        max_connections: 0,
        tcp_listen_backlog: 2048,
        server_http2_max_concurrent_streams: 250,
        ..Default::default()
    }
}

fn proxy_state_with_config(config: GatewayConfig) -> ProxyState {
    let dns_cache = DnsCache::new(DnsConfig {
        global_overrides: HashMap::new(),
        resolver_addresses: None,
        hosts_file_path: None,
        dns_order: None,
        ttl_override_seconds: None,
        min_ttl_seconds: 5,
        stale_ttl_seconds: 3600,
        error_ttl_seconds: 1,
        max_cache_size: 10_000,
        warmup_concurrency: 500,
        backend_allow_ips: ferrum_edge::config::BackendEgressPolicy::unrestricted(),
        slow_threshold_ms: None,
        refresh_threshold_percent: 90,
        failed_retry_interval_seconds: 10,
        try_tcp_on_error: true,
        num_concurrent_reqs: 3,
        max_active_requests: 512,
        max_concurrent_refreshes: 64,
        shard_amount: 0,
    });
    let (state, _health_check_handles) =
        ProxyState::new(config, dns_cache, test_env_config(), None, None).unwrap();
    state
}

fn empty_proxy_state() -> ProxyState {
    proxy_state_with_config(GatewayConfig::default())
}

fn empty_delta_at(poll_timestamp: chrono::DateTime<Utc>) -> IncrementalResult {
    IncrementalResult {
        added_or_modified_proxies: vec![],
        removed_proxy_ids: vec![],
        added_or_modified_consumers: vec![],
        removed_consumer_ids: vec![],
        added_or_modified_plugin_configs: vec![],
        removed_plugin_config_ids: vec![],
        added_or_modified_upstreams: vec![],
        removed_upstream_ids: vec![],
        sequence_cursor: 0,
        poll_timestamp,
    }
}

fn delta_with_proxy(proxy: Proxy, poll_timestamp: chrono::DateTime<Utc>) -> IncrementalResult {
    IncrementalResult {
        added_or_modified_proxies: vec![proxy],
        removed_proxy_ids: vec![],
        added_or_modified_consumers: vec![],
        removed_consumer_ids: vec![],
        added_or_modified_plugin_configs: vec![],
        removed_plugin_config_ids: vec![],
        added_or_modified_upstreams: vec![],
        removed_upstream_ids: vec![],
        sequence_cursor: 0,
        poll_timestamp,
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn update_config_empty_candidate_returns_unchanged() {
    let state = empty_proxy_state();
    let outcome = state.update_config(GatewayConfig::default());
    assert_eq!(outcome, ConfigApplyOutcome::Unchanged);
    assert!(
        state.config.load().proxies.is_empty(),
        "unchanged full candidate must not mutate runtime config"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn update_config_rejected_candidate_reports_rejected() {
    let state = empty_proxy_state();

    let mut p1 = test_proxy("p1", "/dup");
    let mut p2 = test_proxy("p2", "/dup");
    p1.hosts = vec![];
    p2.hosts = vec![];

    let candidate = GatewayConfig {
        proxies: vec![p1, p2],
        loaded_at: Utc::now(),
        ..GatewayConfig::default()
    };
    let outcome = state.update_config(candidate);

    assert!(matches!(outcome, ConfigApplyOutcome::Rejected { .. }));
    assert!(
        state.config.load().proxies.is_empty(),
        "rejected full candidate must not mutate runtime config"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn update_config_quarantines_invalid_hmac_credentials_before_full_snapshot_swap() {
    let state = empty_proxy_state();
    let shared_secret = "shared-hmac-secret-at-least-32-characters";
    let mut first = test_consumer("c1", "alice");
    first.credentials.insert(
        "hmac_auth".to_string(),
        serde_json::json!([{"secret": shared_secret}]),
    );
    let mut duplicate = test_consumer("c2", "bob");
    duplicate.credentials.insert(
        "hmac_auth".to_string(),
        serde_json::json!([{"secret": shared_secret}]),
    );
    let mut weak = test_consumer("c3", "carol");
    weak.credentials.insert(
        "hmac_auth".to_string(),
        serde_json::json!([{"secret": "too-short"}]),
    );
    let mut malformed = test_consumer("c4", "dave");
    malformed.credentials.insert(
        "hmac_auth".to_string(),
        serde_json::json!([{
            "secret": "strong-hmac-secret-at-least-32-characters",
            "unexpected": true
        }]),
    );

    let outcome = state.update_config(GatewayConfig {
        consumers: vec![first, duplicate, weak, malformed],
        loaded_at: Utc::now(),
        ..GatewayConfig::default()
    });

    assert_eq!(outcome, ConfigApplyOutcome::Applied);
    let config = state.config.load();
    assert!(config.consumers[0].has_credential("hmac_auth"));
    assert!(!config.consumers[1].has_credential("hmac_auth"));
    assert!(!config.consumers[2].has_credential("hmac_auth"));
    assert!(!config.consumers[3].has_credential("hmac_auth"));
}

#[tokio::test(flavor = "multi_thread")]
async fn update_config_preserves_same_hmac_secret_across_namespaces() {
    let state = empty_proxy_state();
    let shared_secret = "namespace-reusable-hmac-secret-at-least-32-characters";
    let mut tenant_a = test_consumer("c1", "alice");
    tenant_a.namespace = "tenant-a".to_string();
    tenant_a.credentials.insert(
        "hmac_auth".to_string(),
        serde_json::json!([{"secret": shared_secret}]),
    );
    let mut tenant_b = test_consumer("c2", "bob");
    tenant_b.namespace = "tenant-b".to_string();
    tenant_b.credentials.insert(
        "hmac_auth".to_string(),
        serde_json::json!([{"secret": shared_secret}]),
    );

    assert_eq!(
        state.update_config(GatewayConfig {
            consumers: vec![tenant_a, tenant_b],
            loaded_at: Utc::now(),
            ..GatewayConfig::default()
        }),
        ConfigApplyOutcome::Applied
    );
    assert!(
        state
            .config
            .load()
            .consumers
            .iter()
            .all(|consumer| consumer.has_credential("hmac_auth"))
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn full_snapshot_rehydrates_quarantined_hmac_after_conflict_repair() {
    let state = empty_proxy_state();
    let original_secret = "shared-hmac-secret-at-least-32-characters";
    let mut first = test_consumer("c1", "alice");
    first.credentials.insert(
        "hmac_auth".to_string(),
        serde_json::json!([{"secret": original_secret}]),
    );
    let mut second = test_consumer("c2", "bob");
    second.credentials.insert(
        "hmac_auth".to_string(),
        serde_json::json!([{"secret": original_secret}]),
    );
    assert_eq!(
        state.update_config(GatewayConfig {
            consumers: vec![first, second],
            loaded_at: Utc::now(),
            ..GatewayConfig::default()
        }),
        ConfigApplyOutcome::Applied
    );
    assert!(!state.config.load().consumers[1].has_credential("hmac_auth"));

    let mut repaired_first = test_consumer("c1", "alice");
    repaired_first.credentials.insert(
        "hmac_auth".to_string(),
        serde_json::json!([{"secret": "rotated-hmac-secret-at-least-32-characters"}]),
    );
    let mut rehydrated_second = test_consumer("c2", "bob");
    rehydrated_second.credentials.insert(
        "hmac_auth".to_string(),
        serde_json::json!([{"secret": original_secret}]),
    );
    assert_eq!(
        state.update_config(GatewayConfig {
            consumers: vec![repaired_first, rehydrated_second],
            loaded_at: Utc::now(),
            ..GatewayConfig::default()
        }),
        ConfigApplyOutcome::Applied
    );
    assert!(
        state
            .config
            .load()
            .consumers
            .iter()
            .all(|consumer| consumer.has_credential("hmac_auth"))
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn security_headers_unknown_key_reload_keeps_last_known_good_policy() {
    let state = empty_proxy_state();
    let mut plugin = test_plugin_config("security-policy", true);
    plugin.plugin_name = "security_headers".to_string();
    plugin.config = serde_json::json!({
        "hsts": { "max_age": 300, "include_subdomains": true },
        "set": { "X-Policy": "last-known-good" }
    });
    let valid = GatewayConfig {
        proxies: vec![test_proxy("p1", "/api")],
        plugin_configs: vec![plugin],
        loaded_at: Utc::now(),
        ..GatewayConfig::default()
    };
    assert_eq!(
        state.update_config(valid.clone()),
        ConfigApplyOutcome::Applied
    );
    assert!(
        state
            .plugin_cache
            .request_view("p1", ProxyProtocol::Http)
            .plugins()
            .iter()
            .any(|plugin| plugin.name() == "security_headers")
    );

    let mut invalid = valid;
    invalid.plugin_configs[0].config = serde_json::json!({
        "hsts": {
            "max_age": 300,
            "include_subdomains": true,
            "include_subdomain": true
        },
        "set": { "X-Policy": "must-not-publish" }
    });
    invalid.plugin_configs[0].updated_at += Duration::milliseconds(1);
    let outcome = state.update_config(invalid);
    let ConfigApplyOutcome::Rejected { errors } = outcome else {
        panic!("unknown nested security_headers key must reject reload");
    };
    assert!(errors.iter().any(|error| {
        error.contains("security_headers.hsts") && error.contains("include_subdomain")
    }));
    assert_eq!(
        state.config.load().plugin_configs[0].config["set"]["X-Policy"],
        "last-known-good"
    );
    assert!(
        state
            .plugin_cache
            .request_view("p1", ProxyProtocol::Http)
            .plugins()
            .iter()
            .any(|plugin| plugin.name() == "security_headers"),
        "rejected reload must retain the last-known-good plugin cache"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn ip_restriction_typo_reload_keeps_last_known_good_policy() {
    let state = empty_proxy_state();
    let mut plugin = test_plugin_config("ip-policy", true);
    plugin.plugin_name = "ip_restriction".to_string();
    plugin.config = serde_json::json!({"allow": ["10.0.0.0/8"]});
    let valid = GatewayConfig {
        proxies: vec![test_proxy("p1", "/api")],
        plugin_configs: vec![plugin],
        loaded_at: Utc::now(),
        ..GatewayConfig::default()
    };
    assert_eq!(
        state.update_config(valid.clone()),
        ConfigApplyOutcome::Applied
    );

    let mut invalid = valid;
    invalid.plugin_configs[0].config = serde_json::json!({
        "alow": ["192.0.2.0/24"],
        "deny": ["203.0.113.0/24"]
    });
    invalid.plugin_configs[0].updated_at += Duration::milliseconds(1);
    let ConfigApplyOutcome::Rejected { errors } = state.update_config(invalid) else {
        panic!("misspelled ip_restriction allow list must reject reload");
    };
    assert!(errors.iter().any(|error| {
        error.contains("ip_restriction") && error.contains("unknown configuration field 'alow'")
    }));
    assert_eq!(
        state.config.load().plugin_configs[0].config,
        serde_json::json!({"allow": ["10.0.0.0/8"]})
    );

    let request_view = state.plugin_cache.request_view("p1", ProxyProtocol::Http);
    let mut ctx = RequestContext::new(
        "198.51.100.44".to_string(),
        "GET".to_string(),
        "/api".to_string(),
    );
    let result = request_view.plugins()[0]
        .on_request_received(&mut ctx)
        .await;
    assert!(
        matches!(
            result,
            PluginResult::Reject {
                status_code: 403,
                ..
            }
        ),
        "rejected candidate must not replace the last-known-good allow policy"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn ldap_plaintext_reload_keeps_last_known_good_dial_policy() {
    let state = empty_proxy_state();
    let mut plugin = test_plugin_config("directory-policy", true);
    plugin.plugin_name = "ldap_auth".to_string();
    plugin.config = serde_json::json!({
        "ldap_url": "ldaps://directory.example.test:636",
        "bind_dn_template": "uid={username},ou=users,dc=example,dc=test"
    });
    let valid = GatewayConfig {
        proxies: vec![test_proxy("p1", "/api")],
        plugin_configs: vec![plugin],
        loaded_at: Utc::now(),
        ..GatewayConfig::default()
    };
    assert_eq!(
        state.update_config(valid.clone()),
        ConfigApplyOutcome::Applied
    );
    assert!(
        state
            .plugin_cache
            .request_view("p1", ProxyProtocol::Http)
            .plugins()
            .iter()
            .any(|plugin| plugin.name() == "ldap_auth")
    );

    let mut invalid = valid;
    invalid.plugin_configs[0].config = serde_json::json!({
        "ldap_url": "ldap://directory.example.test:389",
        "bind_dn_template": "uid={username},ou=users,dc=example,dc=test"
    });
    invalid.plugin_configs[0].updated_at += Duration::milliseconds(1);
    let outcome = state.update_config(invalid);
    let ConfigApplyOutcome::Rejected { errors } = outcome else {
        panic!("remote plaintext LDAP reload must be rejected");
    };
    assert!(
        errors
            .iter()
            .any(|error| { error.contains("ldap_auth") && error.contains("STARTTLS or LDAPS") })
    );
    assert_eq!(
        state.config.load().plugin_configs[0].config["ldap_url"],
        "ldaps://directory.example.test:636"
    );
    assert!(
        state
            .plugin_cache
            .request_view("p1", ProxyProtocol::Http)
            .plugins()
            .iter()
            .any(|plugin| plugin.name() == "ldap_auth"),
        "rejected LDAP reload must retain the last-known-good dial policy"
    );
}

/// Empty incremental result returns `Unchanged` so the polling loop can still
/// advance `last_poll_at` (no work to retry).
#[tokio::test(flavor = "multi_thread")]
async fn apply_incremental_empty_result_returns_unchanged() {
    let state = empty_proxy_state();
    let result = state.apply_incremental(empty_delta_at(Utc::now())).await;
    assert_eq!(result, ConfigApplyOutcome::Unchanged);
}

/// A valid incremental result returns `Applied` and the config is patched.
#[tokio::test(flavor = "multi_thread")]
async fn apply_incremental_valid_changes_returns_applied() {
    let state = empty_proxy_state();
    assert!(state.config.load().proxies.is_empty());

    let delta = delta_with_proxy(test_proxy("p1", "/api/v1"), Utc::now());
    let result = state.apply_incremental(delta).await;

    assert_eq!(result, ConfigApplyOutcome::Applied);
    let cfg = state.config.load();
    assert_eq!(cfg.proxies.len(), 1);
    assert_eq!(cfg.proxies[0].id, "p1");
}

/// Mixed incremental mutations must replace by ID, append new IDs, and remove
/// deleted IDs across every runtime config vector without duplicating stale
/// entries.
#[tokio::test(flavor = "multi_thread")]
async fn apply_incremental_mixed_resource_mutations_are_atomic() {
    let initial_config = GatewayConfig {
        proxies: vec![test_proxy("p1", "/one"), test_proxy("p2", "/two")],
        consumers: vec![test_consumer("c1", "alice"), test_consumer("c2", "bob")],
        plugin_configs: vec![
            test_plugin_config("pc1", true),
            test_plugin_config("pc2", true),
        ],
        upstreams: vec![
            test_upstream("u1", "old.example.test", 8080),
            test_upstream("u2", "remove.example.test", 8080),
        ],
        loaded_at: Utc::now(),
        ..GatewayConfig::default()
    };
    let state = proxy_state_with_config(initial_config);

    let mut p1 = test_proxy("p1", "/one-updated");
    p1.backend_port = 4001;
    let p3 = test_proxy("p3", "/three");
    let mut c1 = test_consumer("c1", "alice-updated");
    c1.acl_groups = vec!["paid".to_string()];
    let mut pc1 = test_plugin_config("pc1", false);
    pc1.priority_override = Some(50);
    let u1 = test_upstream("u1", "new.example.test", 9090);
    let poll_timestamp = Utc::now();
    let delta = IncrementalResult {
        added_or_modified_proxies: vec![p1, p3],
        removed_proxy_ids: vec!["p2".to_string()],
        added_or_modified_consumers: vec![c1],
        removed_consumer_ids: vec![NamespacedResourceId::new("ferrum", "c2")],
        added_or_modified_plugin_configs: vec![pc1],
        removed_plugin_config_ids: vec!["pc2".to_string()],
        added_or_modified_upstreams: vec![u1],
        removed_upstream_ids: vec!["u2".to_string()],
        sequence_cursor: 0,
        poll_timestamp,
    };

    let result = state.apply_incremental(delta).await;
    assert_eq!(result, ConfigApplyOutcome::Applied);

    let cfg = state.config.load();
    assert_eq!(cfg.loaded_at, poll_timestamp);
    assert_eq!(cfg.proxies.len(), 2);
    assert!(cfg.proxies.iter().all(|proxy| proxy.id != "p2"));
    let p1 = cfg
        .proxies
        .iter()
        .find(|proxy| proxy.id == "p1")
        .expect("p1 should be modified in place");
    assert_eq!(p1.listen_path.as_deref(), Some("/one-updated"));
    assert_eq!(p1.backend_port, 4001);
    assert!(cfg.proxies.iter().any(|proxy| proxy.id == "p3"));

    assert_eq!(cfg.consumers.len(), 1);
    assert_eq!(cfg.consumers[0].id, "c1");
    assert_eq!(cfg.consumers[0].username, "alice-updated");
    assert_eq!(cfg.consumers[0].acl_groups, vec!["paid".to_string()]);

    assert_eq!(cfg.plugin_configs.len(), 1);
    assert_eq!(cfg.plugin_configs[0].id, "pc1");
    assert!(!cfg.plugin_configs[0].enabled);
    assert_eq!(cfg.plugin_configs[0].priority_override, Some(50));

    assert_eq!(cfg.upstreams.len(), 1);
    assert_eq!(cfg.upstreams[0].id, "u1");
    assert_eq!(cfg.upstreams[0].targets[0].host, "new.example.test");
    assert_eq!(cfg.upstreams[0].targets[0].port, 9090);
}

#[tokio::test(flavor = "multi_thread")]
async fn apply_incremental_consumer_keys_include_namespace() {
    let mut prod = test_consumer("c1", "prod-user");
    prod.namespace = "prod".to_string();
    let mut staging = test_consumer("c1", "staging-user");
    staging.namespace = "staging".to_string();
    let state = proxy_state_with_config(GatewayConfig {
        consumers: vec![prod, staging],
        ..GatewayConfig::default()
    });
    let mut updated_staging = test_consumer("c1", "updated-staging-user");
    updated_staging.namespace = "staging".to_string();
    let delta = IncrementalResult {
        added_or_modified_proxies: vec![],
        removed_proxy_ids: vec![],
        added_or_modified_consumers: vec![updated_staging],
        removed_consumer_ids: vec![NamespacedResourceId::new("staging", "c1")],
        added_or_modified_plugin_configs: vec![],
        removed_plugin_config_ids: vec![],
        added_or_modified_upstreams: vec![],
        removed_upstream_ids: vec![],
        sequence_cursor: 1,
        poll_timestamp: Utc::now(),
    };

    assert_eq!(
        state.apply_incremental(delta).await,
        ConfigApplyOutcome::Applied
    );
    let config = state.config.load();
    assert_eq!(config.consumers.len(), 2);
    assert!(
        config
            .consumers
            .iter()
            .any(|consumer| consumer.namespace == "prod" && consumer.username == "prod-user")
    );
    assert!(config.consumers.iter().any(|consumer| {
        consumer.namespace == "staging" && consumer.username == "updated-staging-user"
    }));
}

/// Two proxies sharing a non-regex `listen_path` violate
/// `validate_unique_listen_paths` and the patch is rejected. The returned
/// outcome must be `Rejected` so the polling loop can leave `last_poll_at`
/// untouched.
#[tokio::test(flavor = "multi_thread")]
async fn apply_incremental_rejected_returns_rejected_variant() {
    let state = empty_proxy_state();

    // Build a delta that violates uniqueness: two proxies with the same
    // `listen_path` and overlapping (empty/catch-all) `hosts`.
    let mut p1 = test_proxy("p1", "/dup");
    let mut p2 = test_proxy("p2", "/dup");
    p1.hosts = vec![];
    p2.hosts = vec![];

    let delta = IncrementalResult {
        added_or_modified_proxies: vec![p1, p2],
        removed_proxy_ids: vec![],
        added_or_modified_consumers: vec![],
        removed_consumer_ids: vec![],
        added_or_modified_plugin_configs: vec![],
        removed_plugin_config_ids: vec![],
        added_or_modified_upstreams: vec![],
        removed_upstream_ids: vec![],
        sequence_cursor: 0,
        poll_timestamp: Utc::now(),
    };

    let result = state.apply_incremental(delta).await;
    assert!(matches!(result, ConfigApplyOutcome::Rejected { .. }));

    // Critical: the in-memory config must remain unchanged on rejection.
    assert!(
        state.config.load().proxies.is_empty(),
        "rejected delta must not be partially applied"
    );
}

/// Reproduces the polling-loop cursor logic from `src/modes/database.rs` and
/// asserts that:
///   - `Applied` advances `last_poll_at`.
///   - `Unchanged` advances `last_poll_at`.
///   - `Rejected` leaves `last_poll_at` unchanged (so the next poll's
///     `since` parameter equals the prior `last_poll_at`, meaning the
///     rejected rows will be re-fetched).
///
/// Without the fix, `last_poll_at` advanced unconditionally and the
/// `since_safe = since - 1s` margin was insufficient to re-fetch a rejected
/// resource whose `updated_at` was older than that one-second window, so the
/// rejected row silently disappeared from the gateway's view of the DB.
#[tokio::test(flavor = "multi_thread")]
async fn polling_cursor_only_advances_on_applied_or_unchanged() {
    let state = empty_proxy_state();

    // ------ Cycle 1: rejected delta. ------
    let cursor_before = Utc::now() - Duration::seconds(60);
    let mut last_poll_at = Some(cursor_before);

    let mut p1 = test_proxy("p1", "/dup");
    let mut p2 = test_proxy("p2", "/dup");
    p1.hosts = vec![];
    p2.hosts = vec![];
    let rejected_ts = Utc::now();
    let rejected_delta = IncrementalResult {
        added_or_modified_proxies: vec![p1, p2],
        removed_proxy_ids: vec![],
        added_or_modified_consumers: vec![],
        removed_consumer_ids: vec![],
        added_or_modified_plugin_configs: vec![],
        removed_plugin_config_ids: vec![],
        added_or_modified_upstreams: vec![],
        removed_upstream_ids: vec![],
        sequence_cursor: 0,
        poll_timestamp: rejected_ts,
    };

    let outcome = state.apply_incremental(rejected_delta).await;
    assert!(matches!(outcome, ConfigApplyOutcome::Rejected { .. }));
    // Mirror the polling loop: advance only on Applied or Unchanged.
    match outcome {
        ConfigApplyOutcome::Applied | ConfigApplyOutcome::Unchanged => {
            last_poll_at = Some(rejected_ts);
        }
        ConfigApplyOutcome::Rejected { .. } => { /* intentionally do not advance */ }
    }
    assert_eq!(
        last_poll_at,
        Some(cursor_before),
        "Rejected outcome must NOT advance last_poll_at — the rejected rows \
         would otherwise fall outside the 1-second since_safe margin and \
         silently disappear from the gateway's view of the DB"
    );

    // ------ Cycle 2: empty delta. ------
    let empty_ts = Utc::now();
    let outcome = state.apply_incremental(empty_delta_at(empty_ts)).await;
    assert_eq!(outcome, ConfigApplyOutcome::Unchanged);
    match outcome {
        ConfigApplyOutcome::Applied | ConfigApplyOutcome::Unchanged => {
            last_poll_at = Some(empty_ts);
        }
        ConfigApplyOutcome::Rejected { .. } => {}
    }
    assert_eq!(
        last_poll_at,
        Some(empty_ts),
        "Unchanged must advance last_poll_at — there is no work to retry"
    );

    // ------ Cycle 3: applied delta. ------
    let applied_ts = Utc::now();
    let applied_delta = delta_with_proxy(test_proxy("p3", "/api/v3"), applied_ts);
    let outcome = state.apply_incremental(applied_delta).await;
    assert_eq!(outcome, ConfigApplyOutcome::Applied);
    match outcome {
        ConfigApplyOutcome::Applied | ConfigApplyOutcome::Unchanged => {
            last_poll_at = Some(applied_ts);
        }
        ConfigApplyOutcome::Rejected { .. } => {}
    }
    assert_eq!(
        last_poll_at,
        Some(applied_ts),
        "Applied must advance last_poll_at"
    );
    assert_eq!(state.config.load().proxies.len(), 1);
    assert_eq!(state.config.load().proxies[0].id, "p3");
}

// ============================================================================
// Stream listener reconcile trigger for upstream-only TLS changes
// ============================================================================

/// Generate a self-signed CA and a leaf cert/key signed by it with the given
/// SANs. Returns (ca_pem, leaf_cert_pem, leaf_key_pem).
fn generate_ca_and_leaf(ca_name: &str, sans: &[&str]) -> (String, String, String) {
    let ca_key =
        rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("generate CA key pair");
    let mut ca_params =
        rcgen::CertificateParams::new(Vec::<String>::new()).expect("CA certificate params");
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, ca_name);
    ca_params
        .key_usages
        .push(rcgen::KeyUsagePurpose::KeyCertSign);
    let ca_cert = ca_params
        .clone()
        .self_signed(&ca_key)
        .expect("self-signed CA");
    let ca_pem = ca_cert.pem();
    let issuer = rcgen::Issuer::new(ca_params, ca_key);

    let leaf_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
        .expect("generate leaf key pair");
    let san_strings: Vec<String> = sans.iter().map(|s| s.to_string()).collect();
    let leaf_params = rcgen::CertificateParams::new(san_strings).expect("leaf params");
    let leaf_cert = leaf_params
        .signed_by(&leaf_key, &issuer)
        .expect("sign leaf cert");
    (ca_pem, leaf_cert.pem(), leaf_key.serialize_pem())
}

/// Spawn a one-message TLS echo server presenting `cert_pem`/`key_pem`.
fn spawn_tls_echo_server(
    listener: tokio::net::TcpListener,
    cert_pem: &str,
    key_pem: &str,
) -> tokio::task::JoinHandle<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let certs: Vec<rustls::pki_types::CertificateDer<'static>> =
        rustls_pemfile::certs(&mut std::io::Cursor::new(cert_pem.as_bytes()))
            .collect::<Result<Vec<_>, _>>()
            .expect("parse echo server cert");
    let key = rustls_pemfile::private_key(&mut std::io::Cursor::new(key_pem.as_bytes()))
        .expect("parse echo server key")
        .expect("echo server key present");
    let server_config = rustls::ServerConfig::builder_with_provider(std::sync::Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .expect("echo server protocol versions")
    .with_no_client_auth()
    .with_single_cert(certs, key)
    .expect("echo server TLS config");
    let acceptor = tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(server_config));

    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                if let Ok(mut tls) = acceptor.accept(stream).await {
                    let mut buf = [0u8; 64];
                    if let Ok(n) = tls.read(&mut buf).await
                        && n > 0
                    {
                        let _ = tls.write_all(&buf[..n]).await;
                        let _ = tls.flush().await;
                    }
                    let _ = tls.shutdown().await;
                }
            });
        }
    })
}

/// Round-trip one message through the TCP+TLS stream proxy. Returns the echo
/// bytes (empty when the proxy closed the relay, e.g. backend TLS handshake
/// failure).
async fn relay_round_trip(proxy_port: u16) -> Vec<u8> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut client = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", proxy_port))
        .await
        .expect("connect to stream proxy frontend");
    // Tolerate write errors: when the backend TLS handshake fails the proxy
    // may have already closed the relay (broken pipe), which is exactly the
    // failure mode the empty-echo assertion captures.
    let _ = client.write_all(b"ping").await;
    let mut buf = Vec::new();
    let _ = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        client.read_to_end(&mut buf),
    )
    .await;
    buf
}

/// Regression test: an UPSTREAM-only TLS change must trigger stream listener
/// reconcile through `apply_incremental`.
///
/// A TCP+TLS stream proxy takes its backend trust (CA / client cert / verify)
/// from its referenced upstream via `resolved_tls`, and an upstream-only
/// update never marks the proxy itself modified (delta diffing is
/// `updated_at`-based). Without the upstream-change trigger, the listener's
/// cached backend `ClientConfig` keeps trusting the OLD CA forever.
///
/// Proof is end-to-end observable: the backend echo server presents a cert
/// signed by CA-B; the upstream initially trusts CA-A (relay dies at the
/// backend handshake), then an upstream-only delta switches trust to CA-B and
/// the relay must start echoing — which only happens if `apply_incremental`
/// reconciled and the restarted listener rebuilt its cached config.
#[tokio::test(flavor = "multi_thread")]
async fn apply_incremental_upstream_only_tls_change_reconciles_stream_listeners() {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let dir = tempfile::tempdir().expect("tempdir");
    let (ca_a_pem, _, _) = generate_ca_and_leaf("Upstream CA A", &["127.0.0.1"]);
    let (ca_b_pem, leaf_cert_pem, leaf_key_pem) =
        generate_ca_and_leaf("Upstream CA B", &["127.0.0.1", "localhost"]);
    let ca_a_path = dir.path().join("ca-a.pem");
    let ca_b_path = dir.path().join("ca-b.pem");
    std::fs::write(&ca_a_path, &ca_a_pem).expect("write ca a");
    std::fs::write(&ca_b_path, &ca_b_pem).expect("write ca b");

    // Backend: TLS echo server with a CA-B-signed cert.
    let backend_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind backend echo listener");
    let backend_port = backend_listener
        .local_addr()
        .expect("backend local addr")
        .port();
    let _echo = spawn_tls_echo_server(backend_listener, &leaf_cert_pem, &leaf_key_pem);

    // Frontend: ephemeral port for the stream proxy.
    let front = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("probe frontend port");
    let proxy_port = front.local_addr().expect("frontend local addr").port();
    drop(front);

    let mut upstream = test_upstream("u-tls", "127.0.0.1", backend_port);
    upstream.backend_tls_verify_server_cert = true;
    upstream.backend_tls_server_ca_cert_path =
        Some(ca_a_path.to_str().expect("utf-8 temp path").to_string());

    let mut proxy = test_proxy("p-tcp-tls", "/unused");
    proxy.listen_path = None;
    proxy.listen_port = Some(proxy_port);
    proxy.backend_scheme = Some(BackendScheme::Tcps);
    proxy.dispatch_kind = DispatchKind::from(BackendScheme::Tcps);
    proxy.upstream_id = Some("u-tls".to_string());

    let mut config = GatewayConfig {
        proxies: vec![proxy],
        upstreams: vec![upstream.clone()],
        loaded_at: Utc::now(),
        ..GatewayConfig::default()
    };
    config.normalize_fields();
    let state = proxy_state_with_config(config);

    state
        .initial_reconcile_stream_listeners()
        .await
        .expect("initial stream listener reconcile");
    state
        .stream_listener_manager
        .wait_until_started(std::time::Duration::from_secs(5))
        .await
        .expect("stream listener should bind");

    // With trust pinned to CA-A, the backend handshake (CA-B cert) fails and
    // the relay closes without echoing.
    let echoed = relay_round_trip(proxy_port).await;
    assert!(
        echoed.is_empty(),
        "relay should fail while the upstream trusts the wrong CA, got {:?}",
        echoed
    );

    // UPSTREAM-only delta: rotate trust to CA-B. The proxy row is untouched.
    let mut rotated_upstream = upstream;
    rotated_upstream.backend_tls_server_ca_cert_path =
        Some(ca_b_path.to_str().expect("utf-8 temp path").to_string());
    rotated_upstream.updated_at = Utc::now();
    let delta = IncrementalResult {
        added_or_modified_proxies: vec![],
        removed_proxy_ids: vec![],
        added_or_modified_consumers: vec![],
        removed_consumer_ids: vec![],
        added_or_modified_plugin_configs: vec![],
        removed_plugin_config_ids: vec![],
        added_or_modified_upstreams: vec![rotated_upstream],
        removed_upstream_ids: vec![],
        sequence_cursor: 0,
        poll_timestamp: Utc::now(),
    };
    let outcome = state.apply_incremental(delta).await;
    assert_eq!(outcome, ConfigApplyOutcome::Applied);

    state
        .stream_listener_manager
        .wait_until_started(std::time::Duration::from_secs(5))
        .await
        .expect("restarted stream listener should bind");

    let echoed = relay_round_trip(proxy_port).await;
    assert_eq!(
        echoed, b"ping",
        "upstream-only TLS change must reconcile the stream listener so the \
         restarted listener's cached backend TLS config trusts the new CA"
    );

    state.stream_listener_manager.shutdown_all().await;
}
