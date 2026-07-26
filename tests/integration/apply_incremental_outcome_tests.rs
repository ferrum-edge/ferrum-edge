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

use std::{collections::HashMap, sync::Arc};

use base64::Engine;
use chrono::{Duration, Utc};

use ferrum_edge::config::db_loader::{IncrementalResult, NamespacedResourceId};
use ferrum_edge::config::file_loader::load_config_from_file;
use ferrum_edge::config::types::{
    AuthMode, BackendScheme, Consumer, DispatchKind, GatewayConfig, LoadBalancerAlgorithm,
    PluginConfig, PluginScope, Proxy, Upstream, UpstreamTarget,
};
use ferrum_edge::dns::{DnsCache, DnsConfig};
use ferrum_edge::plugins::{PluginResult, ProxyProtocol, REQUEST_ID_METADATA_KEY, RequestContext};
use ferrum_edge::proxy::{ConfigApplyOutcome, ProxyState};
use tempfile::TempDir;

const COUNTRY_MMDB_B64: &str = include_str!("../fixtures/maxmind/GeoIP2-Country-Test.mmdb.b64");

fn country_mmdb_bytes() -> Vec<u8> {
    let encoded: String = COUNTRY_MMDB_B64.lines().collect();
    base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .expect("MaxMind fixture base64 decodes")
}

fn country_mmdb_with_country(replacement: &[u8; 2]) -> Vec<u8> {
    let mut bytes = country_mmdb_bytes();
    let mut replacements = 0;
    for offset in 0..bytes.len().saturating_sub(1) {
        if &bytes[offset..offset + 2] == b"SE" {
            bytes[offset..offset + 2].copy_from_slice(replacement);
            replacements += 1;
        }
    }
    assert!(replacements > 0, "fixture contains the SE country code");
    bytes
}

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
    proxy_state_with_config_and_mode(config, ferrum_edge::config::env_config::OperatingMode::File)
}

fn proxy_state_with_config_and_mode(
    config: GatewayConfig,
    mode: ferrum_edge::config::env_config::OperatingMode,
) -> ProxyState {
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
    let mut env_config = test_env_config();
    env_config.mode = mode;
    let (state, _health_check_handles) =
        ProxyState::new(config, dns_cache, env_config, None, None).unwrap();
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

fn delta_with_plugin(
    plugin_config: PluginConfig,
    poll_timestamp: chrono::DateTime<Utc>,
) -> IncrementalResult {
    IncrementalResult {
        added_or_modified_proxies: vec![],
        removed_proxy_ids: vec![],
        added_or_modified_consumers: vec![],
        removed_consumer_ids: vec![],
        added_or_modified_plugin_configs: vec![plugin_config],
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
#[serial_test::serial(country_mmdb_validation_handoff)]
async fn update_config_applies_accepted_mmdb_only_reload_without_config_delta() {
    let directory = TempDir::new().unwrap();
    let mmdb_path = directory.path().join("country.mmdb");
    let config_path = directory.path().join("ferrum.json");
    let original_bytes = country_mmdb_bytes();
    std::fs::write(&mmdb_path, &original_bytes).unwrap();

    let config = GatewayConfig {
        version: ferrum_edge::config::types::CURRENT_CONFIG_VERSION.to_string(),
        proxies: vec![test_proxy("geo-proxy", "/geo")],
        plugin_configs: vec![
            PluginConfig {
                id: "geo-policy".to_string(),
                namespace: ferrum_edge::config::types::default_namespace(),
                plugin_name: "geo_restriction".to_string(),
                config: serde_json::json!({
                    "db_path": mmdb_path.to_str().unwrap(),
                    "deny_countries": ["SE"],
                    "on_lookup_failure": "deny"
                }),
                scope: PluginScope::Global,
                proxy_id: None,
                enabled: true,
                priority_override: None,
                api_spec_id: None,
                created_at: Utc::now(),
                updated_at: Utc::now(),
            },
            test_plugin_config("unrelated-logging", true),
        ],
        loaded_at: Utc::now(),
        ..GatewayConfig::default()
    };
    std::fs::write(&config_path, serde_json::to_vec(&config).unwrap()).unwrap();
    let load = || {
        load_config_from_file(
            config_path.to_str().unwrap(),
            30,
            &ferrum_edge::config::BackendEgressPolicy::unrestricted(),
            "ferrum",
        )
        .unwrap()
    };

    let state = proxy_state_with_config(load());
    let plugins = state
        .plugin_cache
        .request_view("geo-proxy", ProxyProtocol::Http)
        .plugins();
    let geo = plugins
        .iter()
        .find(|plugin| plugin.name() == "geo_restriction")
        .unwrap();
    let unrelated_before = plugins
        .iter()
        .find(|plugin| plugin.name() == "stdout_logging")
        .cloned()
        .unwrap();
    let mut before = RequestContext::new(
        "89.160.20.112".to_string(),
        "GET".to_string(),
        "/geo".to_string(),
    );
    assert!(matches!(
        geo.on_request_received(&mut before).await,
        PluginResult::Reject {
            status_code: 403,
            ..
        }
    ));

    let replacement_bytes = country_mmdb_with_country(b"US");
    assert_eq!(replacement_bytes.len(), original_bytes.len());
    std::fs::write(&mmdb_path, replacement_bytes).unwrap();
    assert_eq!(state.update_config(load()), ConfigApplyOutcome::Applied);

    let plugins = state
        .plugin_cache
        .request_view("geo-proxy", ProxyProtocol::Http)
        .plugins();
    let geo = plugins
        .iter()
        .find(|plugin| plugin.name() == "geo_restriction")
        .unwrap();
    let unrelated_after = plugins
        .iter()
        .find(|plugin| plugin.name() == "stdout_logging")
        .unwrap();
    assert!(std::sync::Arc::ptr_eq(&unrelated_before, unrelated_after));
    let mut after = RequestContext::new(
        "89.160.20.112".to_string(),
        "GET".to_string(),
        "/geo".to_string(),
    );
    assert!(matches!(
        geo.on_request_received(&mut after).await,
        PluginResult::Continue
    ));
}

#[tokio::test(flavor = "multi_thread")]
#[serial_test::serial(country_mmdb_validation_handoff)]
async fn incremental_preloads_geo_for_adaptive_route_rebuild_scope_expansion() {
    let directory = TempDir::new().unwrap();
    let mmdb_path = directory.path().join("country.mmdb");
    std::fs::write(&mmdb_path, country_mmdb_bytes()).unwrap();

    let mut p1 = test_proxy("adaptive-route-1", "/one");
    let mut p2 = test_proxy("adaptive-route-2", "/two");
    p2.plugins.push(
        serde_json::from_value(serde_json::json!({"plugin_config_id": "geo-policy"})).unwrap(),
    );
    let config = GatewayConfig {
        version: ferrum_edge::config::types::CURRENT_CONFIG_VERSION.to_string(),
        proxies: vec![p1.clone(), p2],
        plugin_configs: vec![
            PluginConfig {
                id: "adaptive-policy".to_string(),
                namespace: ferrum_edge::config::types::default_namespace(),
                plugin_name: "adaptive_concurrency".to_string(),
                config: serde_json::json!({
                    "min_limit": 1,
                    "initial_limit": 2,
                    "max_limit": 2,
                    "shadow_mode": true
                }),
                scope: PluginScope::Global,
                proxy_id: None,
                enabled: true,
                priority_override: None,
                api_spec_id: None,
                created_at: Utc::now(),
                updated_at: Utc::now(),
            },
            PluginConfig {
                id: "geo-policy".to_string(),
                namespace: ferrum_edge::config::types::default_namespace(),
                plugin_name: "geo_restriction".to_string(),
                config: serde_json::json!({
                    "db_path": mmdb_path.to_str().unwrap(),
                    "deny_countries": ["SE"],
                    "on_lookup_failure": "allow"
                }),
                scope: PluginScope::Proxy,
                proxy_id: Some("adaptive-route-2".to_string()),
                enabled: true,
                priority_override: None,
                api_spec_id: None,
                created_at: Utc::now(),
                updated_at: Utc::now(),
            },
        ],
        loaded_at: Utc::now(),
        ..GatewayConfig::default()
    };
    let state = proxy_state_with_config(config);

    // Only proxy 1 appears in the prospective ConfigDelta. Its destination
    // change alters the global adaptive-concurrency route definition, which
    // expands the actual plugin rebuild scope to every proxy, including proxy
    // 2's geo policy. Remove the file so the accepted off-thread handoff must
    // carry a lookup-failure result; a synchronous fallback is forbidden by
    // the incremental build session and would reject this update.
    std::fs::remove_file(&mmdb_path).unwrap();
    p1.backend_host = "replacement.local".to_string();
    p1.updated_at = Utc::now() + Duration::milliseconds(1);
    let outcome = state
        .apply_incremental(delta_with_proxy(p1, Utc::now()))
        .await;
    assert_eq!(outcome, ConfigApplyOutcome::Applied);

    let plugins = state
        .plugin_cache
        .request_view("adaptive-route-2", ProxyProtocol::Http)
        .plugins();
    let geo = plugins
        .iter()
        .find(|plugin| plugin.name() == "geo_restriction")
        .unwrap();
    let mut request = RequestContext::new(
        "89.160.20.112".to_string(),
        "GET".to_string(),
        "/two".to_string(),
    );
    assert!(matches!(
        geo.on_request_received(&mut request).await,
        PluginResult::Continue
    ));
}

#[tokio::test(flavor = "multi_thread")]
#[serial_test::serial(country_mmdb_validation_handoff)]
async fn incremental_preloaded_geo_handoff_normalizes_padded_db_path() {
    let directory = TempDir::new().unwrap();
    let mmdb_path = directory.path().join("country.mmdb");
    std::fs::write(&mmdb_path, country_mmdb_bytes()).unwrap();
    let padded_path = format!("  {}\t", mmdb_path.to_str().unwrap());

    let mut proxy = test_proxy("geo-proxy", "/geo");
    proxy.plugins.push(
        serde_json::from_value(serde_json::json!({"plugin_config_id": "geo-policy"})).unwrap(),
    );
    let geo_policy = PluginConfig {
        id: "geo-policy".to_string(),
        namespace: ferrum_edge::config::types::default_namespace(),
        plugin_name: "geo_restriction".to_string(),
        config: serde_json::json!({
            "db_path": padded_path,
            "deny_countries": ["US"],
            "on_lookup_failure": "deny"
        }),
        scope: PluginScope::Proxy,
        proxy_id: Some(proxy.id.clone()),
        enabled: true,
        priority_override: None,
        api_spec_id: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };
    let state = proxy_state_with_config(GatewayConfig {
        version: ferrum_edge::config::types::CURRENT_CONFIG_VERSION.to_string(),
        proxies: vec![proxy],
        plugin_configs: vec![geo_policy.clone()],
        loaded_at: Utc::now(),
        ..GatewayConfig::default()
    });

    let mut updated_policy = geo_policy;
    updated_policy.config["deny_countries"] = serde_json::json!(["SE"]);
    updated_policy.updated_at = Utc::now() + Duration::milliseconds(1);
    assert_eq!(
        state
            .apply_incremental(delta_with_plugin(updated_policy, Utc::now()))
            .await,
        ConfigApplyOutcome::Applied,
        "the incremental PreloadedOnly cache stage must claim the trimmed validation handoff"
    );

    let plugins = state
        .plugin_cache
        .request_view("geo-proxy", ProxyProtocol::Http)
        .plugins();
    let geo = plugins
        .iter()
        .find(|plugin| plugin.name() == "geo_restriction")
        .unwrap();
    let mut request = RequestContext::new(
        "89.160.20.112".to_string(),
        "GET".to_string(),
        "/geo".to_string(),
    );
    assert!(matches!(
        geo.on_request_received(&mut request).await,
        PluginResult::Reject {
            status_code: 403,
            ..
        }
    ));
}

#[tokio::test(flavor = "multi_thread")]
#[serial_test::serial(country_mmdb_validation_handoff)]
async fn incremental_geo_refresh_preserves_out_of_scope_policy_snapshot() {
    let directory = TempDir::new().unwrap();
    let first_mmdb_path = directory.path().join("first.mmdb");
    let second_mmdb_path = directory.path().join("second.mmdb");
    std::fs::write(&first_mmdb_path, country_mmdb_bytes()).unwrap();
    std::fs::write(&second_mmdb_path, country_mmdb_bytes()).unwrap();

    let mut first_proxy = test_proxy("first-geo-proxy", "/first");
    first_proxy.plugins.push(
        serde_json::from_value(serde_json::json!({"plugin_config_id": "first-geo-policy"}))
            .unwrap(),
    );
    let mut second_proxy = test_proxy("second-geo-proxy", "/second");
    second_proxy.plugins.push(
        serde_json::from_value(serde_json::json!({"plugin_config_id": "second-geo-policy"}))
            .unwrap(),
    );
    let first_policy = PluginConfig {
        id: "first-geo-policy".to_string(),
        namespace: ferrum_edge::config::types::default_namespace(),
        plugin_name: "geo_restriction".to_string(),
        config: serde_json::json!({
            "db_path": first_mmdb_path.to_str().unwrap(),
            "deny_countries": ["US"],
            "on_lookup_failure": "deny"
        }),
        scope: PluginScope::Proxy,
        proxy_id: Some(first_proxy.id.clone()),
        enabled: true,
        priority_override: None,
        api_spec_id: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };
    let second_policy = PluginConfig {
        id: "second-geo-policy".to_string(),
        namespace: ferrum_edge::config::types::default_namespace(),
        plugin_name: "geo_restriction".to_string(),
        config: serde_json::json!({
            "db_path": second_mmdb_path.to_str().unwrap(),
            "deny_countries": ["SE"],
            "on_lookup_failure": "deny"
        }),
        scope: PluginScope::Proxy,
        proxy_id: Some(second_proxy.id.clone()),
        enabled: true,
        priority_override: None,
        api_spec_id: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };
    let state = proxy_state_with_config(GatewayConfig {
        version: ferrum_edge::config::types::CURRENT_CONFIG_VERSION.to_string(),
        proxies: vec![first_proxy, second_proxy],
        plugin_configs: vec![first_policy.clone(), second_policy],
        loaded_at: Utc::now(),
        ..GatewayConfig::default()
    });
    let unaffected_before = state
        .plugin_cache
        .request_view("second-geo-proxy", ProxyProtocol::Http)
        .plugins()
        .iter()
        .find(|plugin| plugin.name() == "geo_restriction")
        .cloned()
        .unwrap();

    std::fs::write(&second_mmdb_path, b"corrupt replacement").unwrap();
    let mut updated_first_policy = first_policy;
    updated_first_policy.config["deny_countries"] = serde_json::json!(["SE"]);
    updated_first_policy.updated_at = Utc::now() + Duration::milliseconds(1);
    assert_eq!(
        state
            .apply_incremental(delta_with_plugin(updated_first_policy, Utc::now()))
            .await,
        ConfigApplyOutcome::Applied,
        "an out-of-scope corrupt MMDB must not reject another geo policy's delta"
    );

    let selected_plugins = state
        .plugin_cache
        .request_view("first-geo-proxy", ProxyProtocol::Http)
        .plugins();
    let selected_after = selected_plugins
        .iter()
        .find(|plugin| plugin.name() == "geo_restriction")
        .unwrap();
    let mut selected_request = RequestContext::new(
        "89.160.20.112".to_string(),
        "GET".to_string(),
        "/first".to_string(),
    );
    assert!(matches!(
        selected_after
            .on_request_received(&mut selected_request)
            .await,
        PluginResult::Reject {
            status_code: 403,
            ..
        }
    ));

    let plugins = state
        .plugin_cache
        .request_view("second-geo-proxy", ProxyProtocol::Http)
        .plugins();
    let unaffected_after = plugins
        .iter()
        .find(|plugin| plugin.name() == "geo_restriction")
        .unwrap();
    assert!(std::sync::Arc::ptr_eq(&unaffected_before, unaffected_after));
    let mut request = RequestContext::new(
        "89.160.20.112".to_string(),
        "GET".to_string(),
        "/second".to_string(),
    );
    assert!(matches!(
        unaffected_after.on_request_received(&mut request).await,
        PluginResult::Reject {
            status_code: 403,
            ..
        }
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn dp_full_snapshots_refresh_mmdb_with_and_without_serialized_delta() {
    let directory = TempDir::new().unwrap();
    let mmdb_path = directory.path().join("country.mmdb");
    let config = GatewayConfig {
        version: ferrum_edge::config::types::CURRENT_CONFIG_VERSION.to_string(),
        proxies: vec![test_proxy("geo-proxy", "/geo")],
        plugin_configs: vec![
            PluginConfig {
                id: "geo-policy".to_string(),
                namespace: ferrum_edge::config::types::default_namespace(),
                plugin_name: "geo_restriction".to_string(),
                config: serde_json::json!({
                    "db_path": mmdb_path.to_str().unwrap(),
                    "deny_countries": ["SE"],
                    "on_lookup_failure": "allow"
                }),
                scope: PluginScope::Global,
                proxy_id: None,
                enabled: true,
                priority_override: None,
                api_spec_id: None,
                created_at: Utc::now(),
                updated_at: Utc::now(),
            },
            test_plugin_config("unrelated-logging", true),
        ],
        loaded_at: Utc::now(),
        ..GatewayConfig::default()
    };
    let mut candidate = config.clone();
    candidate
        .consumers
        .push(test_consumer("unrelated-consumer", "unrelated-user"));
    let state = proxy_state_with_config_and_mode(
        config,
        ferrum_edge::config::env_config::OperatingMode::DataPlane,
    );

    let plugins = state
        .plugin_cache
        .request_view("geo-proxy", ProxyProtocol::Http)
        .plugins();
    let geo = plugins
        .iter()
        .find(|plugin| plugin.name() == "geo_restriction")
        .unwrap();
    let unrelated_before = plugins
        .iter()
        .find(|plugin| plugin.name() == "stdout_logging")
        .cloned()
        .unwrap();
    let mut before = RequestContext::new(
        "89.160.20.112".to_string(),
        "GET".to_string(),
        "/geo".to_string(),
    );
    assert!(matches!(
        geo.on_request_received(&mut before).await,
        PluginResult::Continue
    ));

    std::fs::write(&mmdb_path, country_mmdb_bytes()).unwrap();
    assert_eq!(
        state.update_config(candidate.clone()),
        ConfigApplyOutcome::Applied,
        "a DP full snapshot with an unrelated delta must refresh node-local plugin files"
    );

    let plugins = state
        .plugin_cache
        .request_view("geo-proxy", ProxyProtocol::Http)
        .plugins();
    let geo = plugins
        .iter()
        .find(|plugin| plugin.name() == "geo_restriction")
        .unwrap();
    let unrelated_after_delta = plugins
        .iter()
        .find(|plugin| plugin.name() == "stdout_logging")
        .cloned()
        .unwrap();
    assert!(std::sync::Arc::ptr_eq(
        &unrelated_before,
        &unrelated_after_delta
    ));
    let mut after = RequestContext::new(
        "89.160.20.112".to_string(),
        "GET".to_string(),
        "/geo".to_string(),
    );
    assert!(matches!(
        geo.on_request_received(&mut after).await,
        PluginResult::Reject {
            status_code: 403,
            ..
        }
    ));
    let rejecting_geo_after_delta = Arc::clone(geo);

    std::fs::remove_file(&mmdb_path).unwrap();
    let mut missing_candidate = candidate.clone();
    missing_candidate.consumers.push(test_consumer(
        "second-unrelated-consumer",
        "second-unrelated-user",
    ));
    assert_eq!(
        state.update_config(missing_candidate),
        ConfigApplyOutcome::Applied,
        "an unrelated DP full snapshot must not replace a loaded MMDB with a missing fail-open plugin"
    );

    let plugins = state
        .plugin_cache
        .request_view("geo-proxy", ProxyProtocol::Http)
        .plugins();
    let geo = plugins
        .iter()
        .find(|plugin| plugin.name() == "geo_restriction")
        .unwrap();
    assert!(
        !Arc::ptr_eq(&rejecting_geo_after_delta, geo),
        "the refresh still rebuilds the instance from the incoming config; only the validated \
         snapshot is retained"
    );
    let mut after_missing_refresh = RequestContext::new(
        "89.160.20.112".to_string(),
        "GET".to_string(),
        "/geo".to_string(),
    );
    assert!(matches!(
        geo.on_request_received(&mut after_missing_refresh).await,
        PluginResult::Reject {
            status_code: 403,
            ..
        }
    ));

    std::fs::write(&mmdb_path, country_mmdb_with_country(b"US")).unwrap();
    assert_eq!(
        state.update_config(candidate),
        ConfigApplyOutcome::Applied,
        "an unchanged DP full snapshot must also refresh node-local plugin files"
    );

    let plugins = state
        .plugin_cache
        .request_view("geo-proxy", ProxyProtocol::Http)
        .plugins();
    let geo = plugins
        .iter()
        .find(|plugin| plugin.name() == "geo_restriction")
        .unwrap();
    let unrelated_after_no_delta = plugins
        .iter()
        .find(|plugin| plugin.name() == "stdout_logging")
        .unwrap();
    assert!(std::sync::Arc::ptr_eq(
        &unrelated_after_delta,
        unrelated_after_no_delta
    ));
    let mut after_replacement = RequestContext::new(
        "89.160.20.112".to_string(),
        "GET".to_string(),
        "/geo".to_string(),
    );
    assert!(matches!(
        geo.on_request_received(&mut after_replacement).await,
        PluginResult::Continue
    ));
}

/// A DP full snapshot that changes the geo policy while the node-local `.mmdb`
/// is temporarily unreadable must apply the *incoming* policy over the retained
/// last-known-good snapshot. Preserving the previous instance wholesale would
/// silently keep stale `allow_countries`/`deny_countries`/`on_lookup_failure`
/// while still reporting the update as `Applied`.
///
/// Retention is keyed on `db_path`, so a snapshot repointed at a different file
/// is never inherited: that instance falls back to `on_lookup_failure` exactly
/// as the documented first-load behavior does.
#[tokio::test(flavor = "multi_thread")]
async fn dp_full_snapshot_applies_new_geo_policy_over_retained_mmdb() {
    let directory = TempDir::new().unwrap();
    let mmdb_path = directory.path().join("country.mmdb");
    std::fs::write(&mmdb_path, country_mmdb_bytes()).unwrap();

    let geo_plugin_config = |config: serde_json::Value| PluginConfig {
        id: "geo-policy".to_string(),
        namespace: ferrum_edge::config::types::default_namespace(),
        plugin_name: "geo_restriction".to_string(),
        config,
        scope: PluginScope::Global,
        proxy_id: None,
        enabled: true,
        priority_override: None,
        api_spec_id: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };
    let geo_request = || {
        RequestContext::new(
            "89.160.20.112".to_string(),
            "GET".to_string(),
            "/geo".to_string(),
        )
    };
    let live_geo_plugin = |state: &ProxyState| {
        state
            .plugin_cache
            .request_view("geo-proxy", ProxyProtocol::Http)
            .plugins()
            .iter()
            .find(|plugin| plugin.name() == "geo_restriction")
            .cloned()
            .unwrap()
    };

    let config = GatewayConfig {
        version: ferrum_edge::config::types::CURRENT_CONFIG_VERSION.to_string(),
        proxies: vec![test_proxy("geo-proxy", "/geo")],
        plugin_configs: vec![geo_plugin_config(serde_json::json!({
            "db_path": mmdb_path.to_str().unwrap(),
            "deny_countries": ["SE"],
            "on_lookup_failure": "allow"
        }))],
        loaded_at: Utc::now(),
        ..GatewayConfig::default()
    };
    let state = proxy_state_with_config_and_mode(
        config.clone(),
        ferrum_edge::config::env_config::OperatingMode::DataPlane,
    );

    // The snapshot resolves 89.160.20.112 to SE, which the initial policy denies.
    let geo = live_geo_plugin(&state);
    assert!(matches!(
        geo.on_request_received(&mut geo_request()).await,
        PluginResult::Reject {
            status_code: 403,
            ..
        }
    ));

    // The file disappears and the policy simultaneously stops denying SE. The
    // retained snapshot still resolves the IP, but the *new* policy governs, so
    // the request is now allowed.
    std::fs::remove_file(&mmdb_path).unwrap();
    let mut repolicied = config.clone();
    repolicied.plugin_configs = vec![geo_plugin_config(serde_json::json!({
        "db_path": mmdb_path.to_str().unwrap(),
        "deny_countries": ["US"],
        "on_lookup_failure": "allow"
    }))];
    assert_eq!(
        state.update_config(repolicied.clone()),
        ConfigApplyOutcome::Applied
    );
    let geo = live_geo_plugin(&state);
    assert!(
        matches!(
            geo.on_request_received(&mut geo_request()).await,
            PluginResult::Continue
        ),
        "a geo policy change applied while the .mmdb was unavailable must take effect rather than \
         silently preserving the previous instance's deny list"
    );

    // Tightening the policy while the file is still unavailable must also take
    // effect: SE is denied again, resolved from the retained snapshot.
    let mut retightened = config.clone();
    retightened.plugin_configs = vec![geo_plugin_config(serde_json::json!({
        "db_path": mmdb_path.to_str().unwrap(),
        "deny_countries": ["SE"],
        "on_lookup_failure": "allow"
    }))];
    assert_eq!(
        state.update_config(retightened),
        ConfigApplyOutcome::Applied
    );
    let geo = live_geo_plugin(&state);
    assert!(matches!(
        geo.on_request_received(&mut geo_request()).await,
        PluginResult::Reject {
            status_code: 403,
            ..
        }
    ));

    // Repointing `db_path` at a different, absent file must not inherit the
    // retained snapshot: with no resolvable country the instance follows the
    // configured `on_lookup_failure` fallback, here `deny`.
    let repointed_path = directory.path().join("other-country.mmdb");
    let mut repointed = config.clone();
    repointed.plugin_configs = vec![geo_plugin_config(serde_json::json!({
        "db_path": repointed_path.to_str().unwrap(),
        "deny_countries": ["US"],
        "on_lookup_failure": "deny"
    }))];
    assert_eq!(state.update_config(repointed), ConfigApplyOutcome::Applied);
    let geo = live_geo_plugin(&state);
    assert!(
        matches!(
            geo.on_request_received(&mut geo_request()).await,
            PluginResult::Reject {
                status_code: 403,
                ..
            }
        ),
        "a repointed db_path must fall back to on_lookup_failure, never inherit the previous \
         file's snapshot"
    );

    // Once a file exists at the new path its own snapshot is adopted: the IP
    // resolves to SE again, which the repointed policy denies. Use
    // `on_lookup_failure: allow` so a 403 can only come from that successful SE
    // lookup — a reader-less miss would Continue instead.
    std::fs::write(&repointed_path, country_mmdb_bytes()).unwrap();
    let mut repointed_present = config.clone();
    repointed_present.plugin_configs = vec![geo_plugin_config(serde_json::json!({
        "db_path": repointed_path.to_str().unwrap(),
        "deny_countries": ["SE"],
        "on_lookup_failure": "allow"
    }))];
    assert_eq!(
        state.update_config(repointed_present),
        ConfigApplyOutcome::Applied
    );
    let geo = live_geo_plugin(&state);
    assert!(
        matches!(
            geo.on_request_received(&mut geo_request()).await,
            PluginResult::Reject {
                status_code: 403,
                ..
            }
        ),
        "a newly available repointed db_path must load its own snapshot; with \
         on_lookup_failure=allow, 403 proves SE was resolved rather than a \
         reader-less lookup failure"
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
async fn request_termination_invalid_reload_keeps_last_known_good_policy() {
    let state = empty_proxy_state();
    let mut plugin = test_plugin_config("termination-policy", true);
    plugin.plugin_name = "request_termination".to_string();
    plugin.config = serde_json::json!({
        "status_code": 451,
        "trigger": {"path_prefix": "/maintenance"}
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
            .any(|plugin| plugin.name() == "request_termination")
    );

    let mut invalid = valid;
    invalid.plugin_configs[0].config = serde_json::json!({
        "status_code": 451,
        "triger": {"path_prefix": "/must-not-publish"}
    });
    invalid.plugin_configs[0].updated_at += Duration::milliseconds(1);
    let outcome = state.update_config(invalid);
    let ConfigApplyOutcome::Rejected { errors } = outcome else {
        panic!("misspelled request_termination trigger must reject reload");
    };
    assert!(
        errors
            .iter()
            .any(|error| { error.contains("request_termination") && error.contains("triger") })
    );
    assert_eq!(
        state.config.load().plugin_configs[0].config["trigger"]["path_prefix"],
        "/maintenance"
    );
    assert!(
        state
            .plugin_cache
            .request_view("p1", ProxyProtocol::Http)
            .plugins()
            .iter()
            .any(|plugin| plugin.name() == "request_termination"),
        "rejected reload must retain the last-known-good termination policy"
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
async fn load_testing_unknown_key_reload_keeps_last_known_good_generation() {
    let state = empty_proxy_state();
    let mut plugin = test_plugin_config("load-testing-policy", true);
    plugin.plugin_name = "load_testing".to_string();
    plugin.config = serde_json::json!({
        "key": "stable-load-key-0123456789abcdef!",
        "concurrent_clients": 5,
        "duration_seconds": 10,
        "ramp": true
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
            .any(|plugin| plugin.name() == "load_testing")
    );

    let mut invalid = valid;
    invalid.plugin_configs[0].config = serde_json::json!({
        "key": "must-not-publish-load-key-0123456789!",
        "concurrent_clients": 50,
        "duration_seconds": 30,
        "rmap": true,
        "request_timeot_ms": 5000
    });
    invalid.plugin_configs[0].updated_at += Duration::milliseconds(1);
    let outcome = state.update_config(invalid);
    let ConfigApplyOutcome::Rejected { errors } = outcome else {
        panic!("unknown load_testing keys must reject reload");
    };
    assert!(errors.iter().any(|error| {
        error.contains("load_testing")
            && error.contains("unknown configuration key")
            && (error.contains("request_timeot_ms") || error.contains("rmap"))
    }));
    assert_eq!(
        state.config.load().plugin_configs[0].config["key"],
        "stable-load-key-0123456789abcdef!"
    );
    assert_eq!(state.config.load().plugin_configs[0].config["ramp"], true);
    assert!(
        state
            .plugin_cache
            .request_view("p1", ProxyProtocol::Http)
            .plugins()
            .iter()
            .any(|plugin| plugin.name() == "load_testing"),
        "rejected reload must retain the last-known-good load_testing generation"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn ai_stream_router_unknown_key_reload_keeps_last_known_good_policy() {
    let state = empty_proxy_state();
    let mut plugin = test_plugin_config("stream-router-policy", true);
    plugin.plugin_name = "ai_stream_router".to_string();
    plugin.config = serde_json::json!({
        "enabled": true,
        "providers": [{
            "name": "openai",
            "provider_type": "openai",
            "endpoint": "https://api.openai.com/v1/chat/completions",
            "api_key": "sk-last-known-good",
            "model_patterns": ["gpt-*"]
        }]
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
            .any(|plugin| plugin.name() == "ai_stream_router")
    );

    for (label, bad_config, needle) in [
        (
            "enabled-typo",
            serde_json::json!({
                "enabeld": false,
                "providers": [{
                    "name": "openai",
                    "provider_type": "openai",
                    "endpoint": "https://api.openai.com/v1/chat/completions",
                    "api_key": "sk-must-not-publish",
                    "model_patterns": ["gpt-*"]
                }]
            }),
            "config.enabeld",
        ),
        (
            "provider-typo",
            serde_json::json!({
                "providers": [{
                    "name": "openai",
                    "provider_type": "openai",
                    "endpoint": "https://api.openai.com/v1/chat/completions",
                    "api_key": "sk-must-not-publish",
                    "model_patterns": ["gpt-*"],
                    "inherit_backend_tl": true
                }]
            }),
            "config.providers[0].inherit_backend_tl",
        ),
        (
            "fallback-typo",
            serde_json::json!({
                "providers": [{
                    "name": "openai",
                    "provider_type": "openai",
                    "endpoint": "https://api.openai.com/v1/chat/completions",
                    "api_key": "sk-must-not-publish",
                    "model_patterns": ["gpt-*"]
                }],
                "fallback": {"on_connect_erro": true}
            }),
            "config.fallback.on_connect_erro",
        ),
    ] {
        let mut invalid = valid.clone();
        invalid.plugin_configs[0].config = bad_config;
        invalid.plugin_configs[0].updated_at += Duration::milliseconds(1);
        let ConfigApplyOutcome::Rejected { errors } = state.update_config(invalid) else {
            panic!("{label}: unknown ai_stream_router key must reject reload");
        };
        assert!(
            errors.iter().any(|error| {
                error.contains("ai_stream_router")
                    && error.contains("unknown configuration key")
                    && error.contains(needle)
            }),
            "{label}: unexpected rejection errors: {errors:?}"
        );
        assert_eq!(
            state.config.load().plugin_configs[0].config["providers"][0]["api_key"],
            "sk-last-known-good",
            "{label}: rejected candidate must not replace last-known-good config"
        );
        assert!(
            state
                .plugin_cache
                .request_view("p1", ProxyProtocol::Http)
                .plugins()
                .iter()
                .any(|plugin| plugin.name() == "ai_stream_router"),
            "{label}: rejected reload must retain last-known-good plugin cache"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn compression_unknown_key_reload_keeps_last_known_good_generation() {
    let state = empty_proxy_state();
    let mut plugin = test_plugin_config("compression-policy", true);
    plugin.plugin_name = "compression".to_string();
    plugin.config = serde_json::json!({
        "min_content_length": 512,
        "gzip_level": 4,
        "remove_accept_encoding": true
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
            .any(|plugin| plugin.name() == "compression")
    );

    let mut invalid = valid;
    invalid.plugin_configs[0].config = serde_json::json!({
        "min_content_lenght": 4096,
        "gzip_leveel": 1
    });
    invalid.plugin_configs[0].updated_at += Duration::milliseconds(1);
    let ConfigApplyOutcome::Rejected { errors } = state.update_config(invalid) else {
        panic!("unknown compression keys must reject database/CP-DP reload");
    };
    assert!(errors.iter().any(|error| {
        error.contains("config.gzip_leveel") && error.contains("config.min_content_lenght")
    }));
    assert_eq!(
        state.config.load().plugin_configs[0].config["min_content_length"],
        512
    );
    assert!(
        state
            .plugin_cache
            .request_view("p1", ProxyProtocol::Http)
            .plugins()
            .iter()
            .any(|plugin| plugin.name() == "compression"),
        "rejected reload must retain the last-known-good compression generation"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn correlation_id_invalid_reload_keeps_last_known_good_plugin_generation() {
    let state = empty_proxy_state();
    let mut internal = test_plugin_config("internal-request-id-policy", true);
    internal.plugin_name = "correlation_id".to_string();
    internal.priority_override = Some(40);
    internal.config = serde_json::json!({
        "header_name": "x-stable-request-id",
        "echo_downstream": true
    });
    let mut external = test_plugin_config("external-request-id-policy", true);
    external.plugin_name = "correlation_id".to_string();
    external.priority_override = Some(60);
    external.config = serde_json::json!({
        "header_name": "x-external-correlation-id",
        "echo_downstream": true
    });
    let valid = GatewayConfig {
        proxies: vec![test_proxy("p1", "/api")],
        plugin_configs: vec![internal, external],
        loaded_at: Utc::now(),
        ..GatewayConfig::default()
    };
    assert_eq!(
        state.update_config(valid.clone()),
        ConfigApplyOutcome::Applied
    );

    let mut invalid = valid.clone();
    invalid.plugin_configs[0].config = serde_json::json!({
        "header_name": "x-must-not-publish",
        "echo_downsteam": false
    });
    invalid.plugin_configs[0].updated_at += Duration::milliseconds(1);
    let ConfigApplyOutcome::Rejected { errors } = state.update_config(invalid) else {
        panic!("unknown correlation_id field must reject reload");
    };
    assert!(
        errors
            .iter()
            .any(|error| { error.contains("correlation_id") && error.contains("echo_downsteam") })
    );
    assert_eq!(
        state.config.load().plugin_configs[0].config["header_name"],
        "x-stable-request-id"
    );
    assert_eq!(
        state.config.load().plugin_configs[1].config["header_name"],
        "x-external-correlation-id"
    );

    let mut duplicate = valid.clone();
    duplicate.plugin_configs[1].config = serde_json::json!({
        "header_name": " X-Stable-Request-ID ",
        "echo_downstream": true
    });
    duplicate.plugin_configs[1].updated_at += Duration::milliseconds(1);
    let ConfigApplyOutcome::Rejected { errors } = state.update_config(duplicate) else {
        panic!("duplicate effective correlation header must reject reload");
    };
    assert!(errors.iter().any(|error| {
        error.contains("correlation_id") && error.contains("duplicate effective header_name")
    }));
    assert_eq!(
        state.config.load().plugin_configs[0].config["header_name"],
        "x-stable-request-id"
    );
    assert_eq!(
        state.config.load().plugin_configs[1].config["header_name"],
        "x-external-correlation-id"
    );

    let mut priority_tie = valid;
    priority_tie.plugin_configs[1].priority_override = Some(40);
    priority_tie.plugin_configs[1].updated_at += Duration::milliseconds(1);
    let ConfigApplyOutcome::Rejected { errors } = state.update_config(priority_tie) else {
        panic!("equal effective correlation priorities must reject reload");
    };
    assert!(errors.iter().any(|error| {
        error.contains("correlation_id") && error.contains("duplicate effective priority 40")
    }));
    assert_eq!(
        state.config.load().plugin_configs[0].priority_override,
        Some(40)
    );
    assert_eq!(
        state.config.load().plugin_configs[1].priority_override,
        Some(60)
    );

    let request_view = state.plugin_cache.request_view("p1", ProxyProtocol::Http);
    let request_plugins = request_view.plugins();
    let correlations: Vec<_> = request_plugins
        .iter()
        .filter(|plugin| plugin.name() == "correlation_id")
        .collect();
    assert_eq!(correlations.len(), 2);
    let mut ctx = RequestContext::new(
        "198.51.100.44".to_string(),
        "GET".to_string(),
        "/api".to_string(),
    );
    ctx.headers.insert(
        "x-external-correlation-id".to_string(),
        "attacker-preserved-id".to_string(),
    );
    for correlation in correlations {
        assert!(matches!(
            correlation.on_request_received(&mut ctx).await,
            PluginResult::Continue
        ));
    }
    let internal_id = ctx
        .headers
        .get("x-stable-request-id")
        .expect("last-known-good internal correlation header");
    assert!(uuid::Uuid::parse_str(internal_id).is_ok());
    assert_eq!(ctx.metadata.get(REQUEST_ID_METADATA_KEY), Some(internal_id));
    assert_eq!(
        ctx.headers
            .get("x-external-correlation-id")
            .map(String::as_str),
        Some("attacker-preserved-id")
    );
    assert!(!ctx.headers.contains_key("x-must-not-publish"));
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
async fn ai_tool_governor_unknown_key_reload_keeps_last_known_good_policy() {
    let state = empty_proxy_state();
    let mut plugin = test_plugin_config("tool-policy", true);
    plugin.plugin_name = "ai_tool_governor".to_string();
    plugin.config = serde_json::json!({
        "default_action": "deny",
        "tools": {
            "github.create_pr": {
                "action": "allow",
                "required_args": ["ticket_id"]
            }
        }
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
            .any(|plugin| plugin.name() == "ai_tool_governor")
    );

    let mut invalid = valid;
    invalid.plugin_configs[0].config = serde_json::json!({
        "default_action": "deny",
        "tools": {
            "github.create_pr": {
                "action": "allow",
                "required_arg": ["ticket_id"]
            }
        }
    });
    invalid.plugin_configs[0].updated_at += Duration::milliseconds(1);
    let ConfigApplyOutcome::Rejected { errors } = state.update_config(invalid) else {
        panic!("unknown ai_tool_governor tool-policy key must reject reload");
    };
    assert!(errors.iter().any(|error| {
        error.contains("ai_tool_governor")
            && error.contains("unknown configuration key")
            && error.contains("config.tools.github.create_pr.required_arg")
    }));
    assert_eq!(
        state.config.load().plugin_configs[0].config["tools"]["github.create_pr"]["required_args"],
        serde_json::json!(["ticket_id"])
    );
    assert!(
        state
            .plugin_cache
            .request_view("p1", ProxyProtocol::Http)
            .plugins()
            .iter()
            .any(|plugin| plugin.name() == "ai_tool_governor"),
        "rejected reload must retain the last-known-good plugin cache"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn grpc_web_typo_reload_keeps_last_known_good_expose_policy() {
    let state = empty_proxy_state();
    let mut plugin = test_plugin_config("grpc-web-policy", true);
    plugin.plugin_name = "grpc_web".to_string();
    plugin.config = serde_json::json!({
        "expose_headers": ["x-request-id", "custom-header-bin"]
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
            .any(|plugin| plugin.name() == "grpc_web"),
        "baseline cache must include grpc_web"
    );

    let mut invalid = valid;
    invalid.plugin_configs[0].config = serde_json::json!({
        "expose_header": ["x-must-not-publish"]
    });
    invalid.plugin_configs[0].updated_at += Duration::milliseconds(1);
    let ConfigApplyOutcome::Rejected { errors } = state.update_config(invalid) else {
        panic!("misspelled grpc_web expose_headers must reject reload");
    };
    assert!(errors.iter().any(|error| {
        error.contains("grpc_web")
            && error.contains("config.expose_header")
            && error.contains("did you mean 'expose_headers'")
    }));
    assert_eq!(
        state.config.load().plugin_configs[0].config,
        serde_json::json!({
            "expose_headers": ["x-request-id", "custom-header-bin"]
        })
    );
    assert!(
        state
            .plugin_cache
            .request_view("p1", ProxyProtocol::Http)
            .plugins()
            .iter()
            .any(|plugin| plugin.name() == "grpc_web"),
        "rejected reload must retain the last-known-good grpc_web generation"
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

#[tokio::test(flavor = "multi_thread")]
async fn ai_transcript_audit_unknown_key_reload_keeps_last_known_good_instance() {
    let state = empty_proxy_state();
    let mut plugin = test_plugin_config("ai-audit-policy", true);
    plugin.plugin_name = "ai_transcript_audit".to_string();
    plugin.config = serde_json::json!({
        "privacy": { "include_consumer_username": false },
        "sink": {
            "type": "http",
            "endpoint_url": "https://audit.example.com/ingest",
            "on_buffer_full": "reject",
            "on_sink_error": "reject"
        }
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
            .any(|plugin| plugin.name() == "ai_transcript_audit")
    );

    let mut invalid = valid;
    invalid.plugin_configs[0].config = serde_json::json!({
        "privacy": { "include_consumer_usernme": false },
        "sink": {
            "type": "http",
            "endpoint_url": "https://audit.example.com/must-not-publish",
            "on_buffer_ful": "reject",
            "on_sink_eror": "reject"
        }
    });
    invalid.plugin_configs[0].updated_at += Duration::milliseconds(1);
    let outcome = state.update_config(invalid);
    let ConfigApplyOutcome::Rejected { errors } = outcome else {
        panic!("unknown ai_transcript_audit keys must reject reload");
    };
    assert!(errors.iter().any(|error| {
        error.contains("ai_transcript_audit")
            && (error.contains("include_consumer_usernme")
                || error.contains("on_buffer_ful")
                || error.contains("on_sink_eror"))
    }));
    assert_eq!(
        state.config.load().plugin_configs[0].config["sink"]["endpoint_url"],
        "https://audit.example.com/ingest"
    );
    assert_eq!(
        state.config.load().plugin_configs[0].config["privacy"]["include_consumer_username"],
        false
    );
    assert!(
        state
            .plugin_cache
            .request_view("p1", ProxyProtocol::Http)
            .plugins()
            .iter()
            .any(|plugin| plugin.name() == "ai_transcript_audit"),
        "rejected reload must retain the last-known-good ai_transcript_audit instance"
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
        removed_proxy_ids: vec![NamespacedResourceId::new("ferrum", "p2")],
        added_or_modified_consumers: vec![c1],
        removed_consumer_ids: vec![NamespacedResourceId::new("ferrum", "c2")],
        added_or_modified_plugin_configs: vec![pc1],
        removed_plugin_config_ids: vec![NamespacedResourceId::new("ferrum", "pc2")],
        added_or_modified_upstreams: vec![u1],
        removed_upstream_ids: vec![NamespacedResourceId::new("ferrum", "u2")],
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

#[tokio::test(flavor = "multi_thread")]
async fn apply_incremental_proxy_upsert_keys_include_namespace() {
    let mut prod = test_proxy("shared", "/prod");
    prod.namespace = "prod".to_string();
    let mut staging = test_proxy("shared", "/staging");
    staging.namespace = "staging".to_string();
    let state = proxy_state_with_config(GatewayConfig {
        proxies: vec![prod, staging],
        ..GatewayConfig::default()
    });

    let mut updated_staging = test_proxy("shared", "/staging-updated");
    updated_staging.namespace = "staging".to_string();
    let delta = IncrementalResult {
        added_or_modified_proxies: vec![updated_staging],
        removed_proxy_ids: vec![],
        added_or_modified_consumers: vec![],
        removed_consumer_ids: vec![],
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
    assert_eq!(config.proxies.len(), 2);
    assert!(config.proxies.iter().any(|p| {
        p.namespace == "prod" && p.id == "shared" && p.listen_path.as_deref() == Some("/prod")
    }));
    assert!(config.proxies.iter().any(|p| {
        p.namespace == "staging"
            && p.id == "shared"
            && p.listen_path.as_deref() == Some("/staging-updated")
    }));
}

#[tokio::test(flavor = "multi_thread")]
async fn apply_incremental_plugin_config_upsert_keys_include_namespace() {
    let mut prod = test_plugin_config("shared-pc", true);
    prod.namespace = "prod".to_string();
    let mut staging = test_plugin_config("shared-pc", true);
    staging.namespace = "staging".to_string();
    let state = proxy_state_with_config(GatewayConfig {
        plugin_configs: vec![prod, staging],
        ..GatewayConfig::default()
    });

    let mut updated_staging = test_plugin_config("shared-pc", false);
    updated_staging.namespace = "staging".to_string();
    let delta = IncrementalResult {
        added_or_modified_proxies: vec![],
        removed_proxy_ids: vec![],
        added_or_modified_consumers: vec![],
        removed_consumer_ids: vec![],
        added_or_modified_plugin_configs: vec![updated_staging],
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
    assert_eq!(config.plugin_configs.len(), 2);
    assert!(
        config
            .plugin_configs
            .iter()
            .any(|pc| pc.namespace == "prod" && pc.id == "shared-pc" && pc.enabled)
    );
    assert!(
        config
            .plugin_configs
            .iter()
            .any(|pc| pc.namespace == "staging" && pc.id == "shared-pc" && !pc.enabled)
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn apply_incremental_upstream_upsert_keys_include_namespace() {
    let mut prod = test_upstream("shared-u", "prod.example.test", 8080);
    prod.namespace = "prod".to_string();
    let mut staging = test_upstream("shared-u", "staging.example.test", 8080);
    staging.namespace = "staging".to_string();
    let state = proxy_state_with_config(GatewayConfig {
        upstreams: vec![prod, staging],
        ..GatewayConfig::default()
    });

    let mut updated_staging = test_upstream("shared-u", "staging-updated.example.test", 9090);
    updated_staging.namespace = "staging".to_string();
    let delta = IncrementalResult {
        added_or_modified_proxies: vec![],
        removed_proxy_ids: vec![],
        added_or_modified_consumers: vec![],
        removed_consumer_ids: vec![],
        added_or_modified_plugin_configs: vec![],
        removed_plugin_config_ids: vec![],
        added_or_modified_upstreams: vec![updated_staging],
        removed_upstream_ids: vec![],
        sequence_cursor: 1,
        poll_timestamp: Utc::now(),
    };

    assert_eq!(
        state.apply_incremental(delta).await,
        ConfigApplyOutcome::Applied
    );
    let config = state.config.load();
    assert_eq!(config.upstreams.len(), 2);
    assert!(config.upstreams.iter().any(|u| {
        u.namespace == "prod"
            && u.id == "shared-u"
            && u.targets[0].host == "prod.example.test"
            && u.targets[0].port == 8080
    }));
    assert!(config.upstreams.iter().any(|u| {
        u.namespace == "staging"
            && u.id == "shared-u"
            && u.targets[0].host == "staging-updated.example.test"
            && u.targets[0].port == 9090
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
