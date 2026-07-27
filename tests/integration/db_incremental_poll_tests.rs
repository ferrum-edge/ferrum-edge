//! Integration tests for durable DB incremental polling.
//!
//! Incremental polling is driven by ordered `config_changes` records, not
//! wall-clock timestamps or full resource-ID scans. These tests exercise the
//! SQLite SQL path because the same `DatabaseStore` implementation is shared by
//! all SQL backends behind dialect-specific SQL rendering.

use chrono::Utc;
use ferrum_edge::config::db_backend::is_incremental_full_reload_required;
use ferrum_edge::config::db_loader::{DatabaseStore, DbPoolConfig};
use ferrum_edge::config::types::{
    AuthMode, BackendScheme, DispatchKind, LoadBalancerAlgorithm, PluginAssociation, PluginConfig,
    PluginScope, Proxy, Upstream, UpstreamTarget, default_namespace,
};
use serde_json::json;
use std::collections::HashMap;
use tempfile::TempDir;

async fn sqlite_store() -> (DatabaseStore, TempDir) {
    let temp_dir = TempDir::new().unwrap();
    let db_path = temp_dir.path().join("incremental_poll_test.db");
    let db_url = format!("sqlite:{}?mode=rwc", db_path.to_string_lossy());
    let store = DatabaseStore::connect_with_pool_config("sqlite", &db_url, DbPoolConfig::default())
        .await
        .expect("SQLite store creation must succeed");
    (store, temp_dir)
}

fn test_upstream(id: &str, host: &str, port: u16) -> Upstream {
    Upstream {
        id: id.to_string(),
        namespace: default_namespace(),
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

fn test_plugin_config(id: &str) -> PluginConfig {
    PluginConfig {
        id: id.to_string(),
        namespace: default_namespace(),
        plugin_name: "stdout_logging".to_string(),
        config: json!({}),
        scope: PluginScope::ProxyGroup,
        proxy_id: None,
        enabled: true,
        priority_override: None,
        api_spec_id: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

fn test_proxy(id: &str, listen_path: &str, plugins: Vec<PluginAssociation>) -> Proxy {
    Proxy {
        id: id.to_string(),
        namespace: default_namespace(),
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
        plugins,
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

#[tokio::test(flavor = "multi_thread")]
async fn incremental_poll_uses_durable_sequence_for_create_update_delete() {
    let (store, _temp_dir) = sqlite_store().await;
    let start_sequence = store
        .latest_change_sequence("ferrum")
        .await
        .expect("latest sequence must load");

    let mut upstream = test_upstream("sequence-upstream", "127.0.0.1", 8080);
    store
        .create_upstream(&upstream)
        .await
        .expect("upstream create must succeed");

    let created = store
        .load_incremental_config("ferrum", start_sequence)
        .await
        .expect("incremental create poll must succeed");
    assert_eq!(created.added_or_modified_upstreams.len(), 1);
    assert_eq!(
        created.added_or_modified_upstreams[0].id,
        "sequence-upstream"
    );
    assert!(created.removed_upstream_ids.is_empty());
    assert!(created.sequence_cursor > start_sequence);

    let replayed = store
        .load_incremental_config("ferrum", start_sequence)
        .await
        .expect("incremental replay must succeed");
    assert_eq!(replayed.sequence_cursor, created.sequence_cursor);
    assert_eq!(replayed.added_or_modified_upstreams.len(), 1);
    assert_eq!(
        replayed.added_or_modified_upstreams[0].id,
        "sequence-upstream"
    );

    upstream.targets[0].port = 9090;
    store
        .update_upstream(&upstream)
        .await
        .expect("upstream update must succeed");
    let updated = store
        .load_incremental_config("ferrum", created.sequence_cursor)
        .await
        .expect("incremental update poll must succeed");
    assert_eq!(updated.added_or_modified_upstreams.len(), 1);
    assert_eq!(updated.added_or_modified_upstreams[0].targets[0].port, 9090);
    assert!(updated.sequence_cursor > created.sequence_cursor);

    store
        .delete_upstream("ferrum", "sequence-upstream")
        .await
        .expect("upstream delete must succeed");
    let deleted = store
        .load_incremental_config("ferrum", updated.sequence_cursor)
        .await
        .expect("incremental delete poll must succeed");
    assert!(deleted.added_or_modified_upstreams.is_empty());
    assert_eq!(
        deleted.removed_upstream_ids,
        vec![ferrum_edge::config::db_loader::NamespacedResourceId::new(
            "ferrum",
            "sequence-upstream"
        )]
    );
    assert!(deleted.sequence_cursor > updated.sequence_cursor);
}

#[tokio::test(flavor = "multi_thread")]
async fn incremental_poll_does_not_scan_runtime_rows_without_change_records() {
    let (store, _temp_dir) = sqlite_store().await;
    let ts = Utc::now().to_rfc3339();

    sqlx::query(
        "INSERT INTO proxies \
         (id, namespace, name, hosts, listen_path, backend_scheme, backend_host, backend_port, created_at, updated_at) \
         VALUES ('raw-proxy', 'ferrum', 'raw proxy', '[]', '/raw-proxy', 'http', '127.0.0.1', 8080, ?, ?)",
    )
    .bind(&ts)
    .bind(&ts)
    .execute(&store.pool())
    .await
    .expect("raw proxy insert must succeed");

    sqlx::query(
        "INSERT INTO consumers (id, namespace, username, credentials, created_at, updated_at) \
         VALUES ('raw-consumer', 'ferrum', 'raw-consumer', '{}', ?, ?)",
    )
    .bind(&ts)
    .bind(&ts)
    .execute(&store.pool())
    .await
    .expect("raw consumer insert must succeed");

    sqlx::query(
        "INSERT INTO plugin_configs \
         (id, namespace, plugin_name, config, enabled, created_at, updated_at) \
         VALUES ('raw-plugin', 'ferrum', 'stdout_logging', '{}', 1, ?, ?)",
    )
    .bind(&ts)
    .bind(&ts)
    .execute(&store.pool())
    .await
    .expect("raw plugin insert must succeed");

    sqlx::query(
        "INSERT INTO upstreams \
         (id, namespace, name, targets, algorithm, created_at, updated_at) \
         VALUES ('raw-upstream', 'ferrum', 'raw', '[{\"host\":\"127.0.0.1\",\"port\":8080}]', 'round_robin', ?, ?)",
    )
    .bind(&ts)
    .bind(&ts)
    .execute(&store.pool())
    .await
    .expect("raw upstream insert must succeed");

    let result = store
        .load_incremental_config("ferrum", 0)
        .await
        .expect("incremental poll must succeed");
    assert!(
        result.is_empty(),
        "raw runtime rows without config_changes records must not be discovered by incremental polling"
    );
    assert_eq!(result.sequence_cursor, 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn non_consumer_delete_records_drive_removals_without_resource_row_scans() {
    let (store, _temp_dir) = sqlite_store().await;
    let ts = Utc::now().to_rfc3339();

    sqlx::query(
        "INSERT INTO config_changes \
         (sequence, namespace, resource_type, resource_id, operation, created_at) \
         VALUES \
             (1, 'ferrum', 'proxy', 'deleted-proxy', 'delete', ?), \
             (2, 'ferrum', 'plugin_config', 'deleted-plugin', 'delete', ?), \
             (3, 'ferrum', 'upstream', 'deleted-upstream', 'delete', ?)",
    )
    .bind(&ts)
    .bind(&ts)
    .bind(&ts)
    .execute(&store.pool())
    .await
    .expect("manual config_changes delete inserts must succeed");

    let result = store
        .load_incremental_config("ferrum", 0)
        .await
        .expect("delete-only incremental poll must succeed");

    assert_eq!(result.sequence_cursor, 3);
    assert_eq!(
        result.removed_proxy_ids,
        vec![ferrum_edge::config::db_loader::NamespacedResourceId::new(
            "ferrum",
            "deleted-proxy"
        )]
    );
    assert!(result.removed_consumer_ids.is_empty());
    assert_eq!(
        result.removed_plugin_config_ids,
        vec![ferrum_edge::config::db_loader::NamespacedResourceId::new(
            "ferrum",
            "deleted-plugin"
        )]
    );
    assert_eq!(
        result.removed_upstream_ids,
        vec![ferrum_edge::config::db_loader::NamespacedResourceId::new(
            "ferrum",
            "deleted-upstream"
        )]
    );
    assert!(result.added_or_modified_proxies.is_empty());
    assert!(result.added_or_modified_consumers.is_empty());
    assert!(result.added_or_modified_plugin_configs.is_empty());
    assert!(result.added_or_modified_upstreams.is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn global_change_sequence_survives_namespace_scope_shrink() {
    let (store, _temp_dir) = sqlite_store().await;
    let mut surviving = test_upstream("surviving", "127.0.0.1", 8080);
    surviving.namespace = "tenant-a".to_string();
    store
        .create_upstream(&surviving)
        .await
        .expect("surviving namespace write must succeed");
    let surviving_sequence = store
        .latest_change_sequence("tenant-a")
        .await
        .expect("surviving namespace sequence must load");

    let mut removed = test_upstream("removed", "127.0.0.1", 8081);
    removed.namespace = "tenant-b".to_string();
    store
        .create_upstream(&removed)
        .await
        .expect("removed namespace write must succeed");
    store
        .delete_upstream("tenant-b", "removed")
        .await
        .expect("removed namespace delete must succeed");

    let global_sequence = store
        .latest_global_change_sequence()
        .await
        .expect("store-wide sequence must load");
    assert!(
        global_sequence > surviving_sequence,
        "a restarted CP must retain the deleted namespace's newer generation"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn consumer_delete_requires_authoritative_reload_for_quarantine_rehydration() {
    let (store, _temp_dir) = sqlite_store().await;
    let ts = Utc::now().to_rfc3339();

    sqlx::query(
        "INSERT INTO config_changes \
         (sequence, namespace, resource_type, resource_id, operation, created_at) \
         VALUES (1, 'ferrum', 'consumer', 'deleted-consumer', 'delete', ?)",
    )
    .bind(&ts)
    .execute(&store.pool())
    .await
    .expect("manual consumer delete change insert must succeed");

    let error = match store.load_incremental_config("ferrum", 0).await {
        Ok(_) => panic!("consumer deletion must force an authoritative full reload"),
        Err(error) => error,
    };
    assert!(is_incremental_full_reload_required(&error));
    assert!(
        error
            .to_string()
            .contains("rehydrate quarantined credentials"),
        "consumer change escalation must explain the quarantine repair path: {error}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn association_additions_and_removals_are_proxy_change_events() {
    let (store, _temp_dir) = sqlite_store().await;
    let plugin = test_plugin_config("proxy-group-plugin");
    store
        .create_plugin_config(&plugin)
        .await
        .expect("plugin create must succeed");
    let mut proxy = test_proxy("association-proxy", "/association", vec![]);
    store
        .create_proxy(&proxy)
        .await
        .expect("proxy create must succeed");
    let seed_sequence = store
        .latest_change_sequence("ferrum")
        .await
        .expect("latest sequence must load after seed");

    proxy.plugins = vec![PluginAssociation {
        plugin_config_id: plugin.id.clone(),
    }];
    store
        .update_proxy(&proxy)
        .await
        .expect("proxy association add must succeed");

    let added = store
        .load_incremental_config("ferrum", seed_sequence)
        .await
        .expect("association add poll must succeed");
    let changed_proxy = added
        .added_or_modified_proxies
        .iter()
        .find(|proxy| proxy.id == "association-proxy")
        .expect("proxy association add must be represented by a proxy change");
    assert_eq!(changed_proxy.plugins.len(), 1);
    assert_eq!(
        changed_proxy.plugins[0].plugin_config_id,
        "proxy-group-plugin"
    );

    proxy.plugins.clear();
    store
        .update_proxy(&proxy)
        .await
        .expect("proxy association remove must succeed");
    let removed = store
        .load_incremental_config("ferrum", added.sequence_cursor)
        .await
        .expect("association removal poll must succeed");
    let changed_proxy = removed
        .added_or_modified_proxies
        .iter()
        .find(|proxy| proxy.id == "association-proxy")
        .expect("proxy association removal must be represented by a proxy change");
    assert!(changed_proxy.plugins.is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn sparse_global_sequence_gap_without_retention_still_polls_incrementally() {
    let (store, _temp_dir) = sqlite_store().await;
    let ts = Utc::now().to_rfc3339();

    sqlx::query(
        "INSERT INTO config_changes \
         (sequence, namespace, resource_type, resource_id, operation, created_at) \
         VALUES (10, 'ferrum', 'upstream', 'missing-upstream', 'delete', ?)",
    )
    .bind(&ts)
    .execute(&store.pool())
    .await
    .expect("manual config_changes insert must succeed");

    let result = store
        .load_incremental_config("ferrum", 1)
        .await
        .expect("sparse sequence gap without retention must not force full reload");
    assert_eq!(result.sequence_cursor, 10);
    assert_eq!(
        result.removed_upstream_ids,
        vec![ferrum_edge::config::db_loader::NamespacedResourceId::new(
            "ferrum",
            "missing-upstream"
        )]
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn retention_gap_reports_cursor_behind_retained_sequence() {
    let (store, _temp_dir) = sqlite_store().await;
    let ts = Utc::now().to_rfc3339();

    sqlx::query(
        "INSERT INTO config_change_retention (namespace, retained_sequence, updated_at) \
         VALUES ('ferrum', 10, ?)",
    )
    .bind(&ts)
    .execute(&store.pool())
    .await
    .expect("manual config_change_retention insert must succeed");

    let err = match store.load_incremental_config("ferrum", 1).await {
        Ok(_) => panic!("retention gap must force caller to full reload"),
        Err(err) => err,
    };
    let message = err.to_string();
    assert!(
        message.contains("behind retained sequence"),
        "retention gap error should explain the cursor problem, got: {message}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn saturated_change_log_batch_forces_full_reload_fallback() {
    let (store, _temp_dir) = sqlite_store().await;
    let ts = Utc::now().to_rfc3339();

    sqlx::query(
        "WITH digits(d) AS ( \
             VALUES(0),(1),(2),(3),(4),(5),(6),(7),(8),(9) \
         ), seq(n) AS ( \
             SELECT ones.d + tens.d * 10 + hundreds.d * 100 + thousands.d * 1000 + 1 \
             FROM digits AS ones \
             CROSS JOIN digits AS tens \
             CROSS JOIN digits AS hundreds \
             CROSS JOIN digits AS thousands \
         ) \
         INSERT INTO config_changes \
             (sequence, namespace, resource_type, resource_id, operation, created_at) \
         SELECT n, 'ferrum', 'upstream', 'upstream-' || n, 'delete', ? FROM seq",
    )
    .bind(&ts)
    .execute(&store.pool())
    .await
    .expect("manual saturated config_changes insert must succeed");

    let err = match store.load_incremental_config("ferrum", 0).await {
        Ok(_) => panic!("saturated change-log batch must force caller to full reload"),
        Err(err) => err,
    };
    let message = err.to_string();
    assert!(
        message.contains("reached limit") && message.contains("forcing full reload"),
        "saturated batch error should explain the full-reload fallback, got: {message}"
    );
}
