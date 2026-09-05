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
use ferrum_edge::proxy::stream_match::{StreamMatchArm, StreamMatchCriteria};
use serde_json::json;
use std::collections::{BTreeMap, HashMap};
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
        source_labels: Default::default(),
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
        k8s_service_uid: None,
        pending_limit_scope: None,
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
        trigger: None,
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
        backend_proxy_protocol: None,
        stream_match: None,
        compiled_stream_match: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
        pending_limit_scope: None,
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn sql_proxy_stream_match_round_trips_and_updates_without_widening() {
    let (store, _temp_dir) = sqlite_store().await;
    let start_sequence = store
        .latest_change_sequence("ferrum")
        .await
        .expect("latest sequence must load");
    let mut proxy = test_proxy("stream-match-round-trip", "/unused", Vec::new());
    proxy.listen_path = None;
    proxy.backend_scheme = Some(BackendScheme::Tcp);
    proxy.dispatch_kind = DispatchKind::TcpRaw;
    proxy.listen_port = Some(15432);
    proxy.stream_match = Some(StreamMatchCriteria {
        arms: vec![StreamMatchArm {
            source_labels: BTreeMap::from([("app".to_string(), "billing".to_string())]),
            source_subnets: vec!["10.0.0.0/8".to_string()],
            gateways: vec!["mesh".to_string()],
            ..Default::default()
        }],
    });
    let created_match = proxy.stream_match.clone();

    store
        .create_proxy(&proxy)
        .await
        .expect("proxy matcher create must persist");
    let created = store
        .get_proxy("ferrum", &proxy.id)
        .await
        .expect("created proxy matcher must decode")
        .expect("created proxy must exist");
    assert_eq!(created.stream_match, created_match);
    assert!(created.compiled_stream_match.is_some());

    let full = store
        .load_full_config("ferrum")
        .await
        .expect("full SQL config load must preserve matcher");
    assert_eq!(full.proxies[0].stream_match, created_match);
    assert!(full.proxies[0].compiled_stream_match.is_some());

    let created_delta = store
        .load_incremental_config("ferrum", start_sequence)
        .await
        .expect("incremental create must preserve matcher");
    assert_eq!(
        created_delta.added_or_modified_proxies[0].stream_match,
        created_match
    );
    assert!(
        created_delta.added_or_modified_proxies[0]
            .compiled_stream_match
            .is_some()
    );

    proxy.stream_match = Some(StreamMatchCriteria {
        arms: vec![StreamMatchArm {
            source_namespace: Some("payments".to_string()),
            destination_subnets: vec!["192.0.2.10/32".to_string()],
            gateways: vec!["istio-system/ingress".to_string()],
            ..Default::default()
        }],
    });
    proxy.updated_at = Utc::now();
    let updated_match = proxy.stream_match.clone();
    assert!(
        store
            .update_proxy(&proxy)
            .await
            .expect("proxy matcher update must persist")
    );
    let updated = store
        .get_proxy("ferrum", &proxy.id)
        .await
        .expect("updated proxy matcher must decode")
        .expect("updated proxy must exist");
    assert_eq!(updated.stream_match, updated_match);
    assert!(updated.compiled_stream_match.is_some());
    let updated_delta = store
        .load_incremental_config("ferrum", created_delta.sequence_cursor)
        .await
        .expect("incremental update must preserve matcher");
    assert_eq!(
        updated_delta.added_or_modified_proxies[0].stream_match,
        updated_match
    );

    sqlx::query("UPDATE proxies SET stream_match = ? WHERE id = ? AND namespace = ?")
        .bind("{not-json")
        .bind(&proxy.id)
        .bind(&proxy.namespace)
        .execute(&store.pool())
        .await
        .expect("corrupt matcher fixture update must succeed");
    let error = store
        .get_proxy("ferrum", &proxy.id)
        .await
        .expect_err("malformed persisted matcher must fail closed");
    assert!(
        error
            .to_string()
            .contains("failed to parse stream_match JSON")
    );
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

#[tokio::test(flavor = "multi_thread")]
async fn config_change_sequence_locks_are_per_namespace() {
    let (store, _temp_dir) = sqlite_store().await;
    let mut tenant_a = test_upstream("lock-a", "127.0.0.1", 8080);
    tenant_a.namespace = "tenant-a".to_string();
    let mut tenant_b = test_upstream("lock-b", "127.0.0.1", 8081);
    tenant_b.namespace = "tenant-b".to_string();
    store
        .create_upstream(&tenant_a)
        .await
        .expect("tenant-a write must succeed");
    store
        .create_upstream(&tenant_b)
        .await
        .expect("tenant-b write must succeed");

    let lock_names: Vec<String> =
        sqlx::query_scalar("SELECT lock_name FROM config_change_locks ORDER BY lock_name")
            .fetch_all(&store.pool())
            .await
            .expect("config_change_locks rows must load");
    assert_eq!(
        lock_names,
        vec!["tenant-a".to_string(), "tenant-b".to_string()],
        "each namespace must own its own sequence lock row, not a shared 'global' row"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn all_scope_sequence_is_the_sum_of_per_namespace_high_waters() {
    let (store, _temp_dir) = sqlite_store().await;
    let mut tenant_a = test_upstream("sum-a", "127.0.0.1", 8080);
    tenant_a.namespace = "tenant-a".to_string();
    store
        .create_upstream(&tenant_a)
        .await
        .expect("tenant-a write must succeed");
    let a_sequence = store
        .latest_change_sequence("tenant-a")
        .await
        .expect("tenant-a sequence must load");

    let mut tenant_b = test_upstream("sum-b", "127.0.0.1", 8081);
    tenant_b.namespace = "tenant-b".to_string();
    store
        .create_upstream(&tenant_b)
        .await
        .expect("tenant-b write must succeed");
    let b_sequence = store
        .latest_change_sequence("tenant-b")
        .await
        .expect("tenant-b sequence must load");

    let all_scope = store
        .latest_global_change_sequence()
        .await
        .expect("all-scope sequence must load");
    assert_eq!(
        all_scope,
        a_sequence.saturating_add(b_sequence),
        "All-scope mesh stamp must sum per-namespace high-waters, not take MAX(sequence)"
    );
    assert!(
        all_scope > a_sequence && all_scope > b_sequence,
        "the store-wide sum must exceed either namespace's own cursor"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn per_namespace_poller_ordering_stays_strict_across_interleaved_writes() {
    let (store, _temp_dir) = sqlite_store().await;
    let mut first = test_upstream("ordered-a1", "127.0.0.1", 8080);
    first.namespace = "tenant-a".to_string();
    store
        .create_upstream(&first)
        .await
        .expect("first tenant-a write must succeed");
    let after_first = store
        .latest_change_sequence("tenant-a")
        .await
        .expect("first tenant-a sequence must load");

    let mut other = test_upstream("ordered-b1", "127.0.0.1", 8081);
    other.namespace = "tenant-b".to_string();
    store
        .create_upstream(&other)
        .await
        .expect("interleaved tenant-b write must succeed");

    let mut second = test_upstream("ordered-a2", "127.0.0.1", 8082);
    second.namespace = "tenant-a".to_string();
    store
        .create_upstream(&second)
        .await
        .expect("second tenant-a write must succeed");
    let after_second = store
        .latest_change_sequence("tenant-a")
        .await
        .expect("second tenant-a sequence must load");
    assert!(
        after_second > after_first,
        "the second same-namespace write must receive a strictly later sequence"
    );

    let delta = store
        .load_incremental_config("tenant-a", after_first)
        .await
        .expect("per-namespace incremental poll must succeed");
    assert_eq!(delta.sequence_cursor, after_second);
    assert_eq!(delta.added_or_modified_upstreams.len(), 1);
    assert_eq!(delta.added_or_modified_upstreams[0].id, "ordered-a2");

    let from_origin = store
        .load_incremental_config("tenant-a", 0)
        .await
        .expect("origin incremental poll must succeed");
    let mut ids: Vec<String> = from_origin
        .added_or_modified_upstreams
        .iter()
        .map(|upstream| upstream.id.clone())
        .collect();
    ids.sort();
    assert_eq!(
        ids,
        vec!["ordered-a1".to_string(), "ordered-a2".to_string()],
        "the tenant-a poller must observe both writes in that namespace"
    );
}

/// MongoDB incremental polling must fail closed on typed `config_changes`
/// corruption the same way SQL `try_get` aborts the poll (issue #4286).
/// These tests exercise the production decoder without a live MongoDB.
mod mongo_incremental_poll_contract {
    use ferrum_edge::_test_support::decode_mongo_config_change_record;
    use mongodb::bson::{Bson, Document, doc};

    const MONGO_STORE_SOURCE: &str = include_str!("../../src/config/mongo_store.rs");

    fn well_formed_change_doc(sequence: i64, resource_id: &str, operation: &str) -> Document {
        doc! {
            "sequence": sequence,
            "namespace": "ferrum",
            "resource_type": "upstream",
            "resource_id": resource_id,
            "operation": operation,
            "created_at": "2026-08-28T00:00:00Z",
        }
    }

    fn poll_cursor(after_sequence: u64, docs: &[Document]) -> Result<u64, anyhow::Error> {
        let mut sequence_cursor = after_sequence;
        for doc in docs {
            let change = decode_mongo_config_change_record(doc)?;
            sequence_cursor = sequence_cursor.max(change.sequence);
        }
        Ok(sequence_cursor)
    }

    #[test]
    fn wrong_bson_resource_id_aborts_before_a_later_well_formed_change() {
        let mut malformed = well_formed_change_doc(5, "malformed-upstream", "delete");
        malformed.insert("resource_id", Bson::Int32(7));
        let later = well_formed_change_doc(6, "later-upstream", "upsert");

        let error = poll_cursor(0, &[malformed, later]).expect_err(
            "Int32 resource_id must abort the poll so the later change cannot skip it forever",
        );
        let message = error.to_string();
        assert!(
            message.contains("non-string field 'resource_id'"),
            "typed decode error must name the field, got: {message}"
        );
        assert!(
            !message.contains("malformed-upstream")
                && !message.contains("later-upstream")
                && !message.contains("7"),
            "decode errors must not log record content: {message}"
        );
    }

    #[test]
    fn missing_operation_aborts_without_advancing_the_cursor() {
        let mut missing = well_formed_change_doc(2, "upstream-a", "upsert");
        missing.remove("operation");
        let later = well_formed_change_doc(3, "upstream-b", "delete");
        let error = poll_cursor(1, &[missing, later])
            .expect_err("missing operation must abort before the cursor can move");
        assert!(
            error.to_string().contains("missing field 'operation'"),
            "missing field must fail closed, got: {error}"
        );
    }

    #[test]
    fn invalid_operation_does_not_become_an_upsert() {
        let invalid = well_formed_change_doc(4, "upstream-a", "patch");
        let later = well_formed_change_doc(5, "upstream-b", "upsert");
        let error = poll_cursor(0, &[invalid, later])
            .expect_err("unsupported operation must abort the poll, not default to upsert");
        assert!(
            error.to_string().contains("unsupported operation"),
            "invalid operation must fail closed, got: {error}"
        );
    }

    #[test]
    fn integral_double_sequence_decodes_and_advances_the_cursor() {
        // `mongosh insertOne({sequence: 5, ...})` writes a BSON Double unless the
        // operator spells `NumberLong(5)`. That row must decode, not wedge both
        // incremental polling and the full-reload repair path (issue #4530).
        let mut doubled = well_formed_change_doc(5, "upstream-a", "upsert");
        doubled.insert("sequence", Bson::Double(5.0));

        let change = decode_mongo_config_change_record(&doubled)
            .expect("an integral non-negative Double sequence must decode");
        assert_eq!(change.sequence, 5);

        let cursor = poll_cursor(0, &[doubled])
            .expect("a Double sequence row must not abort the incremental poll");
        assert_eq!(cursor, 5);
    }

    #[test]
    fn non_integral_and_negative_double_sequences_are_rejected_without_leaking_content() {
        for (label, value) in [("fractional", 5.5_f64), ("negative", -1.0_f64)] {
            let mut malformed = well_formed_change_doc(5, "malformed-upstream", "delete");
            malformed.insert("sequence", Bson::Double(value));

            let Err(error) = decode_mongo_config_change_record(&malformed) else {
                panic!("a {label} Double sequence must fail closed, but it decoded");
            };
            let message = error.to_string();
            assert!(
                message.contains("invalid 'sequence'"),
                "{label} sequence error must name the field, got: {message}"
            );
            assert!(
                !message.contains("5.5")
                    && !message.contains("-1")
                    && !message.contains("malformed-upstream")
                    && !message.contains("delete"),
                "{label} sequence error must not log record content: {message}"
            );
        }
    }

    #[test]
    fn out_of_exact_range_double_sequence_is_rejected() {
        // Beyond 2^53 a double no longer names exactly one integer, so accepting
        // it could admit a silently wrong sequence.
        let mut malformed = well_formed_change_doc(5, "upstream-a", "upsert");
        malformed.insert("sequence", Bson::Double(9_007_199_254_740_994.0));
        let error = decode_mongo_config_change_record(&malformed)
            .expect_err("a Double beyond 2^53 must fail closed");
        assert!(
            error.to_string().contains("invalid 'sequence'"),
            "out-of-range sequence must fail closed, got: {error}"
        );
    }

    #[test]
    fn string_sequence_is_still_rejected_by_the_watermark_reader() {
        // The full-reload fallback tolerance depends on this shape: a string
        // `sequence` is exactly what makes `latest_change_sequence` fail while
        // the resource collections themselves remain readable.
        let mut malformed = well_formed_change_doc(5, "upstream-a", "upsert");
        malformed.insert("sequence", Bson::String("5".to_string()));
        let error = decode_mongo_config_change_record(&malformed)
            .expect_err("a string sequence must fail closed");
        assert!(
            error.to_string().contains("invalid 'sequence'"),
            "string sequence must fail closed, got: {error}"
        );
    }

    #[test]
    fn every_sequence_reader_shares_the_widened_decoder() {
        for marker in [
            "async fn latest_change_sequence(&self",
            "async fn latest_global_change_sequence(&self",
            "async fn compact_config_changes(&self",
        ] {
            let start = MONGO_STORE_SOURCE
                .find(marker)
                .unwrap_or_else(|| panic!("{marker} must exist"));
            let tail = &MONGO_STORE_SOURCE[start + marker.len()..];
            let end = tail
                .find("\n        async fn ")
                .unwrap_or_else(|| panic!("{marker} must be followed by another method"));
            let body = &MONGO_STORE_SOURCE[start..start + marker.len() + end];
            assert!(
                body.contains("mongo_change_sequence_from_bson"),
                "{marker} must decode sequences through the shared helper:\n{body}"
            );
            assert!(
                !body.contains("invalid sequence: {:?}"),
                "{marker} must not interpolate the BSON payload into its error:\n{body}"
            );
        }
    }

    #[test]
    fn mongo_incremental_loader_uses_fail_closed_decoder_before_cursor_update() {
        let marker = "        async fn load_incremental_config";
        let start = MONGO_STORE_SOURCE
            .find(marker)
            .expect("Mongo load_incremental_config must exist");
        let tail = &MONGO_STORE_SOURCE[start + marker.len()..];
        let end = tail
            .find("\n        async fn ")
            .expect("Mongo load_incremental_config must be followed by another method");
        let body = &MONGO_STORE_SOURCE[start..start + marker.len() + end];
        let decode_at = body
            .find("decode_mongo_config_change_record")
            .expect("Mongo incremental poll must decode through the fail-closed helper");
        let cursor_at = body
            .find("sequence_cursor = sequence_cursor.max(")
            .expect("Mongo incremental poll must update the cursor after accepting a record");
        assert!(
            decode_at < cursor_at,
            "Mongo incremental poll must not advance the cursor past a rejected record:\n{body}"
        );
        assert!(
            body[decode_at..cursor_at].contains('?'),
            "typed decode failure must abort with ? before the cursor updates:\n{body}"
        );
    }
}

/// The full reload is the repair path an incremental-poll failure falls back to,
/// so an unreadable `config_changes` watermark must not abort it (issue #4530).
/// A poisoned `sequence` (a BSON Double before this fix, a string still today)
/// otherwise fails both readers and the gateway can never publish fresh config.
#[tokio::test(flavor = "multi_thread")]
async fn full_reload_publishes_when_the_change_watermark_read_fails() {
    use ferrum_edge::_test_support::{
        database_mode_load_full_config_with_sequence_for_test,
        database_store_set_latest_change_sequence_fault_for_test,
    };
    use ferrum_edge::config::db_backend::DatabaseBackend;
    use std::sync::Arc;

    let (store, _temp_dir) = sqlite_store().await;
    store
        .create_upstream(&test_upstream("upstream-a", "10.0.0.1", 8080))
        .await
        .expect("upstream insert must succeed");

    database_store_set_latest_change_sequence_fault_for_test(&store, true);
    let db: Arc<dyn DatabaseBackend> = Arc::new(store);

    let (config, sequence) = database_mode_load_full_config_with_sequence_for_test(&db, "ferrum")
        .await
        .expect("full reload must still publish when the watermark read fails");

    assert_eq!(
        sequence, 0,
        "an unreadable watermark must degrade to 0, not abort the reload"
    );
    assert!(
        config.upstreams.iter().any(|u| u.id == "upstream-a"),
        "the reload must carry fresh config, not a stale snapshot"
    );
}

// ===========================================================================
// Issue #4116: a saturated change batch must converge through the full-reload
// fallback within a bounded number of poll cycles, at a scale where the
// validation sweep's per-plugin-config cost decides whether it converges.
// ===========================================================================

/// Proxies provisioned by
/// [`saturated_change_log_fallback_converges_within_two_poll_cycles`].
///
/// Each proxy insert records one `config_changes` row and each of its two
/// proxy-scoped plugin configs records two (the plugin row plus the proxy
/// re-upsert), so 2,100 proxies append 10,500 rows — past the 10,000-row
/// change-batch limit, exactly the shape one scale-harness wave produces.
const SATURATED_BATCH_PROXIES: usize = 2_100;

fn scale_proxy_plugin_config(
    id: &str,
    plugin_name: &str,
    proxy_id: &str,
    config: serde_json::Value,
) -> PluginConfig {
    PluginConfig {
        id: id.to_string(),
        namespace: default_namespace(),
        plugin_name: plugin_name.to_string(),
        config,
        scope: PluginScope::Proxy,
        proxy_id: Some(proxy_id.to_string()),
        enabled: true,
        priority_override: None,
        trigger: None,
        api_spec_id: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

fn scale_proxy_state() -> ferrum_edge::proxy::ProxyState {
    use ferrum_edge::config::env_config::OperatingMode;
    use ferrum_edge::dns::{DnsCache, DnsConfig};

    let mut config = ferrum_edge::config::types::GatewayConfig::default();
    config.normalize_fields();
    let env_config = ferrum_edge::config::EnvConfig {
        mode: OperatingMode::Database,
        ..Default::default()
    };
    let (state, _handles) = ferrum_edge::proxy::ProxyState::new(
        config,
        DnsCache::new(DnsConfig::default()),
        env_config,
        None,
        None,
    )
    .expect("ProxyState::new");
    state
}

/// One authoritative poll cycle, mirroring `src/modes/database.rs`: read the
/// change log after the accepted cursor; when the read reports a saturated
/// batch, run the SAME full-reload helper the poll loop uses, publish the
/// snapshot through `update_config`, and commit the cursor the helper read.
///
/// Returns whether this cycle fell back to a full reload.
async fn saturated_batch_poll_cycle(
    db: &std::sync::Arc<dyn ferrum_edge::config::db_backend::DatabaseBackend>,
    proxy_state: &ferrum_edge::proxy::ProxyState,
    apply: &ferrum_edge::config::runtime_config_apply::RuntimeConfigApply,
    cursor: &mut ferrum_edge::config::runtime_config_apply::LiveApplyCursor,
) -> Result<bool, String> {
    use ferrum_edge::_test_support::database_mode_load_full_config_with_sequence_for_test;
    use ferrum_edge::config::runtime_config_apply::LiveApplyCursor;
    use ferrum_edge::proxy::ConfigApplyOutcome;

    match db.load_incremental_config("ferrum", cursor.sequence).await {
        Ok(result) => {
            let next = LiveApplyCursor::new(cursor.topology_epoch, result.sequence_cursor);
            match proxy_state.apply_incremental(result).await {
                ConfigApplyOutcome::Applied | ConfigApplyOutcome::Unchanged => {
                    *cursor = next;
                    apply.record_accepted_cursor(next);
                    Ok(false)
                }
                ConfigApplyOutcome::Rejected { errors } => Err(format!(
                    "incremental candidate rejected: {}",
                    errors.join("; ")
                )),
            }
        }
        Err(error) => {
            let message = error.to_string();
            if !(message.contains("reached limit") && message.contains("forcing full reload")) {
                return Err(format!("incremental poll failed for another reason: {message}"));
            }
            let (config, sequence) =
                database_mode_load_full_config_with_sequence_for_test(db, "ferrum")
                    .await
                    .map_err(|error| format!("full fallback reload failed: {error}"))?;
            let next = LiveApplyCursor::new(cursor.topology_epoch, sequence);
            match proxy_state.update_config(config) {
                ConfigApplyOutcome::Applied | ConfigApplyOutcome::Unchanged => {
                    *cursor = next;
                    apply.record_accepted_cursor(next);
                    Ok(true)
                }
                ConfigApplyOutcome::Rejected { errors } => Err(format!(
                    "full fallback candidate rejected: {}",
                    errors.join("; ")
                )),
            }
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn saturated_change_log_fallback_converges_within_two_poll_cycles() {
    use ferrum_edge::_test_support::{
        database_mode_load_full_config_with_sequence_for_test, plugin_http_client_builds_for_test,
    };
    use ferrum_edge::config::db_backend::{BatchConfigWriteMode, DatabaseBackend};
    use ferrum_edge::config::runtime_config_apply::{LiveApplyCursor, RuntimeConfigApply};
    use ferrum_edge::proxy::ConfigApplyOutcome;
    use std::sync::Arc;

    let (store, _temp_dir) = sqlite_store().await;
    let db: Arc<dyn DatabaseBackend> = Arc::new(store);
    let proxy_state = scale_proxy_state();
    let apply = RuntimeConfigApply::new("ferrum", 0);

    // Seed the accepted cursor from the startup full load exactly as
    // database mode does.
    let (initial, initial_sequence) =
        database_mode_load_full_config_with_sequence_for_test(&db, "ferrum")
            .await
            .expect("startup full load must succeed on an empty store");
    assert!(
        matches!(
            proxy_state.update_config(initial),
            ConfigApplyOutcome::Applied | ConfigApplyOutcome::Unchanged
        ),
        "startup snapshot must publish"
    );
    let topology_epoch = {
        let permit = db.acquire_write_topology_permit().await;
        permit.topology_epoch()
    };
    let mut cursor = LiveApplyCursor::new(topology_epoch, initial_sequence);
    apply.record_accepted_cursor(cursor);

    // One scale-harness wave: proxies, then the two proxy-scoped plugins each
    // wave attaches, written through the same batch admission path the admin
    // API uses. This appends more change rows than one incremental read may
    // consume.
    let proxies: Vec<Proxy> = (0..SATURATED_BATCH_PROXIES)
        .map(|i| test_proxy(&format!("scale-proxy-{i}"), &format!("/scale/{i}"), vec![]))
        .collect();
    db.batch_create_proxies_without_plugins(&proxies, &BatchConfigWriteMode::Admission)
        .await
        .expect("batch proxy create must succeed");
    let plugin_configs: Vec<PluginConfig> = (0..SATURATED_BATCH_PROXIES)
        .flat_map(|i| {
            let proxy_id = format!("scale-proxy-{i}");
            [
                scale_proxy_plugin_config(
                    &format!("scale-keyauth-{i}"),
                    "key_auth",
                    &proxy_id,
                    json!({ "key_location": "header:X-API-Key" }),
                ),
                scale_proxy_plugin_config(
                    &format!("scale-acl-{i}"),
                    "access_control",
                    &proxy_id,
                    json!({ "allowed_consumers": [format!("scale-user-{i}")] }),
                ),
            ]
        })
        .collect();
    db.batch_create_plugin_configs(&plugin_configs, &BatchConfigWriteMode::Admission)
        .await
        .expect("batch plugin config create must succeed");

    let watermark = db
        .latest_change_sequence("ferrum")
        .await
        .expect("watermark must load");
    let appended = watermark - cursor.sequence;
    assert!(
        appended >= 10_000,
        "the wave must append at least one saturated change batch, appended {appended}"
    );

    // Cycle 1: the saturated batch routes through the full-reload fallback,
    // and the reload commits the watermark it read as the accepted cursor.
    let builds_before = plugin_http_client_builds_for_test();
    let fell_back = saturated_batch_poll_cycle(&db, &proxy_state, &apply, &mut cursor)
        .await
        .expect("cycle 1 must publish");
    let builds_during_reload = plugin_http_client_builds_for_test() - builds_before;
    assert!(fell_back, "a saturated change batch must route through the full-reload fallback");
    assert_eq!(
        cursor.sequence, watermark,
        "the fallback reload must commit the watermark it read as the accepted cursor"
    );
    assert_eq!(
        apply.accepted_cursor(), LiveApplyCursor::new(topology_epoch, watermark),
        "the live-apply status must report the reload's cursor as accepted"
    );

    // The defect behind issue #4116: the full-load validation sweep built the
    // two-client plugin validation stack (plus its resolver) once PER enabled
    // plugin config, ~20 ms per proxy on SQLite and PostgreSQL alike. At 30k
    // proxies that reload took longer than bulk provisioning needs to append
    // the next saturated batch, so the fallback re-triggered itself instead of
    // converging. Client construction must be bounded per sweep, not per row.
    let enabled_plugin_configs = plugin_configs.len() as u64;
    assert!(
        builds_during_reload < enabled_plugin_configs,
        "the fallback reload built {builds_during_reload} plugin HTTP clients while validating \
         {enabled_plugin_configs} plugin configs; validation must build a bounded number of \
         clients per sweep, not one per plugin config (issue #4116)"
    );

    let served = proxy_state.current_config();
    assert_eq!(
        served.proxies.len(), SATURATED_BATCH_PROXIES,
        "the reload must serve every proxy of the wave"
    );
    assert_eq!(
        served.plugin_configs.len(), 2 * SATURATED_BATCH_PROXIES,
        "the reload must serve every plugin config of the wave"
    );

    // Cycle 2: nothing was left behind, so the next poll is an ordinary empty
    // incremental read and the cursor stays at the watermark.
    let fell_back = saturated_batch_poll_cycle(&db, &proxy_state, &apply, &mut cursor)
        .await
        .expect("cycle 2 must complete");
    assert!(
        !fell_back,
        "the poll after a fallback reload must be incremental, not another full reload"
    );
    assert_eq!(cursor.sequence, watermark);
    assert_eq!(apply.accepted_sequence(), watermark);

    // A write after the fallback is picked up incrementally from the
    // committed cursor, proving the reload neither skipped ahead of the rows
    // it loaded nor left the poller re-reading the wave.
    db.create_proxy(&test_proxy("scale-proxy-after", "/scale/after", vec![]))
        .await
        .expect("post-reload proxy create must succeed");
    let after_watermark = db
        .latest_change_sequence("ferrum")
        .await
        .expect("watermark must load");
    assert!(after_watermark > watermark);
    let fell_back = saturated_batch_poll_cycle(&db, &proxy_state, &apply, &mut cursor)
        .await
        .expect("cycle 3 must publish");
    assert!(!fell_back, "a single post-reload write must apply incrementally");
    assert_eq!(cursor.sequence, after_watermark);
    assert_eq!(apply.accepted_sequence(), after_watermark);
    assert_eq!(
        proxy_state.current_config().proxies.len(), SATURATED_BATCH_PROXIES + 1,
        "the incremental poll after the fallback must publish the new proxy"
    );
}
