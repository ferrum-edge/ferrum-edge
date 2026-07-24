//! Live MySQL contracts for custom-plugin migration recovery and for the
//! concurrency / identity-integrity workstream (#2991, #2994, #2999):
//! cross-namespace config/route writes without S→X deadlock, byte-exact
//! identity uniqueness under `utf8mb4_bin`, and concurrent duplicate-Upstream
//! admission with exactly one winner.

use std::sync::Arc;
use std::time::Duration;

use ferrum_edge::_test_support::DbPoolConfig;
use ferrum_edge::config::db_loader::DatabaseStore;
use ferrum_edge::config::migrations::MigrationRunner;
use ferrum_edge::config::types::{
    Consumer, LoadBalancerAlgorithm, Proxy, Upstream, UpstreamTarget,
};
use serde_json::json;
use sqlx::Row;
use testcontainers::core::IntoContainerPort;
use testcontainers::runners::AsyncRunner;
use testcontainers::{ContainerAsync, GenericImage, ImageExt};

use super::common::containers::{BoxError, fail_in_ci_else_skip};

struct MySqlFixture {
    _container: ContainerAsync<GenericImage>,
    url: String,
    pool: sqlx::AnyPool,
}

async fn start_mysql() -> Result<MySqlFixture, BoxError> {
    const PASSWORD: &str = "ferrum-mysql-test-password";
    let container = GenericImage::new("mysql", "8.4")
        .with_exposed_port(3306.tcp())
        .with_env_var("MYSQL_ROOT_PASSWORD", PASSWORD)
        .with_env_var("MYSQL_ROOT_HOST", "%")
        .with_env_var("MYSQL_DATABASE", "ferrum")
        .start()
        .await?;
    let port = container.get_host_port_ipv4(3306.tcp()).await?;
    let url = format!("mysql://root:{PASSWORD}@127.0.0.1:{port}/ferrum");

    sqlx::any::install_default_drivers();
    let mut last_error = String::new();
    for _ in 0..90 {
        match sqlx::any::AnyPoolOptions::new()
            .max_connections(8)
            .acquire_timeout(Duration::from_secs(2))
            .connect(&url)
            .await
        {
            Ok(pool) => {
                return Ok(MySqlFixture {
                    _container: container,
                    url,
                    pool,
                });
            }
            Err(error) => {
                last_error = error.to_string();
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
        }
    }
    Err(format!("MySQL did not become ready within 45s: {last_error}").into())
}

async fn connect_store(url: &str) -> DatabaseStore {
    let pool_config = DbPoolConfig {
        max_connections: 16,
        min_connections: 2,
        ..DbPoolConfig::default()
    };
    DatabaseStore::connect_with_pool_config("mysql", url, pool_config)
        .await
        .expect("MySQL DatabaseStore connect + V001 migrations must succeed")
}

fn is_mysql_deadlock(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        let message = cause.to_string();
        message.contains("1213")
            || message.to_ascii_lowercase().contains("deadlock")
            || message.contains("ER_LOCK_DEADLOCK")
    })
}

fn is_unique_constraint_violation(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        let lower = cause.to_string().to_ascii_lowercase();
        lower.contains("duplicate") || lower.contains("unique constraint")
    })
}

fn make_consumer(namespace: &str, id: &str, username: &str) -> Consumer {
    Consumer {
        id: id.to_string(),
        namespace: namespace.to_string(),
        username: username.to_string(),
        custom_id: None,
        credentials: Default::default(),
        acl_groups: Vec::new(),
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    }
}

fn make_http_proxy(namespace: &str, id: &str, listen_path: &str) -> Proxy {
    serde_json::from_value(json!({
        "id": id,
        "namespace": namespace,
        "name": id,
        "hosts": [format!("{id}.test")],
        "listen_path": listen_path,
        "backend_scheme": "http",
        "backend_host": "127.0.0.1",
        "backend_port": 8080
    }))
    .expect("proxy fixture must deserialize")
}

fn make_upstream(namespace: &str, id: &str, name: &str) -> Upstream {
    Upstream {
        id: id.to_string(),
        namespace: namespace.to_string(),
        name: Some(name.to_string()),
        targets: vec![UpstreamTarget {
            host: "127.0.0.1".to_string(),
            port: 8080,
            service_port_policy_key: None,
            weight: 100,
            tags: Default::default(),
            locality: None,
            path: None,
        }],
        algorithm: LoadBalancerAlgorithm::RoundRobin,
        hash_on: None,
        hash_on_cookie_config: None,
        health_checks: None,
        service_discovery: None,
        subsets: None,
        port_overrides: Default::default(),
        source_locality: None,
        locality_lb_strict: false,
        locality_lb_setting: None,
        backend_tls_client_cert_path: None,
        backend_tls_client_key_path: None,
        backend_tls_verify_server_cert: true,
        backend_tls_server_ca_cert_path: None,
        backend_tls_sni: None,
        backend_tls_san_allow_list: Vec::new(),
        resolved_subset_tls: Default::default(),
        dispatch_port_override_fallback: None,
        api_spec_id: None,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    }
}

async fn index_definition(pool: &sqlx::AnyPool, index_name: &str) -> Vec<(String, i64)> {
    sqlx::query(
        "SELECT COLUMN_NAME, CAST(NON_UNIQUE AS SIGNED) \
         FROM information_schema.statistics \
         WHERE table_schema = DATABASE() AND table_name = 'example_audit_log' \
           AND index_name = ? \
         ORDER BY SEQ_IN_INDEX",
    )
    .bind(index_name)
    .fetch_all(pool)
    .await
    .expect("inspect example_audit_log index definition")
    .into_iter()
    .map(|row| {
        (
            row.try_get(0).expect("index column name"),
            row.try_get(1).expect("index uniqueness"),
        )
    })
    .collect()
}

#[tokio::test(flavor = "multi_thread")]
async fn mysql_example_audit_partial_ddl_recovers_and_accepts_text_bindings() {
    // Check plugin presence before starting Docker so default local builds
    // self-skip without waiting ~30-45s for a MySQL container.
    let migrations = ferrum_edge::custom_plugins::collect_all_custom_plugin_migrations();
    let Some((_, example)) = migrations
        .into_iter()
        .find(|(name, _)| *name == "example_audit_plugin")
    else {
        eprintln!(
            "SKIP mysql_example_audit_partial_ddl_recovers_and_accepts_text_bindings: \
             example_audit_plugin not compiled in (set FERRUM_CUSTOM_PLUGINS=example_audit_plugin)"
        );
        return;
    };

    let fixture = match start_mysql().await {
        Ok(fixture) => fixture,
        Err(error) => {
            fail_in_ci_else_skip(
                "mysql_example_audit_partial_ddl_recovers_and_accepts_text_bindings",
                "MySQL 8.4",
                &error,
            );
            return;
        }
    };
    let pool = &fixture.pool;

    // A partial V1 table is missing client_ip. The first attempt successfully
    // rebuilds the timestamp index, then fails on the later client_ip index.
    // MySQL commits that earlier DDL even though no tracking row is written.
    sqlx::query(
        r#"
        CREATE TABLE example_audit_log (
            id VARCHAR(255) PRIMARY KEY,
            timestamp VARCHAR(32) NOT NULL,
            protocol VARCHAR(32) NOT NULL,
            http_method VARCHAR(256),
            request_path TEXT,
            response_status INTEGER,
            grpc_status BIGINT,
            latency_ms DOUBLE NOT NULL,
            consumer_username VARCHAR(255),
            proxy_id VARCHAR(255),
            request_context TEXT,
            connection_error TEXT
        )
        "#,
    )
    .execute(pool)
    .await
    .expect("partial example audit table");
    sqlx::query("CREATE INDEX idx_example_audit_log_timestamp ON example_audit_log (proxy_id)")
        .execute(pool)
        .await
        .expect("wrong timestamp index");
    sqlx::query("CREATE INDEX idx_example_audit_log_client_ip ON example_audit_log (timestamp)")
        .execute(pool)
        .await
        .expect("wrong client index");

    let runner = MigrationRunner::new(pool.clone(), "mysql".to_string());
    let list = vec![("example_audit_plugin", example)];
    let first_error = runner
        .run_plugin_pending(&list)
        .await
        .expect_err("missing client_ip must fail after earlier DDL committed");
    assert!(
        format!("{first_error:#}").contains("client_ip"),
        "unexpected first migration error: {first_error:#}"
    );
    assert_eq!(
        index_definition(pool, "idx_example_audit_log_timestamp").await,
        [("timestamp".to_string(), 1)],
        "the successful earlier index DDL must survive the failed migration"
    );
    assert!(
        index_definition(pool, "idx_example_audit_log_client_ip")
            .await
            .is_empty(),
        "the failing client index must remain absent"
    );
    let tracked_v3: i64 = sqlx::query_scalar(
        "SELECT CAST(COUNT(*) AS SIGNED) FROM _ferrum_plugin_migrations \
         WHERE plugin_name = ? AND version = 3",
    )
    .bind("example_audit_plugin")
    .fetch_one(pool)
    .await
    .expect("inspect missing V3 tracking row");
    assert_eq!(tracked_v3, 0);

    sqlx::query("ALTER TABLE example_audit_log ADD COLUMN client_ip VARCHAR(255) NOT NULL")
        .execute(pool)
        .await
        .expect("repair client_ip column");
    sqlx::query("CREATE INDEX idx_example_audit_log_client_ip ON example_audit_log (timestamp)")
        .execute(pool)
        .await
        .expect("seed wrong client index before retry");

    let applied = runner
        .run_plugin_pending(&list)
        .await
        .expect("retry after partial MySQL DDL must succeed");
    assert!(applied.iter().any(|record| record.version == 3));
    assert!(applied.iter().any(|record| record.version == 4));
    assert_eq!(
        index_definition(pool, "idx_example_audit_log_timestamp").await,
        [("timestamp".to_string(), 1)]
    );
    assert_eq!(
        index_definition(pool, "idx_example_audit_log_client_ip").await,
        [("client_ip".to_string(), 1)]
    );
    assert_eq!(
        index_definition(pool, "idx_example_audit_log_status_ts").await,
        [
            ("response_status".to_string(), 1),
            ("timestamp".to_string(), 1),
        ]
    );

    // Exercise the exact SQLx Any bindings used by the runtime sink.
    sqlx::query(
        "INSERT INTO example_audit_log \
         (id, timestamp, client_ip, protocol, latency_ms, request_context) \
         VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind("runtime-row")
    .bind("2026-07-20T12:00:00.000Z")
    .bind("192.0.2.10")
    .bind("http")
    .bind(1.25_f64)
    .bind("{\"redacted\":true}")
    .execute(pool)
    .await
    .expect("runtime text bindings must be accepted by MySQL through sqlx::Any");
    let context: Vec<u8> = sqlx::query_scalar(
        "SELECT request_context FROM example_audit_log WHERE id = 'runtime-row'",
    )
    .fetch_one(pool)
    .await
    .expect("read runtime text binding");
    assert_eq!(context.as_slice(), b"{\"redacted\":true}");

    // Simulate V4 CREATE INDEX committing before its tracker insert.
    sqlx::query(
        "DELETE FROM _ferrum_plugin_migrations \
         WHERE plugin_name = ? AND version = 4",
    )
    .bind("example_audit_plugin")
    .execute(pool)
    .await
    .expect("remove V4 tracker row");
    let recovered_v4 = runner
        .run_plugin_pending(&list)
        .await
        .expect("V4 tracking-gap retry must succeed");
    assert_eq!(recovered_v4.len(), 1);
    assert_eq!(recovered_v4[0].version, 4);
    assert_eq!(
        index_definition(pool, "idx_example_audit_log_status_ts").await,
        [
            ("response_status".to_string(), 1),
            ("timestamp".to_string(), 1),
        ]
    );
    assert!(runner.run_plugin_pending(&list).await.unwrap().is_empty());
}

/// Cross-namespace consumer (config-change lock) and proxy (route + config-
/// change locks) writers must not deadlock on the global `config_change_locks`
/// row after the MySQL exclusive upsert fix (#2991).
#[tokio::test(flavor = "multi_thread")]
async fn mysql_cross_namespace_config_and_route_writes_do_not_deadlock() {
    let fixture = match start_mysql().await {
        Ok(fixture) => fixture,
        Err(error) => {
            fail_in_ci_else_skip(
                "mysql_cross_namespace_config_and_route_writes_do_not_deadlock",
                "MySQL 8.4",
                &error,
            );
            return;
        }
    };
    let store = Arc::new(connect_store(&fixture.url).await);

    const ITERATIONS: usize = 40;
    for i in 0..ITERATIONS {
        let store_a = Arc::clone(&store);
        let store_b = Arc::clone(&store);
        let consumer = make_consumer("ns-config", &format!("c-{i}"), &format!("user-{i}"));
        let proxy = make_http_proxy("ns-route", &format!("p-{i}"), &format!("/p-{i}"));
        let barrier = Arc::new(tokio::sync::Barrier::new(2));
        let barrier_a = Arc::clone(&barrier);
        let barrier_b = Arc::clone(&barrier);

        let (result_a, result_b) = tokio::join!(
            async move {
                barrier_a.wait().await;
                store_a.create_consumer(&consumer).await
            },
            async move {
                barrier_b.wait().await;
                store_b.create_proxy(&proxy).await
            },
        );

        if let Err(error) = &result_a {
            assert!(
                !is_mysql_deadlock(error),
                "cross-namespace config write hit MySQL deadlock: {error:#}"
            );
        }
        if let Err(error) = &result_b {
            assert!(
                !is_mysql_deadlock(error),
                "cross-namespace route write hit MySQL deadlock: {error:#}"
            );
        }
        result_a.expect("consumer create in ns-config must succeed");
        result_b.expect("proxy create in ns-route must succeed");
    }
}

/// NFC and NFD forms of the same grapheme must remain distinct consumer
/// identities under MySQL `utf8mb4_bin` (#2994), matching Postgres/SQLite.
#[tokio::test(flavor = "multi_thread")]
async fn mysql_byte_exact_identity_accepts_nfc_and_nfd_usernames() {
    let fixture = match start_mysql().await {
        Ok(fixture) => fixture,
        Err(error) => {
            fail_in_ci_else_skip(
                "mysql_byte_exact_identity_accepts_nfc_and_nfd_usernames",
                "MySQL 8.4",
                &error,
            );
            return;
        }
    };
    let store = connect_store(&fixture.url).await;

    // U+00E9 (é) vs e + U+0301 combining acute — canonically equivalent under
    // UCA, distinct as UTF-8 bytes.
    let nfc_username = "caf\u{00e9}";
    let nfd_username = "cafe\u{0301}";
    assert_ne!(
        nfc_username.as_bytes(),
        nfd_username.as_bytes(),
        "fixture usernames must differ by bytes"
    );

    store
        .create_consumer(&make_consumer("ferrum", "nfc-consumer", nfc_username))
        .await
        .expect("NFC username must insert");
    store
        .create_consumer(&make_consumer("ferrum", "nfd-consumer", nfd_username))
        .await
        .expect("NFD username must insert as a distinct identity under utf8mb4_bin");

    assert!(
        store
            .check_consumer_identity_unique("ferrum", "other", nfc_username, None, None)
            .await
            .expect("identity probe")
            .is_some(),
        "NFC username must collide with the NFC consumer only"
    );
    assert!(
        store
            .check_consumer_identity_unique("ferrum", "other", nfd_username, None, None)
            .await
            .expect("identity probe")
            .is_some(),
        "NFD username must collide with the NFD consumer only"
    );

    let loaded_nfc = store
        .get_consumer("ferrum", "nfc-consumer")
        .await
        .expect("load NFC consumer")
        .expect("NFC consumer present");
    let loaded_nfd = store
        .get_consumer("ferrum", "nfd-consumer")
        .await
        .expect("load NFD consumer")
        .expect("NFD consumer present");
    assert_eq!(loaded_nfc.username.as_bytes(), nfc_username.as_bytes());
    assert_eq!(loaded_nfd.username.as_bytes(), nfd_username.as_bytes());

    let count: i64 = sqlx::query_scalar(
        "SELECT CAST(COUNT(*) AS SIGNED) FROM consumers WHERE namespace = 'ferrum'",
    )
    .fetch_one(&fixture.pool)
    .await
    .expect("count consumers");
    assert_eq!(count, 2);
}

/// Concurrent `create_upstream` with the same `(namespace, name)` must commit
/// exactly one row (#2999). The unique index is the datastore backstop; the
/// admin admission lease keeps the advisory 409 path serialized.
#[tokio::test(flavor = "multi_thread")]
async fn mysql_concurrent_duplicate_upstream_name_has_exactly_one_winner() {
    let fixture = match start_mysql().await {
        Ok(fixture) => fixture,
        Err(error) => {
            fail_in_ci_else_skip(
                "mysql_concurrent_duplicate_upstream_name_has_exactly_one_winner",
                "MySQL 8.4",
                &error,
            );
            return;
        }
    };
    let store = Arc::new(connect_store(&fixture.url).await);
    let upstream_a = make_upstream("ferrum", "upstream-a", "shared-name");
    let upstream_b = make_upstream("ferrum", "upstream-b", "shared-name");
    let barrier = Arc::new(tokio::sync::Barrier::new(2));
    let barrier_a = Arc::clone(&barrier);
    let barrier_b = Arc::clone(&barrier);
    let store_a = Arc::clone(&store);
    let store_b = Arc::clone(&store);

    let (result_a, result_b) = tokio::join!(
        async move {
            barrier_a.wait().await;
            store_a.create_upstream(&upstream_a).await
        },
        async move {
            barrier_b.wait().await;
            store_b.create_upstream(&upstream_b).await
        },
    );

    let success_count = [result_a.is_ok(), result_b.is_ok()]
        .into_iter()
        .filter(|ok| *ok)
        .count();
    let failure = result_a.err().or_else(|| result_b.err());
    assert_eq!(
        success_count, 1,
        "exactly one concurrent upstream create must succeed"
    );
    let failure = failure.expect("exactly one concurrent upstream create must fail");
    assert!(
        is_unique_constraint_violation(&failure),
        "losing writer must hit the unique (namespace, name) backstop: {failure:#}"
    );
    assert!(
        !is_mysql_deadlock(&failure),
        "losing writer must not be a deadlock victim: {failure:#}"
    );

    let count: i64 = sqlx::query_scalar(
        "SELECT CAST(COUNT(*) AS SIGNED) FROM upstreams \
         WHERE namespace = 'ferrum' AND name = 'shared-name'",
    )
    .fetch_one(&fixture.pool)
    .await
    .expect("count duplicate-named upstreams");
    assert_eq!(count, 1, "exactly one upstream with the shared name may persist");

    assert!(
        !store
            .check_upstream_name_unique("ferrum", "shared-name", None)
            .await
            .expect("name uniqueness probe"),
        "shared name must no longer be unique after the winner commits"
    );
}
