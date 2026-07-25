//! Live MySQL contracts for custom-plugin migration recovery,
//! cross-namespace config-change lock serialization, and byte-exact
//! identity uniqueness under `utf8mb4_0900_bin` (#2994).

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use ferrum_edge::_test_support::DbPoolConfig;
use ferrum_edge::config::db_loader::DatabaseStore;
use ferrum_edge::config::migrations::MigrationRunner;
use ferrum_edge::config::types::{Consumer, LoadBalancerAlgorithm, Upstream, UpstreamTarget};
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
            .max_connections(2)
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

fn is_mysql_lock_deadlock(error: &anyhow::Error) -> bool {
    for cause in error.chain() {
        if let Some(sqlx_error) = cause.downcast_ref::<sqlx::Error>()
            && let sqlx::Error::Database(database_error) = sqlx_error
            && let Some(mysql_error) =
                database_error.try_downcast_ref::<sqlx::mysql::MySqlDatabaseError>()
            && mysql_error.number() == 1213
        {
            return true;
        }
        let rendered = cause.to_string();
        if rendered.contains("1213") || rendered.contains("Deadlock found when trying to get lock")
        {
            return true;
        }
    }
    false
}

fn make_namespace_upstream(namespace: &str, id: &str) -> Upstream {
    Upstream {
        id: id.to_string(),
        namespace: namespace.to_string(),
        name: Some(format!("{namespace}-{id}")),
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

async fn connect_store(url: &str) -> DatabaseStore {
    let pool_config = DbPoolConfig {
        max_connections: 4,
        min_connections: 1,
        acquire_timeout_seconds: 10,
        statement_timeout_seconds: 0,
        ..DbPoolConfig::default()
    };
    DatabaseStore::connect_with_pool_config("mysql", url, pool_config)
        .await
        .expect("MySQL DatabaseStore connect + V001 migrations must succeed")
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

/// Cross-namespace admin writers share `config_change_locks.lock_name='global'`.
/// The historical MySQL shape (`INSERT IGNORE` + `SELECT ... FOR UPDATE`)
/// deadlocked on the S->X upgrade under concurrent distinct namespaces. This
/// races two bounded write loops and asserts zero ER_LOCK_DEADLOCK 1213.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mysql_cross_namespace_config_change_lock_avoids_deadlock() {
    let fixture = match start_mysql().await {
        Ok(fixture) => fixture,
        Err(error) => {
            fail_in_ci_else_skip(
                "mysql_cross_namespace_config_change_lock_avoids_deadlock",
                "MySQL 8.4",
                &error,
            );
            return;
        }
    };

    // Two concurrent writers each need a connection; keep the pool small and
    // deterministic so the race stays on the shared lock row rather than pool
    // exhaustion.
    let pool_config = DbPoolConfig {
        max_connections: 4,
        min_connections: 2,
        acquire_timeout_seconds: 10,
        statement_timeout_seconds: 0,
        ..DbPoolConfig::default()
    };

    let store = Arc::new(
        DatabaseStore::connect_with_pool_config("mysql", &fixture.url, pool_config)
            .await
            .expect("connect DatabaseStore to hosted MySQL"),
    );

    const ITERATIONS: usize = 40;
    let barrier = Arc::new(tokio::sync::Barrier::new(2));
    let deadlocks = Arc::new(AtomicUsize::new(0));
    let other_failures = Arc::new(AtomicUsize::new(0));

    let run_writer = |namespace: &'static str| {
        let store = store.clone();
        let barrier = barrier.clone();
        let deadlocks = deadlocks.clone();
        let other_failures = other_failures.clone();
        async move {
            for i in 0..ITERATIONS {
                barrier.wait().await;
                let upstream = make_namespace_upstream(namespace, &format!("u-{namespace}-{i}"));
                match store.create_upstream(&upstream).await {
                    Ok(()) => {}
                    Err(error) if is_mysql_lock_deadlock(&error) => {
                        deadlocks.fetch_add(1, Ordering::Relaxed);
                    }
                    Err(_) => {
                        other_failures.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
        }
    };

    let ((), ()) = tokio::join!(run_writer("ns-a"), run_writer("ns-b"));

    let deadlock_count = deadlocks.load(Ordering::Relaxed);
    let other_failure_count = other_failures.load(Ordering::Relaxed);
    assert_eq!(
        deadlock_count, 0,
        "cross-namespace MySQL writers must not hit ER_LOCK_DEADLOCK 1213 \
         (observed {deadlock_count} deadlocks, {other_failure_count} other failures)"
    );
    assert_eq!(
        other_failure_count, 0,
        "cross-namespace MySQL writers must complete without non-deadlock failures \
         (observed {other_failure_count})"
    );

    let change_count: i64 = sqlx::query_scalar(
        "SELECT CAST(COUNT(*) AS SIGNED) FROM config_changes \
         WHERE namespace IN ('ns-a', 'ns-b') AND resource_type = 'upstream'",
    )
    .fetch_one(&fixture.pool)
    .await
    .expect("count committed config_changes");
    assert_eq!(
        change_count as usize,
        ITERATIONS * 2,
        "every raced create_upstream must commit a config_changes row"
    );
}

/// NFC/NFD forms and trailing-space variants must remain distinct consumer
/// identities under MySQL `utf8mb4_0900_bin` (#2994), matching Postgres/SQLite
/// and the runtime's byte-keyed `ConsumerIndex`.
#[tokio::test(flavor = "multi_thread")]
async fn mysql_byte_exact_identity_accepts_unicode_and_space_variants() {
    let fixture = match start_mysql().await {
        Ok(fixture) => fixture,
        Err(error) => {
            fail_in_ci_else_skip(
                "mysql_byte_exact_identity_accepts_unicode_and_space_variants",
                "MySQL 8.4",
                &error,
            );
            return;
        }
    };
    let store = connect_store(&fixture.url).await;

    let username_collation: String = sqlx::query_scalar(
        "SELECT COLLATION_NAME FROM information_schema.COLUMNS \
         WHERE TABLE_SCHEMA = DATABASE() \
           AND TABLE_NAME = 'consumers' AND COLUMN_NAME = 'username'",
    )
    .fetch_one(&fixture.pool)
    .await
    .expect("inspect consumers.username collation");
    assert_eq!(
        username_collation, "utf8mb4_0900_bin",
        "V001 must apply binary collation on consumers.username"
    );

    let identity_collation: String = sqlx::query_scalar(
        "SELECT COLLATION_NAME FROM information_schema.COLUMNS \
         WHERE TABLE_SCHEMA = DATABASE() \
           AND TABLE_NAME = 'consumer_identity_index' \
           AND COLUMN_NAME = 'identity_value'",
    )
    .fetch_one(&fixture.pool)
    .await
    .expect("inspect consumer_identity_index.identity_value collation");
    assert_eq!(
        identity_collation, "utf8mb4_0900_bin",
        "V001 must apply binary collation on identity_value"
    );

    let pad_attribute: String = sqlx::query_scalar(
        "SELECT PAD_ATTRIBUTE FROM information_schema.COLLATIONS \
         WHERE COLLATION_NAME = 'utf8mb4_0900_bin'",
    )
    .fetch_one(&fixture.pool)
    .await
    .expect("inspect utf8mb4_0900_bin padding semantics");
    assert_eq!(
        pad_attribute, "NO PAD",
        "byte-exact VARCHAR identity comparison must preserve trailing spaces"
    );

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
        .expect("NFD username must insert as a distinct identity under utf8mb4_0900_bin");
    store
        .create_consumer(&make_consumer("ferrum", "plain-consumer", "alice"))
        .await
        .expect("plain username must insert");
    store
        .create_consumer(&make_consumer("ferrum", "space-consumer", "alice "))
        .await
        .expect("trailing-space username must insert as a distinct identity");

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
    let loaded_space = store
        .get_consumer("ferrum", "space-consumer")
        .await
        .expect("load trailing-space consumer")
        .expect("trailing-space consumer present");
    assert_eq!(loaded_space.username.as_bytes(), b"alice ");

    assert!(
        store
            .check_consumer_identity_unique("ferrum", "other", "alice", None, None)
            .await
            .expect("plain identity probe")
            .is_some(),
        "plain username must collide with the plain consumer only"
    );
    assert!(
        store
            .check_consumer_identity_unique("ferrum", "other", "alice ", None, None)
            .await
            .expect("trailing-space identity probe")
            .is_some(),
        "trailing-space username must collide with the spaced consumer only"
    );

    let count: i64 = sqlx::query_scalar(
        "SELECT CAST(COUNT(*) AS SIGNED) FROM consumers WHERE namespace = 'ferrum'",
    )
    .fetch_one(&fixture.pool)
    .await
    .expect("count consumers");
    assert_eq!(count, 4);
}
