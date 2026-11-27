//! Store-level contract of the Admin API list filters (`q`, `ids`, the viewer
//! `name` guard) and of the collection revision, on SQLite, PostgreSQL 17 and
//! MySQL 8.4:
//!
//! - ASCII-only case folding on every dialect (the Kelvin sign `U+212A` is not
//!   `k`, `É` is not `é`), literal `%` / `_` / `!`, and `total` = matches;
//! - `ids` returns the named rows, missing ids absent;
//! - concurrent writers: whenever two revision reads bracket a read of the
//!   collection and agree, the collection content is a function of that
//!   revision (no two bracketed reads with one revision ever disagree), the
//!   revision moves with every committed write, and a write to one collection
//!   never moves another collection's revision.
//!
//! The module name contains `mysql` so the Service Integration job's
//! exhaustive filter list (whose `mysql` entry matches test paths by
//! substring) runs all three backends.

use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;
use std::time::Duration;

use ferrum_edge::_test_support::DbPoolConfig;
use ferrum_edge::config::db_loader::DatabaseStore;
use ferrum_edge::config::list_query::{ResourceListFilter, SearchTerm};
use ferrum_edge::config::types::{Consumer, LoadBalancerAlgorithm, Upstream, UpstreamTarget};
use ferrum_edge::time_compat::UtcTimestamp;
use testcontainers::core::IntoContainerPort;
use testcontainers::runners::AsyncRunner;
use testcontainers::{ContainerAsync, GenericImage, ImageExt};

use super::common::containers::{BoxError, fail_in_ci_else_skip, start_within_deadline};
use super::common::host_ports::{allocate_host_port, retry_on_host_port_collision};

const NAMESPACE: &str = "listq";

fn upstream(id: &str, name: &str) -> Upstream {
    Upstream {
        labels: Default::default(),
        id: id.to_string(),
        namespace: NAMESPACE.to_string(),
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
        source_labels: Default::default(),
        locality_lb_strict: false,
        locality_lb_setting: None,
        backend_tls_client_cert_path: None,
        backend_tls_client_key_path: None,
        backend_tls_verify_server_cert: true,
        backend_tls_server_ca_cert_path: None,
        backend_tls_sni: None,
        backend_tls_san_allow_list: Vec::new(),
        resolved_subset_tls: Default::default(),
        backend_tls_refused: false,
        dispatch_port_override_fallback: None,
        api_spec_id: None,
        created_at: UtcTimestamp::now(),
        updated_at: UtcTimestamp::now(),
        k8s_service_uid: None,
        admission_upstream_id: None,
        pending_limit_scope: None,
    }
}

fn consumer(id: &str, username: &str, custom_id: Option<&str>) -> Consumer {
    Consumer {
        labels: Default::default(),
        id: id.to_string(),
        namespace: NAMESPACE.to_string(),
        username: username.to_string(),
        custom_id: custom_id.map(str::to_string),
        credentials: Default::default(),
        acl_groups: Vec::new(),
        created_at: UtcTimestamp::now(),
        updated_at: UtcTimestamp::now(),
    }
}

fn search(term: &str) -> ResourceListFilter {
    ResourceListFilter {
        search: SearchTerm::parse(term).expect("valid term"),
        ..Default::default()
    }
}

async fn connect_store(db_type: &str, url: &str) -> DatabaseStore {
    let pool_config = DbPoolConfig {
        max_connections: 8,
        min_connections: 1,
        acquire_timeout_seconds: 10,
        statement_timeout_seconds: 0,
        ..DbPoolConfig::default()
    };
    DatabaseStore::connect_with_pool_config(db_type, url, pool_config)
        .await
        .unwrap_or_else(|error| panic!("{db_type} store connect + migrations: {error:#}"))
}

async fn consumer_ids(store: &DatabaseStore, filter: &ResourceListFilter) -> (Vec<String>, i64) {
    let page = store
        .list_consumers_filtered(NAMESPACE, filter, 100, 0)
        .await
        .expect("filtered consumer list");
    (page.items.into_iter().map(|c| c.id).collect(), page.total)
}

async fn run_store_contract(store: Arc<DatabaseStore>, label: &str, writers: usize) {
    for (id, username, custom_id) in [
        ("c-1", "Alice", Some("CRM-1")),
        ("c-2", "\u{212A}elvin", None),
        ("c-3", "café", None),
        ("c-4", "50% off", None),
        ("c-5", "a_b", None),
        ("c-6", "axb", None),
        ("c-7", "wow!", None),
    ] {
        store
            .create_consumer(&consumer(id, username, custom_id))
            .await
            .unwrap_or_else(|error| panic!("{label}: create {id}: {error:#}"));
    }

    let cases: &[(&str, &[&str])] = &[
        ("ALICE", &["c-1"]),
        ("crm-1", &["c-1"]),
        // Unicode folding would map U+212A to `k`; ASCII-only folding must not.
        ("KELVIN", &[]),
        ("elvin", &["c-2"]),
        ("café", &["c-3"]),
        ("CAFÉ", &[]),
        ("cafe", &[]),
        ("%", &["c-4"]),
        ("50%", &["c-4"]),
        ("_", &["c-5"]),
        ("a_b", &["c-5"]),
        ("!", &["c-7"]),
        ("C-", &["c-1", "c-2", "c-3", "c-4", "c-5", "c-6", "c-7"]),
    ];
    for (term, expected) in cases {
        let (ids, total) = consumer_ids(&store, &search(term)).await;
        assert_eq!(ids, expected.to_vec(), "{label}: q={term:?}");
        assert_eq!(
            total,
            expected.len() as i64,
            "{label}: total for q={term:?}"
        );
    }

    let by_ids = ResourceListFilter {
        ids: Some(vec!["c-3".into(), "c-1".into(), "c-missing".into()]),
        ..Default::default()
    };
    assert_eq!(
        consumer_ids(&store, &by_ids).await,
        (vec!["c-1".into(), "c-3".into()], 2),
        "{label}"
    );
    let both = ResourceListFilter {
        search: SearchTerm::parse("alice").unwrap(),
        ids: Some(vec!["c-1".into(), "c-2".into()]),
        exclude_at_sign_names: false,
    };
    assert_eq!(
        consumer_ids(&store, &both).await,
        (vec!["c-1".into()], 1),
        "{label}"
    );

    // The viewer `name` guard.
    store
        .create_upstream(&upstream("u-secret", "https://ops:hunter2@example.com"))
        .await
        .expect("create upstream");
    store
        .create_upstream(&upstream("u-plain", "Hunter Pool"))
        .await
        .expect("create upstream");
    let unguarded = store
        .list_upstreams_filtered(NAMESPACE, &search("hunter"), 100, 0)
        .await
        .unwrap();
    assert_eq!(unguarded.total, 2, "{label}");
    let guarded = ResourceListFilter {
        exclude_at_sign_names: true,
        ..search("hunter")
    };
    let guarded = store
        .list_upstreams_filtered(NAMESPACE, &guarded, 100, 0)
        .await
        .unwrap();
    let guarded_ids: Vec<String> = guarded.items.into_iter().map(|u| u.id).collect();
    assert_eq!(guarded_ids, ["u-plain"], "{label}");

    run_concurrent_revision_contract(store, label, writers).await;
}

/// `writer_count` concurrent writers (SQLite runs one: it has a single writer
/// lock, and the property under test is writer-vs-reader concurrency).
async fn run_concurrent_revision_contract(
    store: Arc<DatabaseStore>,
    label: &str,
    writer_count: usize,
) {
    const ROUNDS: usize = 12;
    let consumer_revision = store
        .config_collection_revision(NAMESPACE, &["consumer"])
        .await
        .unwrap();
    let initial = store
        .config_collection_revision(NAMESPACE, &["upstream"])
        .await
        .unwrap();
    assert!(initial > 0, "{label}: seeded upstreams have a revision");

    for writer in 0..writer_count {
        store
            .create_upstream(&upstream(
                &format!("u-w{writer}-0"),
                &format!("w{writer}-0"),
            ))
            .await
            .unwrap();
    }
    let mut writers = Vec::new();
    for writer in 0..writer_count {
        let store = store.clone();
        writers.push(tokio::spawn(async move {
            // Same-size churn: create the next row, then delete the previous.
            for round in 1..=ROUNDS {
                let next = format!("u-w{writer}-{round}");
                store
                    .create_upstream(&upstream(&next, &format!("w{writer}-{round}")))
                    .await
                    .expect("churn create");
                let previous = format!("u-w{writer}-{}", round - 1);
                assert!(
                    store
                        .delete_upstream(NAMESPACE, &previous)
                        .await
                        .expect("churn delete")
                );
            }
        }));
    }

    let mut by_revision: HashMap<u64, BTreeSet<String>> = HashMap::new();
    let mut bracketed = 0usize;
    loop {
        let done = writers.iter().all(|writer| writer.is_finished());
        let before = store
            .config_collection_revision(NAMESPACE, &["upstream"])
            .await
            .unwrap();
        let page = store
            .list_upstreams_filtered(NAMESPACE, &ResourceListFilter::default(), 1000, 0)
            .await
            .unwrap();
        let after = store
            .config_collection_revision(NAMESPACE, &["upstream"])
            .await
            .unwrap();
        if before == after {
            bracketed += 1;
            let ids: BTreeSet<String> = page.items.into_iter().map(|u| u.id).collect();
            assert_eq!(ids.len() as i64, page.total, "{label}");
            if let Some(previous) = by_revision.get(&before) {
                assert_eq!(
                    previous, &ids,
                    "{label}: two consistent reads of revision {before} disagree"
                );
            } else {
                by_revision.insert(before, ids);
            }
        }
        if done {
            break;
        }
    }
    for writer in writers {
        writer.await.expect("writer task");
    }
    let last = store
        .config_collection_revision(NAMESPACE, &["upstream"])
        .await
        .unwrap();
    assert!(last > initial, "{label}: revision moved with the writes");
    assert!(bracketed > 0, "{label}: at least one consistent read");
    assert_eq!(
        store
            .config_collection_revision(NAMESPACE, &["consumer"])
            .await
            .unwrap(),
        consumer_revision,
        "{label}: upstream writes must not move the consumer revision"
    );
    // The final state is the last revision's content.
    let final_ids: BTreeSet<String> = store
        .list_upstreams_filtered(NAMESPACE, &ResourceListFilter::default(), 1000, 0)
        .await
        .unwrap()
        .items
        .into_iter()
        .map(|u| u.id)
        .collect();
    let expected: BTreeSet<String> = ["u-plain".to_string(), "u-secret".to_string()]
        .into_iter()
        .chain((0..writer_count).map(|writer| format!("u-w{writer}-{ROUNDS}")))
        .collect();
    assert_eq!(final_ids, expected, "{label}");
    if let Some(seen) = by_revision.get(&last) {
        assert_eq!(seen, &final_ids, "{label}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn sqlite_admin_list_filters_and_revision_contract() {
    let directory = tempfile::TempDir::new().unwrap();
    let url = format!(
        "sqlite:{}?mode=rwc",
        directory.path().join("list-queries.db").display()
    );
    let store = Arc::new(connect_store("sqlite", &url).await);
    run_store_contract(store, "sqlite", 1).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn mysql_admin_list_filters_and_revision_contract() {
    let fixture = match super::mysql::start_mysql().await {
        Ok(fixture) => fixture,
        Err(error) => {
            fail_in_ci_else_skip(
                "mysql_admin_list_filters_and_revision_contract",
                "MySQL 8.4",
                &error,
            );
            return;
        }
    };
    let store = Arc::new(connect_store("mysql", &fixture.url).await);
    run_store_contract(store, "mysql", 2).await;
}

struct PostgresFixture {
    _container: ContainerAsync<GenericImage>,
    url: String,
}

async fn start_postgres() -> Result<PostgresFixture, BoxError> {
    const PASSWORD: &str = "ferrum-postgres-list-test-password";
    let (container, port) = retry_on_host_port_collision(|| async {
        let host_port = allocate_host_port()?;
        let container = start_within_deadline("PostgreSQL", || {
            GenericImage::new("postgres", "17")
                .with_exposed_port(5432.tcp())
                .with_mapped_port(host_port, 5432.tcp())
                .with_env_var("POSTGRES_USER", "ferrum")
                .with_env_var("POSTGRES_PASSWORD", PASSWORD)
                .with_env_var("POSTGRES_DB", "ferrum")
                .start()
        })
        .await?;
        Ok((container, host_port))
    })
    .await?;
    let url = format!("postgres://ferrum:{PASSWORD}@127.0.0.1:{port}/ferrum");

    sqlx::any::install_default_drivers();
    // Prove the published mapping from the host before any assertion. The
    // image's init server restarts once, so require a working query.
    let mut last_error = String::new();
    for _ in 0..120 {
        match sqlx::any::AnyPoolOptions::new()
            .max_connections(1)
            .acquire_timeout(Duration::from_secs(2))
            .connect(&url)
            .await
        {
            Ok(pool) => match sqlx::query("SELECT 1").fetch_one(&pool).await {
                Ok(_) => {
                    return Ok(PostgresFixture {
                        _container: container,
                        url,
                    });
                }
                Err(error) => last_error = error.to_string(),
            },
            Err(error) => last_error = error.to_string(),
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    Err(format!("PostgreSQL connect readiness not reached: {last_error}").into())
}

#[tokio::test(flavor = "multi_thread")]
async fn postgres_admin_list_filters_and_revision_contract() {
    let fixture = match start_postgres().await {
        Ok(fixture) => fixture,
        Err(error) => {
            fail_in_ci_else_skip(
                "postgres_admin_list_filters_and_revision_contract",
                "PostgreSQL 17",
                &error,
            );
            return;
        }
    };
    let store = Arc::new(connect_store("postgres", &fixture.url).await);
    run_store_contract(store, "postgres", 2).await;
}
