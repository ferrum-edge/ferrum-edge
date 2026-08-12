//! Upstream `(namespace, name)` uniqueness (issue #2999).
//!
//! The admin name precheck is raceable without the namespace config admission
//! lease. The durable backstop is the baseline unique index
//! (`idx_upstreams_namespace_name` / Mongo partial unique on string names).
//! These tests exercise that persistence invariant on SQLite (same
//! `DatabaseStore` path as PostgreSQL/MySQL behind dialect SQL rendering).

use chrono::Utc;
use ferrum_edge::config::db_backend::DatabaseBackend;
use ferrum_edge::config::db_loader::{DatabaseStore, DbPoolConfig};
use ferrum_edge::config::types::{LoadBalancerAlgorithm, Upstream, UpstreamTarget};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use tempfile::TempDir;

async fn sqlite_store() -> (DatabaseStore, TempDir) {
    let temp_dir = TempDir::new().unwrap();
    let db_path = temp_dir.path().join("upstream_name_unique.db");
    let db_url = format!("sqlite:{}?mode=rwc", db_path.to_string_lossy());
    let store = DatabaseStore::connect_with_pool_config(
        "sqlite",
        &db_url,
        DbPoolConfig {
            // Concurrent writers need more than one connection.
            max_connections: 4,
            min_connections: 2,
            ..DbPoolConfig::default()
        },
    )
    .await
    .expect("SQLite store creation must succeed");
    store
        .run_migrations()
        .await
        .expect("migrations must succeed");
    (store, temp_dir)
}

fn named_upstream(namespace: &str, id: &str, name: Option<&str>) -> Upstream {
    Upstream {
        id: id.to_string(),
        namespace: namespace.to_string(),
        name: name.map(str::to_string),
        targets: vec![UpstreamTarget {
            host: "10.0.0.1".to_string(),
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
        dispatch_port_override_fallback: None,
        api_spec_id: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
        k8s_service_uid: None,
        pending_limit_scope: None,
    }
}

fn assert_unique_violation(err: &anyhow::Error) {
    let msg = err.to_string().to_lowercase();
    assert!(
        msg.contains("unique constraint")
            || msg.contains("duplicate key")
            || msg.contains("duplicate entry"),
        "expected a unique-constraint violation, got: {msg}"
    );
}

#[tokio::test]
async fn sequential_duplicate_upstream_name_is_rejected() {
    let (store, _tmp) = sqlite_store().await;

    store
        .create_upstream(&named_upstream("ferrum", "u1", Some("shared")))
        .await
        .expect("first upstream must persist");

    let err = store
        .create_upstream(&named_upstream("ferrum", "u2", Some("shared")))
        .await
        .expect_err("duplicate (namespace, name) must hit the unique index");
    assert_unique_violation(&err);

    let listed = store
        .list_upstreams_paginated("ferrum", 100, 0)
        .await
        .expect("list must succeed");
    assert_eq!(listed.total, 1);
    assert_eq!(listed.items.len(), 1);
    assert_eq!(listed.items[0].id, "u1");
}

#[tokio::test]
async fn concurrent_create_upstream_same_name_admits_exactly_one() {
    let (store, _tmp) = sqlite_store().await;
    let store = Arc::new(store);
    let barrier = Arc::new(tokio::sync::Barrier::new(2));
    let successes = Arc::new(AtomicUsize::new(0));
    let unique_failures = Arc::new(AtomicUsize::new(0));
    let other_failures = Arc::new(AtomicUsize::new(0));

    let run = |id: &'static str| {
        let store = store.clone();
        let barrier = barrier.clone();
        let successes = successes.clone();
        let unique_failures = unique_failures.clone();
        let other_failures = other_failures.clone();
        async move {
            barrier.wait().await;
            match store
                .create_upstream(&named_upstream("ferrum", id, Some("raced-name")))
                .await
            {
                Ok(()) => {
                    successes.fetch_add(1, Ordering::Relaxed);
                }
                Err(error) => {
                    let msg = error.to_string().to_lowercase();
                    if msg.contains("unique constraint")
                        || msg.contains("duplicate key")
                        || msg.contains("duplicate entry")
                    {
                        unique_failures.fetch_add(1, Ordering::Relaxed);
                    } else {
                        other_failures.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
        }
    };

    let ((), ()) = tokio::join!(run("race-a"), run("race-b"));

    assert_eq!(
        successes.load(Ordering::Relaxed),
        1,
        "exactly one concurrent create_upstream must commit"
    );
    assert_eq!(
        unique_failures.load(Ordering::Relaxed),
        1,
        "the losing create must surface as a unique-constraint violation"
    );
    assert_eq!(
        other_failures.load(Ordering::Relaxed),
        0,
        "no non-uniqueness failures expected"
    );

    let listed = store
        .list_upstreams_paginated("ferrum", 100, 0)
        .await
        .expect("list must succeed");
    assert_eq!(listed.total, 1, "exactly one named upstream must remain");
    assert_eq!(listed.items.len(), 1);
    assert_eq!(listed.items[0].name.as_deref(), Some("raced-name"));
}

#[tokio::test]
async fn update_keeping_own_name_succeeds() {
    let (store, _tmp) = sqlite_store().await;

    store
        .create_upstream(&named_upstream("ferrum", "u1", Some("keep-me")))
        .await
        .expect("create must succeed");

    let mut updated = named_upstream("ferrum", "u1", Some("keep-me"));
    updated.targets[0].port = 9090;
    updated.updated_at = Utc::now();
    let matched = store
        .update_upstream(&updated)
        .await
        .expect("self-same name update must not collide");
    assert!(matched);

    let loaded = store
        .get_upstream("ferrum", "u1")
        .await
        .expect("get must succeed")
        .expect("upstream must exist");
    assert_eq!(loaded.name.as_deref(), Some("keep-me"));
    assert_eq!(loaded.targets[0].port, 9090);
}

#[tokio::test]
async fn update_stealing_another_upstream_name_is_rejected() {
    let (store, _tmp) = sqlite_store().await;

    store
        .create_upstream(&named_upstream("ferrum", "u1", Some("alpha")))
        .await
        .expect("u1 must persist");
    store
        .create_upstream(&named_upstream("ferrum", "u2", Some("beta")))
        .await
        .expect("u2 must persist");

    let err = store
        .update_upstream(&named_upstream("ferrum", "u2", Some("alpha")))
        .await
        .expect_err("stealing another upstream's name must hit the unique index");
    assert_unique_violation(&err);

    let loaded = store
        .get_upstream("ferrum", "u2")
        .await
        .expect("get must succeed")
        .expect("u2 must still exist");
    assert_eq!(loaded.name.as_deref(), Some("beta"));
}

#[tokio::test]
async fn unnamed_upstreams_may_coexist_and_names_are_per_namespace() {
    let (store, _tmp) = sqlite_store().await;

    store
        .create_upstream(&named_upstream("ferrum", "unnamed-a", None))
        .await
        .expect("unnamed A");
    store
        .create_upstream(&named_upstream("ferrum", "unnamed-b", None))
        .await
        .expect("unnamed B must coexist");

    store
        .create_upstream(&named_upstream(
            "tenant-a",
            "tenant-a-id",
            Some("shared-name"),
        ))
        .await
        .expect("tenant-a");
    store
        .create_upstream(&named_upstream(
            "tenant-b",
            "tenant-b-id",
            Some("shared-name"),
        ))
        .await
        .expect("same name in another namespace must be allowed");
}
