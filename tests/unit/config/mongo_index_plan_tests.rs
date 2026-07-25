//! External coverage for the canonical MongoDB index plan.
//!
//! Pins plan parity across `up` / dry-run / status wiring and exercises
//! present / missing / mismatched classification without a live MongoDB.

use ferrum_edge::config::mongo_index_plan::{
    IndexPresence, REQUIRED_GUARD_COLLECTIONS, classify_guard_collections,
    classify_plan_against_live, classify_required_index, default_index_name, dry_run_lines,
    required_mongo_indexes, summarize_index,
};
use mongodb::IndexModel;
use mongodb::bson::doc;
use mongodb::options::IndexOptions;
use std::collections::{HashMap, HashSet};
use std::time::Duration;

const MONGO_STORE_SOURCE: &str = include_str!("../../../src/config/mongo_store.rs");
const MIGRATE_SOURCE: &str = include_str!("../../../src/modes/migrate.rs");
const PLAN_SOURCE: &str = include_str!("../../../src/config/mongo_index_plan.rs");

#[test]
fn canonical_plan_is_non_empty_and_covers_core_collections() {
    let plan = required_mongo_indexes();
    assert!(
        plan.len() >= 40,
        "baseline plan unexpectedly small ({})",
        plan.len()
    );

    let collections: std::collections::HashSet<&str> =
        plan.iter().map(|entry| entry.collection).collect();
    for required in [
        "proxies",
        "consumers",
        "consumer_identity_index",
        "plugin_configs",
        "upstreams",
        "api_specs",
        "audit_events",
        "config_changes",
    ] {
        assert!(
            collections.contains(required),
            "canonical plan missing collection {required}"
        );
    }

    assert_eq!(
        REQUIRED_GUARD_COLLECTIONS,
        &[
            "proxy_route_locks",
            "upstream_ref_guards",
            "mtls_dns_admission_locks",
        ]
    );

    let api_specs_unique = plan
        .iter()
        .find(|entry| {
            entry.collection == "api_specs"
                && entry.model.keys == doc! { "namespace": 1, "proxy_id": 1 }
        })
        .expect("api_specs (namespace, proxy_id) index");
    assert!(
        api_specs_unique.recreate_on_options_conflict,
        "api_specs unique+partial must recreate on options conflict"
    );
}

#[test]
fn dry_run_lines_are_generated_from_canonical_plan() {
    let plan = required_mongo_indexes();
    let lines = dry_run_lines();
    let joined = lines.join("\n");

    assert!(
        joined.contains("canonical plan"),
        "dry-run must identify the canonical plan source"
    );
    for entry in &plan {
        let summary = summarize_index(&entry.model);
        assert!(
            joined.contains(&summary),
            "dry-run missing plan entry {}.{}",
            entry.collection,
            summary
        );
    }
    for collection in REQUIRED_GUARD_COLLECTIONS {
        assert!(
            joined.contains(collection),
            "dry-run missing guard collection {collection}"
        );
    }

    // No separately maintained four-line summary left in migrate.rs.
    assert!(
        !MIGRATE_SOURCE.contains("proxies: name (unique), updated_at, upstream_id, listen_port"),
        "migrate.rs must not keep a hard-coded Mongo dry-run summary"
    );
    assert!(
        MIGRATE_SOURCE.contains("mongo_index_plan::dry_run_lines"),
        "migrate dry-run must call mongo_index_plan::dry_run_lines"
    );
}

#[test]
fn run_migrations_and_status_consume_canonical_plan() {
    assert!(
        MONGO_STORE_SOURCE.contains("required_mongo_indexes()"),
        "run_migrations must iterate required_mongo_indexes()"
    );
    assert!(
        MONGO_STORE_SOURCE.contains("ensure_planned_index"),
        "run_migrations must apply indexes through ensure_planned_index"
    );
    assert!(
        MONGO_STORE_SOURCE.contains("migration_status"),
        "MongoStore must expose non-mutating migration_status"
    );
    assert!(
        MONGO_STORE_SOURCE.contains("list_indexes"),
        "status path must use list_indexes"
    );
    assert!(
        MIGRATE_SOURCE.contains("migration_status"),
        "migrate status must call migration_status"
    );

    let status_arm = MIGRATE_SOURCE
        .find("// MongoDB: connect and non-mutatingly compare")
        .expect("mongodb status arm");
    let status_body = &MIGRATE_SOURCE[status_arm..];
    let status_end = status_body
        .find("sqlx::any::install_default_drivers()")
        .unwrap_or(status_body.len());
    let status_body = &status_body[..status_end];
    assert!(
        status_body.contains("MongoStore::connect"),
        "mongodb status must connect before reporting"
    );
    assert!(
        status_body.contains("listIndexes only") || status_body.contains("migration_status"),
        "mongodb status must compare via migration_status"
    );
    assert!(
        MONGO_STORE_SOURCE.contains("classify_guard_collections"),
        "MongoDB status must classify the canonical guard-collection plan"
    );

    // Orphan-reconcile documentation stays on the migration path.
    let migrations_start = MONGO_STORE_SOURCE
        .find("async fn run_migrations(&self)")
        .expect("run_migrations");
    let migrations = &MONGO_STORE_SOURCE[migrations_start..];
    let migrations_end = migrations
        .find("\n        async fn list_namespaces")
        .unwrap_or(migrations.len());
    let migrations = &migrations[..migrations_end];
    assert!(
        migrations.contains("Intentionally no automatic orphan reconcile"),
        "migrations must document why automatic orphan reclaim is omitted"
    );
    assert!(
        !migrations.contains("reconcile_orphaned_consumer_identity_reservations"),
        "startup migrations must not reclaim reservations from point-read consumer absence"
    );
}

#[test]
fn guard_collection_status_uses_the_canonical_collection_plan() {
    let live = HashSet::from([
        "proxy_route_locks".to_string(),
        "mtls_dns_admission_locks".to_string(),
    ]);

    let status = classify_guard_collections(&live);
    assert_eq!(status.len(), REQUIRED_GUARD_COLLECTIONS.len());
    assert!(
        status
            .iter()
            .any(|entry| entry.collection == "proxy_route_locks" && entry.present)
    );
    assert!(
        status
            .iter()
            .any(|entry| entry.collection == "upstream_ref_guards" && !entry.present)
    );
    assert!(
        status
            .iter()
            .any(|entry| entry.collection == "mtls_dns_admission_locks" && entry.present)
    );
}

#[test]
fn classify_required_index_present_missing_mismatched() {
    let required = IndexModel::builder()
        .keys(doc! { "namespace": 1, "proxy_id": 1 })
        .options(
            IndexOptions::builder()
                .unique(true)
                .partial_filter_expression(doc! { "proxy_id": { "$type": "string" } })
                .build(),
        )
        .build();

    assert_eq!(
        classify_required_index(&required, &[]),
        IndexPresence::Missing
    );

    let matching = IndexModel::builder()
        .keys(doc! { "namespace": 1, "proxy_id": 1 })
        .options(
            IndexOptions::builder()
                .name("namespace_1_proxy_id_1".to_string())
                .unique(true)
                .partial_filter_expression(doc! { "proxy_id": { "$type": "string" } })
                .build(),
        )
        .build();
    assert_eq!(
        classify_required_index(&required, std::slice::from_ref(&matching)),
        IndexPresence::Present
    );

    let legacy_unique_only = IndexModel::builder()
        .keys(doc! { "namespace": 1, "proxy_id": 1 })
        .options(IndexOptions::builder().unique(true).build())
        .build();
    match classify_required_index(&required, &[legacy_unique_only]) {
        IndexPresence::Mismatched { detail } => {
            assert!(
                detail.contains("partialFilterExpression"),
                "mismatch detail should mention partial filter: {detail}"
            );
        }
        other => panic!("expected mismatched for legacy unique-only index, got {other:?}"),
    }

    let matching_after_mismatch = IndexModel::builder()
        .keys(doc! { "namespace": 1, "proxy_id": 1 })
        .options(
            IndexOptions::builder()
                .unique(true)
                .partial_filter_expression(doc! { "proxy_id": { "$type": "string" } })
                .build(),
        )
        .build();
    let mismatched_first = IndexModel::builder()
        .keys(doc! { "namespace": 1, "proxy_id": 1 })
        .options(IndexOptions::builder().unique(true).build())
        .build();
    assert_eq!(
        classify_required_index(&required, &[mismatched_first, matching_after_mismatch]),
        IndexPresence::Present,
        "any exact same-key candidate must satisfy the canonical plan"
    );

    let unexpected_ttl = IndexModel::builder()
        .keys(doc! { "namespace": 1, "proxy_id": 1 })
        .options(
            IndexOptions::builder()
                .unique(true)
                .partial_filter_expression(doc! { "proxy_id": { "$type": "string" } })
                .expire_after(Duration::from_secs(60))
                .build(),
        )
        .build();
    match classify_required_index(&required, &[unexpected_ttl]) {
        IndexPresence::Mismatched { detail } => {
            assert!(
                detail.contains("expireAfterSeconds"),
                "semantic TTL drift must be reported: {detail}"
            );
        }
        other => panic!("expected mismatched for unexpected TTL index, got {other:?}"),
    }

    let wrong_keys = IndexModel::builder()
        .keys(doc! { "proxy_id": 1 })
        .options(IndexOptions::builder().unique(true).build())
        .build();
    assert_eq!(
        classify_required_index(&required, &[wrong_keys]),
        IndexPresence::Missing
    );
}

#[test]
fn classify_plan_against_live_reports_mixed_presence() {
    let plan = required_mongo_indexes();
    let sample = plan
        .iter()
        .find(|entry| entry.collection == "proxies")
        .expect("proxies entry");

    let mut live = HashMap::new();
    live.insert(
        "proxies".to_string(),
        vec![
            IndexModel::builder()
                .keys(sample.model.keys.clone())
                .options(sample.model.options.clone())
                .build(),
        ],
    );

    let report = classify_plan_against_live(&live);
    assert_eq!(report.len(), plan.len());

    let present = report
        .iter()
        .filter(|e| e.presence == IndexPresence::Present)
        .count();
    let missing = report
        .iter()
        .filter(|e| matches!(e.presence, IndexPresence::Missing))
        .count();
    assert_eq!(present, 1);
    assert_eq!(missing, plan.len() - 1);
}

#[test]
fn default_index_name_matches_mongo_driver_convention() {
    assert_eq!(
        default_index_name(&doc! { "namespace": 1, "proxy_id": 1 }),
        "namespace_1_proxy_id_1"
    );
    assert_eq!(
        default_index_name(&doc! { "namespace": 1, "created_at": -1 }),
        "namespace_1_created_at_-1"
    );
}

#[test]
fn plan_module_is_the_sole_index_definition_home() {
    // `up` must not re-declare IndexModel builders inline once the plan module
    // owns definitions — keep the migration body as an apply loop.
    let migrations_start = MONGO_STORE_SOURCE
        .find("async fn run_migrations(&self)")
        .expect("run_migrations");
    let migrations = &MONGO_STORE_SOURCE[migrations_start..];
    let migrations_end = migrations
        .find("\n        async fn list_namespaces")
        .unwrap_or(migrations.len());
    let migrations = &migrations[..migrations_end];
    assert!(
        !migrations.contains("IndexModel::builder()"),
        "run_migrations must not embed IndexModel builders; use the canonical plan"
    );
    assert!(
        PLAN_SOURCE.contains("pub fn required_mongo_indexes"),
        "plan module must export required_mongo_indexes"
    );
}
