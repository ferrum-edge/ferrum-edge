//! Unit coverage for the MongoDB config store's pure builders.
//!
//! The migration lease normally acquires/renews via an aggregation-pipeline
//! update that stamps expiry/renewal from MongoDB SERVER time (`$$NOW`), which
//! is immune to client clock skew. AWS DocumentDB is documented as
//! MongoDB-compatible but does NOT support pipeline-form updates, so the lease
//! falls back to classic operator updates stamped from the CLIENT clock. These
//! tests pin the classic builder shapes and the command-error capability
//! detection without requiring a live DocumentDB backend.

use ferrum_edge::_test_support::{
    mongo_migration_lease_acquire_filter_classic, mongo_migration_lease_acquire_update_classic,
    mongo_migration_lease_duration_millis, mongo_migration_lease_renew_update_classic,
    mongo_mtls_dns_admission_drop_must_retain, mongo_mtls_dns_admission_lock_filter,
    mongo_mtls_dns_admission_lock_update, mongo_pipeline_update_unsupported,
    mtls_dns_policy_requires_consumer_load,
};
use ferrum_edge::config::types::{GatewayConfig, PluginConfig, PluginScope};
use serde_json::json;

const OWNER: &str = "test-owner-uuid";
// Fixed client-clock instant so the builders are deterministic (no DateTime::now).
const NOW_MILLIS: i64 = 1_700_000_000_000;

fn expiry_millis() -> i64 {
    NOW_MILLIS + mongo_migration_lease_duration_millis()
}

fn mongo_command_error(code: i32, message: &str) -> mongodb::error::Error {
    let command_error: mongodb::error::CommandError = mongodb::bson::from_document(
        mongodb::bson::doc! { "code": code, "codeName": "TestCommandError", "errmsg": message },
    )
    .unwrap();
    mongodb::error::ErrorKind::Command(command_error).into()
}

#[test]
fn pipeline_update_rejection_matches_unsupported_and_type_error_shapes() {
    for error in [
        mongo_command_error(303, "Aggregation pipeline updates are not supported"),
        mongo_command_error(
            14,
            "The update value must be an object, but received an array",
        ),
    ] {
        assert!(
            mongo_pipeline_update_unsupported(&error),
            "DocumentDB pipeline rejection must select the classic lease: {error}"
        );
    }
}

#[test]
fn pipeline_update_rejection_excludes_contention_connectivity_and_auth() {
    let duplicate_key = mongo_command_error(11_000, "duplicate key during update");
    assert!(!mongo_pipeline_update_unsupported(&duplicate_key));

    let network_error: mongodb::error::Error = std::io::Error::new(
        std::io::ErrorKind::ConnectionReset,
        "connection reset during update",
    )
    .into();
    assert!(!mongo_pipeline_update_unsupported(&network_error));

    let unauthorized = mongo_command_error(13, "not authorized to execute update command");
    assert!(!mongo_pipeline_update_unsupported(&unauthorized));
}

#[test]
fn migration_lease_duration_is_120_seconds() {
    // The classic fallback must keep the same 120s lease window as the pipeline.
    assert_eq!(mongo_migration_lease_duration_millis(), 120_000);
}

#[test]
fn mtls_dns_admission_lock_has_no_expiry_takeover_path() {
    let filter = mongo_mtls_dns_admission_lock_filter("default", OWNER);
    assert_eq!(filter.get_str("_id").unwrap(), "default");
    assert!(
        !filter.contains_key("expires_at") && !format!("{filter:?}").contains("expires_at"),
        "admission lock filter must never admit an expired-owner takeover: {filter:?}"
    );
    let clauses = filter.get_array("$or").unwrap();
    assert_eq!(clauses.len(), 2);
    assert_eq!(
        clauses[1].as_document().unwrap().get_str("owner").unwrap(),
        OWNER
    );

    let update = mongo_mtls_dns_admission_lock_update(OWNER, NOW_MILLIS);
    let set = update.get_document("$set").unwrap();
    assert_eq!(set.get_str("owner").unwrap(), OWNER);
    assert!(set.get("expires_at").is_none());
    assert!(
        update
            .get_document("$unset")
            .unwrap()
            .contains_key("expires_at"),
        "admission lock must erase any expiry field: {update:?}"
    );
}

#[test]
fn mtls_dns_admission_drop_retains_only_uncertain_mutations() {
    assert!(
        mongo_mtls_dns_admission_drop_must_retain(true, false),
        "a dispatched mutation without a settled outcome must keep the durable fence"
    );
    assert!(
        !mongo_mtls_dns_admission_drop_must_retain(false, false),
        "pre-mutation validation cancellation may clean up its unused fence"
    );
    assert!(
        !mongo_mtls_dns_admission_drop_must_retain(true, true),
        "an explicit settled release may retry owner-qualified cleanup"
    );
}

#[test]
fn mtls_dns_policy_gate_skips_consumers_until_san_dns_is_effective() {
    let now = chrono::Utc::now();
    let mut config = GatewayConfig {
        plugin_configs: vec![PluginConfig {
            id: "dns-mtls".to_string(),
            namespace: "ferrum".to_string(),
            plugin_name: "mtls_auth".to_string(),
            enabled: false,
            config: json!({"cert_field": "san_dns"}),
            scope: PluginScope::Global,
            proxy_id: None,
            priority_override: None,
            api_spec_id: None,
            created_at: now,
            updated_at: now,
        }],
        ..Default::default()
    };
    assert!(!mtls_dns_policy_requires_consumer_load(&config));
    config.plugin_configs[0].enabled = true;
    assert!(mtls_dns_policy_requires_consumer_load(&config));
}

#[test]
fn classic_acquire_filter_matches_missing_expired_or_owned_lease() {
    let filter = mongo_migration_lease_acquire_filter_classic(OWNER, NOW_MILLIS);
    assert_eq!(filter.get_str("_id").unwrap(), "global");

    let clauses = filter.get_array("$or").unwrap();
    assert_eq!(
        clauses.len(),
        3,
        "classic acquire filter must offer exactly the three claimable cases: {filter:?}"
    );

    // 1) lock document has no expires_at (never held / freshly upserted).
    let missing = clauses[0].as_document().unwrap();
    assert!(
        !missing
            .get_document("expires_at")
            .unwrap()
            .get_bool("$exists")
            .unwrap(),
        "first clause must match a missing expires_at: {missing:?}"
    );

    // 2) lock expired by the CLIENT clock (client-time comparison).
    let expired = clauses[1].as_document().unwrap();
    assert_eq!(
        expired
            .get_document("expires_at")
            .unwrap()
            .get_datetime("$lte")
            .unwrap()
            .timestamp_millis(),
        NOW_MILLIS,
        "second clause must expire against the client clock: {expired:?}"
    );

    // 3) lock already owned by us (re-entrant renewal via acquire).
    let owned = clauses[2].as_document().unwrap();
    assert_eq!(owned.get_str("owner").unwrap(), OWNER);
}

#[test]
fn classic_acquire_update_stamps_client_time_expiry_and_created_on_insert() {
    let update = mongo_migration_lease_acquire_update_classic(OWNER, NOW_MILLIS);

    let set = update.get_document("$set").unwrap();
    assert_eq!(set.get_str("owner").unwrap(), OWNER);
    assert_eq!(
        set.get_datetime("expires_at").unwrap().timestamp_millis(),
        expiry_millis(),
        "acquire must stamp expires_at at client now + lease duration: {set:?}"
    );
    assert_eq!(
        set.get_datetime("updated_at").unwrap().timestamp_millis(),
        NOW_MILLIS
    );
    // created_at is written ONLY on insert, never on a takeover of an expired
    // lease, so the original creation time survives.
    assert!(
        set.get("created_at").is_none(),
        "$set must not rewrite created_at: {set:?}"
    );
    let set_on_insert = update.get_document("$setOnInsert").unwrap();
    assert_eq!(
        set_on_insert
            .get_datetime("created_at")
            .unwrap()
            .timestamp_millis(),
        NOW_MILLIS
    );
}

#[test]
fn classic_renew_update_refreshes_expiry_without_touching_ownership() {
    let update = mongo_migration_lease_renew_update_classic(NOW_MILLIS);

    let set = update.get_document("$set").unwrap();
    assert_eq!(
        set.get_datetime("expires_at").unwrap().timestamp_millis(),
        expiry_millis(),
        "renew must extend expires_at to client now + lease duration: {set:?}"
    );
    assert_eq!(
        set.get_datetime("updated_at").unwrap().timestamp_millis(),
        NOW_MILLIS
    );
    // Renew relies on the owner match in the query filter, so the update must
    // not rewrite owner or created_at.
    assert!(
        set.get("owner").is_none(),
        "renew $set must not rewrite owner: {set:?}"
    );
    assert!(
        update.get("$setOnInsert").is_none(),
        "renew must not upsert a new lock document: {update:?}"
    );
}
