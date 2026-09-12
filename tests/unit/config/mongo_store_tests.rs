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
    MongoConfigChangeOp, MongoReconnectTopology, MongoReconnectTransitionTestHooks,
    decode_mongo_config_change_record, mongo_migration_lease_acquire_filter_classic,
    mongo_migration_lease_acquire_update_classic, mongo_migration_lease_duration_millis,
    mongo_migration_lease_renew_update_classic, mongo_mtls_dns_admission_drop_must_retain,
    mongo_mtls_dns_admission_lock_filter, mongo_mtls_dns_admission_lock_update,
    mongo_pipeline_update_unsupported, mongo_store_acquire_connection_generation_pin_for_test,
    mongo_store_new_unconnected_for_test, mongo_store_published_database_name_for_test,
    mongo_store_set_reconnect_transition_hooks_for_test,
    mongo_store_try_publish_reconnected_bundle_for_test, mtls_dns_policy_requires_consumer_load,
};
use ferrum_edge::config::db_backend::DatabaseBackend;
use ferrum_edge::config::types::{GatewayConfig, PluginConfig, PluginScope};
use mongodb::bson::{Bson, Document, doc};
use serde_json::json;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::sync::oneshot;

const OWNER: &str = "test-owner-uuid";
const ADMIN_SOURCE: &str = include_str!("../../../src/admin/mod.rs");
const MONGO_STORE_SOURCE: &str = include_str!("../../../src/config/mongo_store.rs");
const MONGODB_DOC: &str = include_str!("../../../docs/mongodb.md");
// Fixed client-clock instant so the builders are deterministic (no DateTime::now).
const NOW_MILLIS: i64 = 1_700_000_000_000;

fn mongo_method(name: &str) -> &str {
    let marker = format!("        async fn {name}");
    let start = MONGO_STORE_SOURCE.find(&marker).unwrap();
    let tail = &MONGO_STORE_SOURCE[start + marker.len()..];
    let end = tail.find("\n        async fn ").unwrap_or(tail.len());
    &MONGO_STORE_SOURCE[start..start + marker.len() + end]
}

/// Extract a method body stopping at the next inherent `fn` or `async fn`
/// at the same indentation (avoids spilling into neighboring sync helpers).
fn mongo_fn_body(marker: &str) -> &str {
    let start = MONGO_STORE_SOURCE
        .find(marker)
        .unwrap_or_else(|| panic!("missing method marker {marker}"));
    let tail = &MONGO_STORE_SOURCE[start + marker.len()..];
    let end = tail
        .find("\n        fn ")
        .into_iter()
        .chain(tail.find("\n        async fn "))
        .min()
        .unwrap_or(tail.len());
    &MONGO_STORE_SOURCE[start..start + marker.len() + end]
}

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
fn mongo_backup_restore_api_specs_methods_exist() {
    let source = include_str!("../../../src/config/mongo_store.rs");
    assert!(
        source.contains("async fn list_api_specs_with_content("),
        "MongoStore must implement list_api_specs_with_content for backup/snapshot"
    );
    assert!(
        source.contains("async fn batch_insert_api_specs("),
        "MongoStore must implement batch_insert_api_specs for restore"
    );
    assert!(
        source.contains("async fn apply_api_spec_ownership_from_resources("),
        "MongoStore must stamp api_spec_id ownership during restore"
    );
    let load = source
        .find("async fn load_full_config_for_purpose(")
        .expect("load_full_config_for_purpose");
    let load_body = &source[load..];
    assert!(
        load_body.contains("FullConfigLoadPurpose::BackupExport")
            && load_body.contains("strip_api_spec_id_from_runtime_config"),
        "BackupExport must preserve api_spec_id while runtime loads strip it"
    );
}

/// Namespace enumeration must scan gateway_trust_bundles so a trust-only
/// namespace is still discovered by CP/admin listing (issue #3727 / PR #3782).
/// Paginated listing reuses `list_namespaces()`, so covering the merge is enough.
#[test]
fn list_namespaces_scans_gateway_trust_bundles() {
    let body = mongo_method("list_namespaces(");
    for collection in [
        "proxies",
        "consumers",
        "plugin_configs",
        "upstreams",
        "gateway_trust_bundles",
    ] {
        let needle = format!("distinct_namespaces(\"{collection}\")");
        assert!(
            body.contains(&needle),
            "list_namespaces must scan {collection}: missing {needle}"
        );
    }
    assert!(
        body.contains("registry_namespace_names()"),
        "list_namespaces must union the namespaces registry"
    );
    assert!(
        body.contains("result.sort()"),
        "list_namespaces must keep deterministic ascending order"
    );
}

/// `rollback_ids_for_unordered_insert_error` derives "documents this call
/// created" as *every id minus the reported write-error indices*. That is only
/// correct for an UNORDERED `insert_many`: an ordered insert stops at the first
/// write error, so every id after it would be reported as created and then
/// deleted by the compensating `delete_many({_id: {$in: ...}})`. Since issue
/// #4627 those `_id`s are namespace-qualified, so the over-delete can no longer
/// escape the tenant — but it would still destroy that tenant's untouched
/// documents. Every standalone batch insert paired with the helper must
/// therefore stay `.ordered(false)`.
#[test]
fn standalone_insert_rollback_is_only_paired_with_unordered_inserts() {
    const CALL: &str = "Self::rollback_ids_for_unordered_insert_error(";
    let mut searched = 0usize;
    let mut sites = 0usize;
    while let Some(offset) = MONGO_STORE_SOURCE[searched..].find(CALL) {
        let call = searched + offset;
        searched = call + 1;
        sites += 1;

        let preceding = &MONGO_STORE_SOURCE[..call];
        let insert = preceding
            .rfind(".insert_many(")
            .expect("the rollback helper must compensate a preceding insert_many");
        let ordered_at = preceding[insert..]
            .find(".ordered(")
            .expect("an insert_many compensated by the rollback helper must set ordered()");
        let ordered = &preceding[insert + ordered_at..];
        assert!(
            ordered.starts_with(".ordered(false)"),
            "insert_many compensated by rollback_ids_for_unordered_insert_error must be \
             unordered; found {}",
            ordered.chars().take(20).collect::<String>()
        );
    }
    assert!(
        sites >= 5,
        "expected every standalone batch insert rollback site to be scanned, found {sites}"
    );
}

/// Issue #4627: every namespaced resource collection stores its documents under
/// the composite `"{namespace}:{id}"` durable key, so one tenant cannot squat a
/// bare id another tenant needs.
#[test]
fn namespaced_resource_documents_use_composite_durable_keys() {
    for converter in [
        "fn proxy_to_doc(",
        "fn plugin_config_to_doc(",
        "fn upstream_to_doc(",
        "fn api_spec_to_doc(",
        "fn consumer_to_doc(",
    ] {
        let start = MONGO_STORE_SOURCE
            .find(converter)
            .unwrap_or_else(|| panic!("missing {converter}"));
        let body = &MONGO_STORE_SOURCE[start..];
        let insert = body
            .find("doc.insert(\"_id\"")
            .unwrap_or_else(|| panic!("{converter} must set _id"));
        let line_end = body[insert..]
            .find('\n')
            .map(|offset| insert + offset)
            .unwrap_or(body.len());
        let line = &body[insert..line_end];
        assert!(
            line.contains("namespaced_doc_id(") || line.contains("consumer_doc_id("),
            "{converter} must key on the composite \"{{namespace}}:{{id}}\" durable id, got: {line}"
        );
    }

    assert!(
        MONGO_STORE_SOURCE.contains(concat!(
            "fn namespaced_doc_id(namespace: &str, id: &str) -> String {\n",
            "        format!(\"{namespace}:{id}\")"
        )),
        "the composite durable key must stay \"{{namespace}}:{{id}}\""
    );
    assert!(
        MONGO_STORE_SOURCE.contains(concat!(
            "fn consumer_doc_id(namespace: &str, id: &str) -> String {\n",
            "        namespaced_doc_id(namespace, id)"
        )),
        "consumer_doc_id must remain an alias for the shared composite helper"
    );
}

#[test]
fn mongo_plugin_graph_validation_runs_under_the_durable_namespace_fence() {
    let validator = mongo_method("validate_mtls_dns_candidate_with_mode");
    let graph_validation = validator
        .find("validate_tcp_connection_throttle_attachments")
        .expect("shared Mongo candidate validation must enforce TCP throttle attachments");
    let mtls_fast_path = validator
        .find("has_effective_mtls_dns_identity_policy")
        .expect("mTLS consumer-load fast path");
    assert!(
        graph_validation < mtls_fast_path,
        "TCP graph validation must run even when no effective mTLS DNS policy loads Consumers"
    );

    for method_name in [
        "create_proxy(&self, proxy: &Proxy)",
        "update_proxy(&self, proxy: &Proxy)",
        "delete_proxy_with_orphan_cleanup(",
        "create_plugin_config(&self, pc: &PluginConfig)",
        "update_plugin_config(&self, pc: &PluginConfig)",
        "delete_plugin_config(",
        "batch_create_proxies(",
        "batch_create_plugin_configs(",
        "submit_api_spec_bundle(",
        "delete_api_spec(&self, namespace: &str, id: &str)",
    ] {
        let method = mongo_method(method_name);
        let acquire = method
            .find("acquire_mtls_dns_admission")
            .unwrap_or_else(|| panic!("{method_name} must acquire the durable namespace fence"));
        let validate = method
            .find("validate_plugin_graph")
            .unwrap_or_else(|| panic!("{method_name} must validate the guarded graph candidate"));
        let mutate = method[validate..]
            .find("run_mutation")
            .map(|offset| validate + offset)
            .or_else(|| {
                method[validate..]
                    .find("run_mtls_dns_mutations")
                    .map(|offset| validate + offset)
            })
            .unwrap_or_else(|| panic!("{method_name} must mutate only after validation"));
        assert!(
            acquire < validate && validate < mutate,
            "{method_name} must acquire, re-read/validate, then mutate in that order"
        );
    }

    let replace = mongo_method("replace_api_spec_bundle(");
    let acquire = replace.find("acquire_mtls_dns_admission").unwrap();
    let validate = replace.find("validate_plugin_graph").unwrap();
    let graph_mutation = replace[validate..].find("run_mtls_dns_mutations").unwrap() + validate;
    assert!(acquire < validate && validate < graph_mutation);
}

#[test]
fn mtls_dns_policy_gate_skips_consumers_until_san_dns_is_effective() {
    let now = chrono::Utc::now();
    let mut config = GatewayConfig {
        plugin_configs: vec![PluginConfig {
            labels: Default::default(),
            id: "dns-mtls".to_string(),
            namespace: "ferrum".to_string(),
            plugin_name: "mtls_auth".to_string(),
            enabled: false,
            config: json!({"cert_field": "san_dns"}),
            scope: PluginScope::Global,
            proxy_id: None,
            priority_override: None,
            trigger: None,
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

#[test]
fn ordered_insert_prefix_attributes_only_this_attempts_inserts() {
    use ferrum_edge::_test_support::ordered_insert_newly_inserted_prefix;

    // Rollback may release only this attempt's newly inserted prefix; adopted
    // same-owner docs (provenance unknown) stay out of the release set.
    let values = ["alice".to_string(), "alice@example.com".to_string()];
    assert_eq!(
        ordered_insert_newly_inserted_prefix(&values, Some(1)),
        &values[..1],
        "ordered E11000 at index 1 means only the leading value was inserted here"
    );
    assert_eq!(
        ordered_insert_newly_inserted_prefix(&values, Some(0)),
        &[] as &[String],
        "a conflict on the first ordered doc attributes nothing to this attempt"
    );
    assert_eq!(
        ordered_insert_newly_inserted_prefix(&values, Some(values.len())),
        &values[..],
        "an index equal to len means every ordered value was inserted here"
    );
    assert!(
        ordered_insert_newly_inserted_prefix(&values, None).is_empty(),
        "unknown write-error index ⇒ retain all (empty rollback-safe set)"
    );
    assert!(
        ordered_insert_newly_inserted_prefix(&values, Some(values.len() + 1)).is_empty(),
        "an out-of-range index is not a verifiable prefix ⇒ retain all"
    );
}

#[test]
fn adoption_failure_release_combines_ordered_prefix_and_adoption_inserts() {
    use ferrum_edge::_test_support::consumer_identity_adoption_failure_release_values;

    let ordered = [
        "alice".to_string(),
        "alice@example.com".to_string(),
        "bob".to_string(),
    ];
    // Ordered insert failed at index 1 (only "alice" from the ordered path);
    // adoption then inserted alice@example.com before conflicting on bob. The
    // failure release set is the ordered prefix plus the adoption vacant insert.
    let release = consumer_identity_adoption_failure_release_values(
        &ordered,
        Some(1),
        &["alice@example.com".to_string()],
    );
    assert_eq!(
        release,
        vec!["alice".to_string(), "alice@example.com".to_string()],
        "failure release must include ordered prefix plus adoption vacant inserts"
    );

    // Dedup: an adoption insert that is also inside the ordered prefix appears once.
    let dedup = consumer_identity_adoption_failure_release_values(
        &ordered,
        Some(1),
        &["alice".to_string(), "alice@example.com".to_string()],
    );
    assert_eq!(
        dedup,
        vec!["alice".to_string(), "alice@example.com".to_string()],
        "values in both the ordered prefix and adoption inserts must not double-release"
    );
}

#[test]
fn batch_adoption_failure_release_is_exactly_adoption_inserts_without_ordered_prefix() {
    use ferrum_edge::_test_support::consumer_identity_adoption_failure_release_values;

    // Batch-style adoption where earlier vacant docs were inserted before a later
    // conflict, and the ordered insert conflicted on its first doc (no verifiable
    // prefix). Release must be exactly the earlier adoption inserts.
    let ordered_batch = [
        "ns:alice".to_string(),
        "ns:alice@example.com".to_string(),
        "ns:stolen".to_string(),
    ];
    let adoption_inserts = ["ns:alice".to_string(), "ns:alice@example.com".to_string()];
    let release = consumer_identity_adoption_failure_release_values(
        &ordered_batch,
        Some(0),
        &adoption_inserts,
    );
    assert_eq!(
        release,
        adoption_inserts.to_vec(),
        "with empty ordered prefix, release set is exactly earlier adoption inserts"
    );
}

#[test]
fn pre_existing_same_owner_docs_stay_out_of_adoption_failure_release() {
    use ferrum_edge::_test_support::consumer_identity_adoption_failure_release_values;

    // "pre-existing" was an adopted same-owner doc (never in the adoption-inserts
    // set); "new-value" was inserted by this adoption attempt. Only "new-value"
    // is rollback-safe — a pre-existing reservation must never be released.
    let ordered = [
        "pre-existing".to_string(),
        "new-value".to_string(),
        "conflict".to_string(),
    ];
    let release = consumer_identity_adoption_failure_release_values(
        &ordered,
        Some(0), // ordered inserted nothing verifiable
        &["new-value".to_string()],
    );
    assert_eq!(release, vec!["new-value".to_string()]);
    assert!(
        !release.contains(&"pre-existing".to_string()),
        "pre-existing same-owner reservation must stay out of the release set"
    );
}

#[test]
fn unknown_ordered_insert_provenance_remains_retained_on_adoption_failure() {
    use ferrum_edge::_test_support::consumer_identity_adoption_failure_release_values;

    let ordered = [
        "maybe-inserted-a".to_string(),
        "maybe-inserted-b".to_string(),
        "conflict".to_string(),
    ];
    // None ⇒ cannot attribute any ordered-insert docs to this attempt; retain
    // them. Still release exact vacant inserts from the adoption attempt.
    let release = consumer_identity_adoption_failure_release_values(
        &ordered,
        None,
        &["adoption-vacant".to_string()],
    );
    assert_eq!(
        release,
        vec!["adoption-vacant".to_string()],
        "unknown ordered-insert provenance must remain retained; only adoption \
         vacant inserts are release-safe"
    );
    assert!(
        !release.iter().any(|v| v.starts_with("maybe-inserted")),
        "unattributed ordered-insert values must not be released"
    );
}

#[test]
fn mongo_timeout_overrides_preserve_uri_unless_env_explicit() {
    use ferrum_edge::_test_support::apply_mongo_timeout_overrides;
    use mongodb::options::ClientOptions;
    use std::time::Duration;

    let mut options = ClientOptions::default();
    options.server_selection_timeout = Some(Duration::from_millis(5_000));
    options.connect_timeout = Some(Duration::from_millis(3_000));

    apply_mongo_timeout_overrides(&mut options, None, None);
    assert_eq!(
        options.server_selection_timeout,
        Some(Duration::from_millis(5_000)),
        "URI-only serverSelectionTimeoutMS must survive when env is unset"
    );
    assert_eq!(
        options.connect_timeout,
        Some(Duration::from_millis(3_000)),
        "URI-only connectTimeoutMS must survive when env is unset"
    );

    apply_mongo_timeout_overrides(&mut options, Some(30), Some(10));
    assert_eq!(
        options.server_selection_timeout,
        Some(Duration::from_secs(30)),
        "explicit FERRUM_MONGO_SERVER_SELECTION_TIMEOUT_SECONDS must override URI"
    );
    assert_eq!(
        options.connect_timeout,
        Some(Duration::from_secs(10)),
        "explicit FERRUM_MONGO_CONNECT_TIMEOUT_SECONDS must override URI"
    );

    // Driver/default path: unset options stay unset when env is also unset.
    let mut bare = ClientOptions::default();
    apply_mongo_timeout_overrides(&mut bare, None, None);
    assert!(
        bare.server_selection_timeout.is_none() && bare.connect_timeout.is_none(),
        "defaults must not clobber absent URI timeout options"
    );
}

#[test]
fn replace_api_spec_metadata_shortcut_checks_matched_count() {
    // Issue #2989 / #4285: the hash-unchanged metadata-only shortcut must verify the
    // `replace_one` (no upsert) matched a document before reporting success, so
    // a spec raced away by a concurrent DELETE (or a dangling api_spec_id without
    // an api_specs document) surfaces an error, not a 200.
    let replace = mongo_method("replace_api_spec_bundle(");
    let shortcut = replace
        .find("Only update metadata fields on the spec doc")
        .expect("metadata-only shortcut marker");
    let matched = replace[shortcut..]
        .find("matched_count")
        .expect("metadata shortcut must verify matched_count");
    let release = replace[shortcut..]
        .find("release_mtls_dns_admission_leases")
        .expect("shortcut lease release");
    assert!(
        matched < release,
        "matched_count must be checked before the metadata shortcut returns success"
    );
}

#[test]
fn consumer_identity_reserve_paths_adopt_same_owner_on_duplicate_key() {
    let standalone = mongo_method("reserve_consumer_identity_docs_standalone(");
    assert!(
        standalone.contains("ensure_consumer_identity_docs_owned"),
        "standalone reserve must same-owner-adopt on E11000"
    );
    assert!(
        standalone.contains("is_duplicate_key"),
        "standalone reserve must classify duplicate-key before adopting"
    );
    assert!(
        standalone.contains("newly_inserted"),
        "standalone reserve must expose newly-inserted values for safe rollback"
    );
    assert!(
        standalone.contains("consumer_identity_adoption_failure_release_values"),
        "standalone reserve failure must release ordered prefix plus adoption vacant inserts"
    );

    let ensure = mongo_method("ensure_consumer_identity_docs_owned(");
    assert!(
        ensure.contains("ConsumerIdentityEnsureOwnedError"),
        "ensure must return an error type that preserves failure provenance"
    );
    assert!(
        ensure.contains("owner != consumer_id") && ensure.contains("duplicate key error"),
        "ensure must fail closed (409 duplicate-key) when a different owner holds the reservation"
    );

    // Replica-set reserve is preflight-first: the in-session wrapper delegates
    // to the preflight helper and never inserts-then-recovers after an E11000.
    let session = mongo_method("insert_consumer_identity_docs_in_session(");
    assert!(
        session.contains("preflight_reserve_consumer_identity_docs_in_session"),
        "replica-set reserve must delegate to the preflight read-then-insert helper"
    );
    assert!(
        !session.contains("ensure_consumer_identity_docs_owned_in_session")
            && !session.contains(".insert_many("),
        "replica-set reserve wrapper must not insert-then-recover inside the transaction"
    );

    // The preflight helper reads and classifies every candidate BEFORE any
    // write, fails closed on a different owner, and never recovers after an
    // in-transaction E11000 (the aborted session is not reused).
    let preflight = mongo_method("preflight_reserve_consumer_identity_docs_in_session(");
    let read = preflight
        .find("\"$in\": ids")
        .expect("preflight must batch-read candidate reservations first");
    let insert = preflight
        .find("insert_many(to_insert)")
        .expect("preflight must insert only preflight-absent candidates");
    assert!(
        read < insert,
        "preflight read must precede the reservation insert (read-then-insert)"
    );
    assert!(
        preflight.contains("!= consumer_id") && preflight.contains("duplicate key error"),
        "preflight must fail closed (409 duplicate-key) for a different-owner reservation"
    );
    assert!(
        !preflight.contains("ensure_consumer_identity_docs_owned"),
        "preflight must not run post-E11000 session recovery"
    );

    // The replica-set batch create must also preflight-reserve — no
    // insert-then-recover inside the transaction.
    let batch_method = mongo_method("batch_create_consumers(");
    assert!(
        batch_method.contains("preflight_reserve_consumer_identity_docs_in_session"),
        "replica-set batch create must preflight-reserve the identity keyspace"
    );
    assert!(
        !batch_method.contains("ensure_consumer_identity_docs_owned_in_session"),
        "replica-set batch create must not recover after an in-transaction E11000"
    );

    let create = mongo_method("create_consumer(");
    assert!(
        create.contains("newly_inserted_identity_values"),
        "create_consumer rollback must release only newly-inserted reservations"
    );

    // Batch standalone adoption failure must release ensured_new_docs, not only
    // the ordered-insert prefix.
    let batch = mongo_method("batch_create_consumers(");
    let adopt_fail = batch
        .find("still releasing vacant reservations inserted during this adoption")
        .or_else(|| batch.find("ensured_new_docs"))
        .expect("batch adoption failure must track ensured_new_docs for release");
    let release_call = batch[adopt_fail..]
        .find("release_consumer_identity_docs_best_effort")
        .expect("batch adoption failure must best-effort release tracked docs");
    assert!(
        release_call < 2500,
        "batch failure release must run on the adoption-conflict path"
    );

    let migrations = mongo_method("run_migrations(");
    assert!(
        !migrations.contains("reconcile_orphaned_consumer_identity_reservations"),
        "startup migrations must not reclaim reservations from point-read consumer absence"
    );
    assert!(
        migrations.contains("Intentionally no automatic orphan reconcile"),
        "migrations must document why automatic orphan reclaim is omitted"
    );
}

#[test]
fn mongodb_doc_pins_exactly_one_tls_source_contract() {
    // `build_connection_bundle` in mongo_store.rs rejects the combination of
    // `FERRUM_DB_TLS_MODE` with URI TLS options at startup. The docs must not
    // regress to the stale "take precedence" wording that contradicted that
    // fail-closed contract.
    assert!(
        !MONGODB_DOC.contains("take precedence"),
        "docs/mongodb.md must not claim URI TLS options 'take precedence' over \
         FERRUM_DB_TLS_* env vars; the code rejects the combination at startup"
    );
    assert!(
        MONGODB_DOC.contains("exactly one source"),
        "docs/mongodb.md must document the exactly-one-source TLS contract"
    );
}

/// MongoDB identity uniqueness is BSON string equality on
/// `"{namespace}:{identity_value}"` — already byte-exact. Issue #2994's MySQL
/// collation change must not invent Unicode normalization on this path.
#[test]
fn mongo_consumer_identity_keys_remain_raw_byte_strings() {
    let helper = MONGO_STORE_SOURCE
        .find("fn consumer_identity_doc_id(namespace: &str, value: &str) -> String")
        .expect("consumer_identity_doc_id helper");
    let body = &MONGO_STORE_SOURCE[helper..helper + 240];
    assert!(
        body.contains("format!(\"{namespace}:{value}\")"),
        "Mongo identity _id must stay a raw namespace:value concatenation"
    );
    assert!(
        !body.to_ascii_lowercase().contains("nfc")
            && !body.to_ascii_lowercase().contains("nfd")
            && !body.to_ascii_lowercase().contains("normali"),
        "Mongo identity keys must not Unicode-normalize (already byte-exact)"
    );
}

/// PR #3162 follow-up: `POST /batch` is all-or-nothing, so a confirmed commit
/// must be reported as success. Admission-lease cleanup runs *after* the graph
/// is durable and can therefore never decide the response: a cleanup error
/// would tell the caller the batch failed and invite an identical retry that
/// collides with the rows it just created.
#[test]
fn committed_batch_graph_release_cannot_fail_the_response() {
    let atomic = mongo_method("batch_create_config_graph_atomically(");
    assert!(
        atomic.contains("release_mtls_dns_admission_leases_after_commit(&mut mtls_leases).await;"),
        "the atomic batch graph must use the post-commit (infallible) lease release"
    );
    assert!(
        !atomic.contains("release_mtls_dns_admission_leases(&mut mtls_leases).await?"),
        "post-commit lease cleanup must not be able to turn a committed graph into an error"
    );

    // Every guarded write path that releases its leases only after the
    // protected mutation returned Ok has the same contract.
    assert!(
        !MONGO_STORE_SOURCE.contains("release_mtls_dns_admission_leases(&mut mtls_leases).await?"),
        "no post-commit call site may propagate admission-lease cleanup failure"
    );

    let after_commit = mongo_method("release_mtls_dns_admission_leases_after_commit(");
    let after_commit = &after_commit[..after_commit
        .find("fn mark_mtls_dns_mutations_started")
        .unwrap_or(after_commit.len())];
    assert!(
        !after_commit.contains("-> Result"),
        "the post-commit release helper must not return an error to its caller"
    );
    assert!(
        after_commit.contains("error!("),
        "post-commit cleanup trouble must still be logged loudly for operators"
    );
    assert!(
        !after_commit.contains("owner") && !after_commit.contains("secret"),
        "post-commit cleanup logging must stay redacted (namespace/lock label only)"
    );
}

/// A release loop that stops at the first failure would leave the remaining
/// guards with `InFlightOrUncertain` mutation state, so their `Drop` would
/// strand both the non-expiring lock document and this process's connection
/// generation pin even though the protected outcome is already settled.
#[test]
fn admission_lease_release_drains_every_guard_before_reporting() {
    let release = mongo_method("release_mtls_dns_admission_leases(");
    assert!(
        !release.contains("lease.release().await?"),
        "the release loop must not return early and strand later guards"
    );
    assert!(
        release.contains("while let Some(mut lease) = leases.pop()")
            && release.contains("first_error"),
        "the release loop must drain the vector and report the first failure"
    );

    // Fail-closed pre-commit behavior is unchanged: a definitively failed
    // mutation still surfaces an error to the caller. The source marker uses
    // `<` because the method is generic (`run_mtls_dns_mutations<T, F>(`);
    // searching for `name(` would miss it.
    let run = mongo_method("run_mtls_dns_mutations<");
    assert!(
        run.contains("mongo_mutation_outcome_is_uncertain(&error) => Err(error)"),
        "an uncertain mutation outcome must still retain its leases and fail closed"
    );
    assert!(
        run.contains("Self::release_mtls_dns_admission_leases(leases).await?;"),
        "a definitively failed mutation must still release and return an error"
    );
}

/// Mongo batch writers serialize the documents they receive. Domain hostname /
/// SNI / SAN / blank-ID canonicalization must happen in restore/CRUD admission
/// before `proxy_to_doc` / `upstream_to_doc` / `consumer_to_doc` (issue #2402).
#[test]
fn mongo_batch_create_serializers_do_not_repeat_domain_normalization() {
    for (helper_name, forbidden) in [
        (
            "fn proxy_to_doc(",
            &["to_ascii_lowercase", "to_lowercase"][..],
        ),
        (
            "fn upstream_to_doc(",
            &["to_ascii_lowercase", "to_lowercase"][..],
        ),
        (
            "fn consumer_to_doc(",
            &["to_ascii_lowercase", "to_lowercase"][..],
        ),
        (
            "fn plugin_config_to_doc(",
            &["to_ascii_lowercase", "to_lowercase"][..],
        ),
    ] {
        let start = MONGO_STORE_SOURCE
            .find(helper_name)
            .unwrap_or_else(|| panic!("missing {helper_name}"));
        let tail = &MONGO_STORE_SOURCE[start..];
        let end = tail
            .find("\n    fn ")
            .or_else(|| tail.find("\n    async fn "))
            .unwrap_or(800);
        let body = &tail[..end];
        for needle in forbidden {
            assert!(
                !body.contains(needle),
                "{helper_name} must not re-canonicalize host/SNI/SAN fields; found `{needle}`:\n{body}"
            );
        }
        assert!(
            body.contains("mongodb::bson::to_document(") || body.contains("to_document("),
            "{helper_name} must serialize the provided resource document directly"
        );
    }

    for method_name in [
        "batch_create_proxies(",
        "batch_create_upstreams(",
        "batch_create_consumers(",
        "batch_create_plugin_configs(",
    ] {
        let method = mongo_method(method_name);
        assert!(
            !method.contains("normalize_fields(") && !method.contains("to_ascii_lowercase("),
            "{method_name} must persist the caller-provided canonical form without re-normalizing"
        );
    }
}

/// Issue #3001: Mongo failover must flip the write gate before publishing the
/// connection (SQL `reconnect_for_topology` parity). Default-disabled admin
/// writes must never observe a failover connection while `primary_active`
/// still reads true. Primary `mark_primary` must finalize under the same
/// publication guards after ArcSwap. Deferred reconnects must not change
/// topology.
#[test]
fn reconnect_failover_marks_topology_before_publishing_connection() {
    let reconnect_failover = mongo_fn_body("        async fn reconnect_failover(");
    assert!(
        reconnect_failover.contains("build_connection_bundle("),
        "reconnect_failover must build the connection before any topology change"
    );
    assert!(
        reconnect_failover.contains("publish_reconnected_bundle("),
        "reconnect_failover must publish through the ordered helper"
    );
    assert!(
        reconnect_failover.contains("MongoReconnectTopology::Failover")
            && (reconnect_failover.contains("redact_url(db_url)")
                || reconnect_failover.contains("crate::config::db_backend::redact_url(db_url)")),
        "reconnect_failover must publish as Failover with a redacted URL:\n{reconnect_failover}"
    );
    // Must not reintroduce the old post-publish mark_failover call site.
    let after_publish = reconnect_failover
        .split("publish_reconnected_bundle(")
        .nth(1)
        .expect("publish call");
    assert!(
        !after_publish.contains("mark_failover("),
        "mark_failover must not run after publication in reconnect_failover:\n{reconnect_failover}"
    );

    let publish = mongo_fn_body("        async fn publish_reconnected_bundle(");
    let publish_body = publish
        .split_once('{')
        .map(|(_, body)| body)
        .expect("publish_reconnected_bundle body");
    let admin_try_write_at = publish_body
        .find("admin_write_topology.try_write()")
        .expect(
            "publish_reconnected_bundle must fail-fast on the Admin write-topology guard first",
        );
    let generation_try_write_at = publish_body
        .find("connection_generation.try_write()")
        .expect("publish_reconnected_bundle must fail-fast on the generation guard second");
    let mark_failover_at = publish_body
        .find("mark_failover(")
        .expect("publish_reconnected_bundle must mark failover under the guards");
    let swap_at = publish_body
        .find("connection.swap(")
        .expect("publish_reconnected_bundle must ArcSwap the connection");
    let mark_primary_at = publish_body
        .find("mark_primary(")
        .expect("publish_reconnected_bundle must mark primary under the guards");
    assert!(
        admin_try_write_at < generation_try_write_at
            && generation_try_write_at < mark_failover_at
            && mark_failover_at < swap_at
            && swap_at < mark_primary_at,
        "admin try_write -> generation try_write -> mark_failover -> swap -> mark_primary is the serialized order:\n{publish_body}"
    );
    assert!(
        !publish_body.contains(".write().await"),
        "Mongo publication must stay fail-fast (try_write), never unbounded write().await:\n{publish_body}"
    );

    // Primary reconnect must not finalize topology outside the publication
    // critical section (the pre-fix fail-open race).
    let reconnect = mongo_fn_body("        async fn reconnect(");
    assert!(
        reconnect.contains("install_reconnected_bundle("),
        "reconnect must publish via install_reconnected_bundle:\n{reconnect}"
    );
    assert!(
        !reconnect.contains("mark_primary("),
        "reconnect must not call mark_primary after releasing publication guards:\n{reconnect}"
    );

    // SQL parity: failover topology flips before pool publication, and the
    // reconnect transition *write* lock serializes publication through deferred
    // migrations / primary mark_primary. Admin mutations take a shared *read*
    // pin via acquire_write_topology_permit so reconnect cannot redirect an
    // in-flight write (issue #3001 check-to-use race).
    let sql_source = include_str!("../../../src/config/db_loader.rs");
    let sql_reconnect = sql_source
        .split("async fn reconnect_for_topology(")
        .nth(1)
        .and_then(|rest| rest.split("\n    /// Extract the hostname").next())
        .expect("DatabaseStore::reconnect_for_topology body");
    assert!(
        sql_reconnect.contains("self.reconnect_transition.write().await"),
        "SQL reconnect_for_topology must serialize publication under reconnect_transition write lock:\n{sql_reconnect}"
    );
    let sql_lock = sql_reconnect
        .find("self.reconnect_transition.write().await")
        .expect("reconnect_transition write lock");
    let sql_mark = sql_reconnect
        .find("mark_failover(")
        .expect("SQL failover path must call mark_failover");
    let sql_swap = sql_reconnect
        .find("self.pool.swap(")
        .expect("SQL failover path must swap the pool");
    let sql_migrations = sql_reconnect
        .find("maybe_apply_deferred_migrations()")
        .expect("SQL reconnect must await deferred migrations under the transition lock");
    let sql_mark_primary = sql_reconnect
        .find("mark_primary(")
        .expect("SQL primary path must call mark_primary after migrations");
    assert!(
        sql_lock < sql_mark && sql_mark < sql_swap,
        "write lock -> mark_failover -> pool.swap is the fail-closed failover order:\n{sql_reconnect}"
    );
    assert!(
        sql_swap < sql_migrations && sql_migrations < sql_mark_primary,
        "pool.swap -> deferred migrations -> mark_primary must stay under the same write lock:\n{sql_reconnect}"
    );
    let connect_at = sql_reconnect
        .find("connect_any_pool_with_timeout(")
        .expect("connect must stay outside the transition write lock");
    assert!(
        connect_at < sql_lock,
        "pool connect must complete before taking reconnect_transition write lock:\n{sql_reconnect}"
    );

    let sql_acquire = sql_source
        .split("async fn acquire_write_topology_permit(")
        .nth(1)
        .and_then(|rest| rest.split("fn pool_stats(").next())
        .expect("DatabaseStore::acquire_write_topology_permit body");
    assert!(
        sql_acquire.contains("reconnect_transition.clone().read_owned().await")
            || sql_acquire.contains("self.reconnect_transition.clone().read_owned().await"),
        "SQL write admit must pin via reconnect_transition read_owned:\n{sql_acquire}"
    );

    // Mongo write admit pins the distinct Admin topology gate — never the
    // admission `connection_generation` lock (Tokio fair RwLock is not
    // reentrant; mutations nest into admission after the outer permit).
    let mongo_source = include_str!("../../../src/config/mongo_store.rs");
    let mongo_acquire = mongo_source
        .split("async fn acquire_write_topology_permit(")
        .nth(1)
        .and_then(|rest| rest.split("fn set_slow_query_threshold(").next())
        .expect("MongoStore::acquire_write_topology_permit body");
    assert!(
        mongo_acquire.contains("admin_write_topology.clone().read_owned().await")
            || mongo_acquire.contains("self.admin_write_topology.clone().read_owned().await"),
        "Mongo write admit must pin via admin_write_topology read_owned:\n{mongo_acquire}"
    );
    // Forbid code expressions that acquire/read the admission lock. Comments may
    // still name `connection_generation` when explaining why the locks are distinct.
    assert!(
        !mongo_acquire.contains("self.connection_generation"),
        "Mongo write admit must not acquire/read connection_generation:\n{mongo_acquire}"
    );

    // All Mongo publication paths funnel through publish_reconnected_bundle.
    let install = mongo_fn_body("        async fn install_reconnected_bundle(");
    assert!(
        install.contains("publish_reconnected_bundle(")
            && install.contains("MongoReconnectTopology::Primary"),
        "install_reconnected_bundle (primary reconnect) must publish via the shared helper as Primary"
    );
    assert!(
        reconnect_failover.contains("publish_reconnected_bundle("),
        "reconnect_failover must publish via the shared helper"
    );
}

/// Issue #3001: Admin write-topology pins and admission generation pins are
/// distinct fair RwLocks. Holding the outer Admin permit must fail-fast defer
/// publication, while a nested admission acquire on `connection_generation`
/// still completes (no same-lock reentrancy deadlock). Barriers make the
/// reconnect-between-outer-and-inner interleaving deterministic.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn admin_permit_defers_publish_while_nested_admission_pin_succeeds() {
    let store = mongo_store_new_unconnected_for_test(vec![]).expect("lazy mongo store");
    assert_eq!(mongo_store_published_database_name_for_test(&store), "test");
    assert!(store.failover_topology_status().primary_active);

    let permit = store.acquire_write_topology_permit().await;
    let pinned_epoch = permit.topology_epoch();
    assert!(
        permit.is_pinned(),
        "Mongo write admit must retain an admin_write_topology read pin"
    );
    assert_eq!(store.config_topology_epoch(), pinned_epoch);

    let (admission_ready_tx, admission_ready_rx) = oneshot::channel::<()>();
    let (release_admission_tx, release_admission_rx) = oneshot::channel::<()>();
    let nested_ok = Arc::new(AtomicBool::new(false));

    let admit_store = store.clone();
    let nested_ok_task = Arc::clone(&nested_ok);
    let admission_task = tokio::spawn(async move {
        // Simulates Admin mutation CRUD entering acquire_durable_admission_lock
        // while the outer write-topology permit is still held.
        let admission_pin =
            mongo_store_acquire_connection_generation_pin_for_test(&admit_store).await;
        nested_ok_task.store(true, Ordering::SeqCst);
        let _ = admission_ready_tx.send(());
        let _ = release_admission_rx.await;
        drop(admission_pin);
    });

    admission_ready_rx
        .await
        .expect("nested admission pin must complete while Admin permit is held");
    assert!(
        nested_ok.load(Ordering::SeqCst),
        "nested connection_generation read must not deadlock behind the Admin permit"
    );

    let blocked = mongo_store_try_publish_reconnected_bundle_for_test(
        &store,
        "should_not_publish",
        MongoReconnectTopology::Failover,
        "mongodb://failover.example/test",
    )
    .await
    .expect_err("Admin write-topology pin must fail-fast defer publication");
    let blocked_msg = blocked.to_string();
    assert!(
        blocked_msg.contains("Admin write-topology permit"),
        "deferred reconnect must name the Admin pin, got: {blocked_msg}"
    );
    assert!(
        store.failover_topology_status().primary_active,
        "deferred reconnect must leave topology untouched"
    );
    assert_eq!(
        mongo_store_published_database_name_for_test(&store),
        "test",
        "deferred reconnect must not ArcSwap the connection"
    );
    assert_eq!(
        store.config_topology_epoch(),
        pinned_epoch,
        "a deferred publication must not consume a topology epoch"
    );

    release_admission_tx.send(()).expect("release admission");
    admission_task.await.expect("join admission task");
    drop(permit);

    mongo_store_try_publish_reconnected_bundle_for_test(
        &store,
        "after_admin_pin",
        MongoReconnectTopology::Failover,
        "mongodb://failover.example/test",
    )
    .await
    .expect("publish must succeed after Admin + admission pins drop");
    assert!(!store.failover_topology_status().primary_active);
    let published_epoch = store.config_topology_epoch();
    assert!(
        published_epoch > pinned_epoch,
        "a published Mongo topology must advance its process-local epoch"
    );
    let published_permit = store.acquire_write_topology_permit().await;
    assert_eq!(published_permit.topology_epoch(), published_epoch);
    assert_eq!(
        mongo_store_published_database_name_for_test(&store),
        "after_admin_pin"
    );
}

/// Admission-only pins still fail-fast defer publication (generation gate),
/// independent of the Admin write-topology lock.
#[tokio::test(flavor = "current_thread")]
async fn admission_pin_defers_publish_without_topology_change() {
    let store = mongo_store_new_unconnected_for_test(vec![]).expect("lazy mongo store");
    let admission_pin = mongo_store_acquire_connection_generation_pin_for_test(&store).await;

    let blocked = mongo_store_try_publish_reconnected_bundle_for_test(
        &store,
        "blocked_by_admission",
        MongoReconnectTopology::Failover,
        "mongodb://failover.example/test",
    )
    .await
    .expect_err("admission pin must fail-fast defer publication");
    assert!(
        blocked.to_string().contains("admission operation pins"),
        "deferred reconnect must name the admission pin, got: {blocked}"
    );
    assert!(store.failover_topology_status().primary_active);
    assert_eq!(mongo_store_published_database_name_for_test(&store), "test");

    drop(admission_pin);
    mongo_store_try_publish_reconnected_bundle_for_test(
        &store,
        "after_admission_pin",
        MongoReconnectTopology::Failover,
        "mongodb://failover.example/test",
    )
    .await
    .expect("publish after admission pin drops");
    assert!(!store.failover_topology_status().primary_active);
    assert_eq!(
        mongo_store_published_database_name_for_test(&store),
        "after_admission_pin"
    );
}

/// Concurrent reconnect attempt that races between outer Admin permit acquire
/// and nested admission must observe fail-fast deferral (never hang), then
/// succeed once both pins drop. Uses oneshot barriers — no timing sleeps.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reconnect_between_admin_permit_and_admission_is_fail_fast() {
    let store = mongo_store_new_unconnected_for_test(vec![]).expect("lazy mongo store");
    let permit = store.acquire_write_topology_permit().await;

    let (outer_held_tx, outer_held_rx) = oneshot::channel::<()>();
    let (publish_saw_defer_tx, publish_saw_defer_rx) = oneshot::channel::<()>();
    let (release_pins_tx, release_pins_rx) = oneshot::channel::<()>();

    let publish_store = store.clone();
    let publish_task = tokio::spawn(async move {
        outer_held_rx
            .await
            .expect("wait until Admin permit is held");
        let first = mongo_store_try_publish_reconnected_bundle_for_test(
            &publish_store,
            "raced_publish",
            MongoReconnectTopology::Failover,
            "mongodb://failover.example/test",
        )
        .await;
        assert!(
            first.is_err(),
            "publish racing under Admin permit must fail-fast defer"
        );
        let _ = publish_saw_defer_tx.send(());
        release_pins_rx.await.expect("wait for pin release");
        mongo_store_try_publish_reconnected_bundle_for_test(
            &publish_store,
            "after_race",
            MongoReconnectTopology::Failover,
            "mongodb://failover.example/test",
        )
        .await
    });

    let _ = outer_held_tx.send(());
    // Nested admission while outer permit held (the former self-deadlock window).
    let admission_pin = mongo_store_acquire_connection_generation_pin_for_test(&store).await;
    publish_saw_defer_rx
        .await
        .expect("publish task must observe fail-fast deferral without hanging");

    drop(admission_pin);
    drop(permit);
    let _ = release_pins_tx.send(());

    publish_task
        .await
        .expect("join publish")
        .expect("publish after pins drop");
    assert!(!store.failover_topology_status().primary_active);
    assert_eq!(
        mongo_store_published_database_name_for_test(&store),
        "after_race"
    );
}

/// Issue #3001: a primary publication that pauses after ArcSwap (before
/// `mark_primary`) must not let a concurrent failover publish and then be
/// overwritten only in metadata by a delayed `mark_primary` — that left the
/// live bundle on failover while `primary_active=true` and made write gating
/// fail open. Rendezvous via test seams; no sleeps.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn delayed_primary_publish_cannot_overwrite_later_failover_topology() {
    use std::sync::Mutex as StdMutex;
    use tokio::sync::Mutex as AsyncMutex;

    let store = mongo_store_new_unconnected_for_test(vec![]).expect("lazy mongo store");
    // Start on failover so primary failback is a real topology transition.
    mongo_store_try_publish_reconnected_bundle_for_test(
        &store,
        "initial_failover",
        MongoReconnectTopology::Failover,
        "mongodb://failover.example/test",
    )
    .await
    .expect("seed failover topology");
    assert!(!store.failover_topology_status().primary_active);

    let (primary_holding_tx, primary_holding_rx) = oneshot::channel::<()>();
    let (primary_resume_tx, primary_resume_rx) = oneshot::channel::<()>();
    let (failover_before_lock_tx, failover_before_lock_rx) = oneshot::channel::<()>();
    let failover_holding = Arc::new(AtomicBool::new(false));

    let primary_holding_tx = Arc::new(StdMutex::new(Some(primary_holding_tx)));
    let primary_resume_rx = Arc::new(AsyncMutex::new(Some(primary_resume_rx)));
    let failover_before_lock_tx = Arc::new(StdMutex::new(Some(failover_before_lock_tx)));

    mongo_store_set_reconnect_transition_hooks_for_test(
        &store,
        Some(MongoReconnectTransitionTestHooks {
            before_lock: Some(Arc::new({
                let failover_before_lock_tx = Arc::clone(&failover_before_lock_tx);
                move |topology| {
                    let failover_before_lock_tx = Arc::clone(&failover_before_lock_tx);
                    Box::pin(async move {
                        if topology != MongoReconnectTopology::Failover {
                            return;
                        }
                        if let Some(tx) = failover_before_lock_tx.lock().unwrap().take() {
                            let _ = tx.send(());
                        }
                    })
                }
            })),
            while_holding: Some(Arc::new({
                let primary_holding_tx = Arc::clone(&primary_holding_tx);
                let primary_resume_rx = Arc::clone(&primary_resume_rx);
                let failover_holding = Arc::clone(&failover_holding);
                move |topology| {
                    let primary_holding_tx = Arc::clone(&primary_holding_tx);
                    let primary_resume_rx = Arc::clone(&primary_resume_rx);
                    let failover_holding = Arc::clone(&failover_holding);
                    Box::pin(async move {
                        match topology {
                            MongoReconnectTopology::Primary => {
                                if let Some(tx) = primary_holding_tx.lock().unwrap().take() {
                                    let _ = tx.send(());
                                }
                                if let Some(rx) = primary_resume_rx.lock().await.take() {
                                    let _ = rx.await;
                                }
                            }
                            MongoReconnectTopology::Failover => {
                                failover_holding.store(true, Ordering::SeqCst);
                            }
                        }
                    })
                }
            })),
        }),
    );

    let primary_store = store.clone();
    let primary_task = tokio::spawn(async move {
        mongo_store_try_publish_reconnected_bundle_for_test(
            &primary_store,
            "primary_bundle",
            MongoReconnectTopology::Primary,
            "mongodb://primary.example/test",
        )
        .await
    });

    primary_holding_rx
        .await
        .expect("primary publish must enter while_holding under the publication guards");
    assert!(
        !store.failover_topology_status().primary_active,
        "primary must stay fail-closed until mark_primary after the deferred window"
    );
    assert_eq!(
        mongo_store_published_database_name_for_test(&store),
        "primary_bundle",
        "bundle must already be primary while mark_primary is still pending under the guards"
    );

    let failover_store = store.clone();
    let failover_task = tokio::spawn(async move {
        mongo_store_try_publish_reconnected_bundle_for_test(
            &failover_store,
            "later_failover",
            MongoReconnectTopology::Failover,
            "mongodb://failover.example/test",
        )
        .await
    });

    failover_before_lock_rx
        .await
        .expect("failover publish must reach before_lock while primary holds publication");
    assert!(
        !failover_holding.load(Ordering::SeqCst),
        "failover must not enter while_holding while primary still holds publication"
    );

    // Fail-fast: concurrent failover cannot acquire the publication guards.
    let deferred = failover_task.await.expect("join deferred failover");
    let deferred_err =
        deferred.expect_err("failover racing under primary publication must fail-fast defer");
    let deferred_msg = deferred_err.to_string();
    assert!(
        deferred_msg.contains("Admin write-topology permit")
            || deferred_msg.contains("admission operation pins"),
        "deferred failover must name a publication pin, got: {deferred_msg}"
    );

    primary_resume_tx.send(()).expect("resume primary");
    primary_task
        .await
        .expect("join primary")
        .expect("primary publish");
    assert!(store.failover_topology_status().primary_active);
    assert_eq!(
        mongo_store_published_database_name_for_test(&store),
        "primary_bundle"
    );

    mongo_store_try_publish_reconnected_bundle_for_test(
        &store,
        "later_failover",
        MongoReconnectTopology::Failover,
        "mongodb://failover.example/test",
    )
    .await
    .expect("failover must publish after primary releases");
    assert!(
        failover_holding.load(Ordering::SeqCst),
        "failover must enter while_holding only after primary releases publication"
    );

    mongo_store_set_reconnect_transition_hooks_for_test(&store, None);

    assert!(
        !store.failover_topology_status().primary_active,
        "later failover must own topology after the serialized primary transition"
    );
    assert_eq!(
        mongo_store_published_database_name_for_test(&store),
        "later_failover",
        "active bundle must match the later failover publication"
    );
}

#[test]
fn gateway_trust_bundle_identity_parses_id_and_trust_domain_strictly() {
    let body = mongo_method("gateway_trust_bundle_identity");
    assert!(
        !body.contains("unwrap_or_default()"),
        "identity fields must not silently default on parse failure:\n{body}"
    );
    assert!(
        body.contains("strict_stored_str_field"),
        "identity id/trust_domain must use strict stored-field decoding:\n{body}"
    );
}

// ---------------------------------------------------------------------------
// Namespace registry (issue #3955)
// ---------------------------------------------------------------------------

/// Every registry mutation must (a) refuse standalone MongoDB before touching
/// a document, and (b) commit inside one transaction that re-verifies the
/// caller's admission leases. A live replica set is not available in unit
/// tests, so the decision is pinned at the source level — the same seam the
/// other MongoDB shape contracts in this file use.
#[test]
fn namespace_registry_mutations_are_transactional_and_refuse_standalone() {
    let preflight = mongo_fn_body("        fn ensure_namespace_registry_atomicity_supported(");
    assert!(
        preflight.contains("self.replica_set_configured()")
            && preflight.contains("namespace_registry_standalone_refusal()"),
        "the namespace registry capability preflight must refuse standalone MongoDB:\n{preflight}"
    );

    for (entry, in_session) in [
        ("create_namespace(", "create_namespace_in_session("),
        ("update_namespace(", "update_namespace_in_session("),
        ("delete_namespace(", "delete_namespace_in_session("),
    ] {
        let body = mongo_method(entry);
        assert!(
            body.contains("if !self.replica_set_configured()"),
            "{entry} must re-check topology before mutating:\n{body}"
        );
        assert!(
            body.contains("namespace_registry_standalone_refusal()"),
            "{entry} must fail closed on standalone MongoDB:\n{body}"
        );
        assert!(
            body.contains("start_transaction()") && body.contains(in_session),
            "{entry} must run {in_session} inside one transaction:\n{body}"
        );

        let session_body = mongo_method(in_session);
        assert!(
            session_body.contains("verify_namespace_registry_leases_in_session"),
            "{in_session} must re-verify the admission leases before commit:\n{session_body}"
        );
    }
}

/// The public 501 promise includes admission-lock collections: an unsupported
/// standalone deployment must be refused before the handler acquires a global,
/// source, or target namespace lease. The backend mutation still re-checks
/// topology to close the reconnect race after this preflight.
#[test]
fn namespace_registry_handlers_refuse_before_admission_mutation() {
    for (handler, next_handler) in [
        ("handle_create_namespace(", "handle_update_namespace("),
        ("handle_update_namespace(", "handle_delete_namespace("),
        ("handle_delete_namespace(", "handle_list_audit_logs("),
    ] {
        let start = ADMIN_SOURCE
            .find(&format!("async fn {handler}"))
            .unwrap_or_else(|| panic!("missing handler {handler}"));
        let end = ADMIN_SOURCE[start..]
            .find(&format!("\nasync fn {next_handler}"))
            .map(|offset| start + offset)
            .unwrap_or(ADMIN_SOURCE.len());
        let body = &ADMIN_SOURCE[start..end];
        let capability = body
            .find("db.ensure_namespace_registry_atomicity_supported()")
            .unwrap_or_else(|| panic!("{handler} is missing the capability preflight"));
        let admission = body
            .find("acquire_namespace_registry_admission(")
            .unwrap_or_else(|| panic!("{handler} is missing namespace admission"));
        assert!(
            capability < admission,
            "{handler} must return 501 before touching admission-lock documents:\n{body}"
        );
    }
}

/// The registry-lease gate is a conditional in-session WRITE compared against
/// MongoDB's own clock, so a competing acquirer raises a write conflict rather
/// than being masked by the transaction's read snapshot.
#[test]
fn namespace_registry_lease_gate_uses_server_time_and_joins_the_write_set() {
    let body = mongo_method("verify_namespace_config_admission_lease_in_session(");
    assert!(
        body.contains("update_one"),
        "the lease gate must be a conditional write, not a read:\n{body}"
    );
    assert!(
        body.contains("$$NOW") && body.contains("server_time_lease_touch_pipeline"),
        "expiry must be evaluated from MongoDB's clock at the gate:\n{body}"
    );
    assert!(
        body.contains("$currentDate")
            && body.contains("is_pipeline_update_unsupported")
            && body.contains("is_server_time_expr_unsupported")
            && body.contains("filter.clone()"),
        "the DocumentDB fallback must reuse the in-session $$NOW predicate on a classic \
         update and fail closed when that predicate is unavailable:\n{body}"
    );
    assert!(
        !body.contains("lease_server_time()"),
        "lease_server_time() must not be the expiry authority in this gate:\n{body}"
    );
    assert!(
        !body.contains("\"expires_at\": { \"$gt\": now }"),
        "a pre-read timestamp must not become the expiry predicate:\n{body}"
    );
}

/// `proxy_route_locks` documents are keyed only by `_id` (`"{namespace}:{hash}"`)
/// and carry NO `namespace` field, so a `{"namespace": ...}` filter is a silent
/// no-op. Cleanup must use the anchored, regex-escaped `_id` prefix instead —
/// and the id-rewriting helper (which DOES filter on `namespace`) must never be
/// pointed at that collection again.
#[test]
fn proxy_route_lock_cleanup_uses_an_escaped_id_prefix_not_a_namespace_filter() {
    let filter = mongo_fn_body("        fn namespace_id_prefix_filter(");
    assert!(
        filter.contains("regex_escape(namespace)") && filter.contains(r#""^{}:""#),
        "the id-prefix filter must be anchored and regex-escaped:\n{filter}"
    );

    let cleanup = mongo_method("delete_namespace_guard_docs_in_session(");
    assert!(
        cleanup.contains("proxy_route_locks()")
            && cleanup.contains("namespace_id_prefix_filter(namespace)"),
        "route-lock cleanup must target the `_id` prefix:\n{cleanup}"
    );
    assert!(
        !cleanup.contains("mtls_dns_admission_locks")
            && !cleanup.contains("config_admission_locks"),
        "the guard documents proving the mutation must not be deleted:\n{cleanup}"
    );

    // Single-line needles only: a multi-line source assertion breaks the
    // moment rustfmt reflows the call it is pinning.
    let rename = mongo_method("rename_namespace_documents_in_session(");
    assert!(
        !rename.contains("self.proxy_route_locks()") && !rename.contains("\"proxy_route_locks\","),
        "the rename must not try to rewrite `proxy_route_locks` ids — those \
         documents have no `namespace` field, so the filter never matches:\n{rename}"
    );
    assert!(
        !MONGO_STORE_SOURCE.contains(r#""consumer_credential_index""#),
        "the MongoDB backend has no consumer_credential_index collection"
    );
}

#[test]
fn namespace_prefixed_id_rewrite_requires_suffix_field_and_embedded_namespace() {
    let body = mongo_method("rewrite_namespace_prefixed_ids_in_session(");
    assert!(
        body.contains("namespace_prefixed_id_suffix_field(collection_name)")
            && body.contains("namespace_identity_scan_filter(current_name)")
            && body.contains("require_namespace_prefixed_identity(")
            && body.contains("document.get_str(\"namespace\").ok()")
            && body.contains("document.get_str(suffix_field).ok()"),
        "composite rewrite must require suffix-to-field equality and an embedded namespace:\n{body}"
    );
    let scan = mongo_fn_body("        fn namespace_identity_scan_filter(");
    assert!(
        scan.contains("\"$or\"")
            && scan.contains("\"namespace\": namespace")
            && scan.contains("namespace_id_prefix_filter(namespace)"),
        "the scan must expose both halves of a split embedded/key identity:\n{scan}"
    );
    assert!(
        !body.contains("unwrap_or(old_id.as_str())"),
        "the silent strip_prefix fallback must not return:\n{body}"
    );
    let require_at = body
        .find("require_namespace_prefixed_identity(")
        .expect("require helper");
    let delete_at = body.find("delete_one").expect("delete_one");
    assert!(
        require_at < delete_at,
        "corrupt identities must abort before delete/insert so the rename rolls back:\n{body}"
    );
    let rename = mongo_method("rename_namespace_documents_in_session(");
    assert!(
        rename.contains("\"consumers\"")
            && rename.contains("\"consumer_identity_index\"")
            && rename.contains("\"gateway_trust_bundles\""),
        "rename must still rewrite both composite collections and the keyed trust document:\n{rename}"
    );
}

#[test]
fn mongo_namespace_rename_rewrites_historical_audit_events() {
    let rename = mongo_method("rename_namespace_documents_in_session(");
    for collection in ["proxies", "plugin_configs", "upstreams", "api_specs"] {
        assert!(
            rename.contains(&format!("\"{collection}\"")),
            "in-place Mongo rename must still rewrite live collection {collection}:\n{rename}"
        );
    }
    assert!(
        rename.contains("self.audit_events()"),
        "historical audit_events must follow the renamed tenant:\n{rename}"
    );
    let audit_at = rename
        .find("self.audit_events()")
        .expect("audit_events rewrite");
    let audit_end = (audit_at + 500).min(rename.len());
    let audit_update = &rename[audit_at..audit_end];
    assert!(
        audit_update.contains("\"namespace\": new_name"),
        "audit rename must rewrite the authorization-scoping namespace field:\n{audit_update}"
    );
    assert!(
        !audit_update.contains("namespace_at_event"),
        "namespace_at_event must not be rewritten on rename:\n{audit_update}"
    );
}

#[test]
fn namespace_keyed_document_move_scans_split_identity_before_mutation() {
    let body = mongo_method("move_namespace_keyed_document_in_session(");
    let collect_at = body
        .find("collect_validated_namespace_keyed_docs_in_session")
        .expect("move must reuse the split-identity collector");
    let find_at = body
        .find("find_one(doc! { \"_id\": current_id })")
        .expect("after validation, move only the durable source key");
    let delete_at = body.find("delete_one").expect("delete_one");
    assert!(
        collect_at < find_at && find_at < delete_at,
        "a key-only query would miss `_id = other` / `namespace = current` occupancy \
         and leave that document behind while the rest of the tenant commits:\n{body}"
    );
    assert!(
        body.contains("require_namespace_keyed_identity(")
            && body.contains("NamespaceRegistryCorrupt::field(\"identity\")"),
        "split-identity disagreement must abort as typed NamespaceRegistryCorrupt:\n{body}"
    );
    assert!(
        !body.contains("update_many") && !body.contains("\"namespace\": current_id"),
        "move must never rewrite or delete by embedded namespace (that would touch another tenant):\n{body}"
    );
}

#[test]
fn namespace_keyed_document_move_requires_embedded_namespace_equality() {
    let body = mongo_method("move_namespace_keyed_document_in_session(");
    assert!(
        body.contains("require_namespace_keyed_identity(")
            && body.contains("document.get_str(\"namespace\").ok()")
            && body.contains("document.get_str(\"id\").ok()"),
        "keyed trust documents must require source-matching `_id` and embedded namespace, \
         plus a nonempty resource id:\n{body}"
    );
    assert!(
        !body.contains("if document.get_str(\"namespace\").is_ok()"),
        "a missing or non-string namespace must abort rather than being skipped:\n{body}"
    );
    let require_at = body
        .find("require_namespace_keyed_identity(")
        .expect("require helper");
    let delete_at = body.find("delete_one").expect("delete_one");
    assert!(
        require_at < delete_at,
        "a mismatched identity must abort before delete/insert:\n{body}"
    );
}

#[test]
fn namespace_registry_transaction_error_preserves_typed_corrupt() {
    let body = mongo_fn_body("        fn namespace_registry_transaction_error(");
    assert!(
        body.contains("get_custom::<NamespaceRegistryCorrupt>()")
            && body.contains("anyhow::Error::new(corrupt)"),
        "typed rename corruption must surface as NamespaceRegistryCorrupt so admin stays on the static 500:\n{body}"
    );
}

#[test]
fn last_remaining_namespace_authority_is_the_registry_collection() {
    let body = mongo_method("any_namespace_remains_in_session(");
    assert!(
        body.contains("namespaces()") && !body.contains("DERIVED_NAMESPACE_RESOURCE_TABLES"),
        "last-remaining protection must be registry-row based; ordinary resource CRUD \
         is not serialized by the global registry lease:\n{body}"
    );
}

#[test]
fn mongo_namespace_list_fails_closed_on_corrupt_registry_documents() {
    let list = mongo_method("list_namespaces(");
    assert!(
        list.contains("registry_namespace_names()"),
        "list must load registry documents, not only derived names:\n{list}"
    );
    let registry = mongo_method("registry_namespace_names(");
    assert!(
        registry.contains("document_to_namespace_record"),
        "corrupt registry documents must fail the list rather than being skipped:\n{registry}"
    );
}

#[test]
fn namespace_rename_acquires_source_and_target_mtls_dns_fences_in_lock_order() {
    let body = mongo_method("update_namespace(");
    assert!(
        body.contains("mtls_dns_admission_namespaces(")
            && body.contains("acquire_mtls_dns_admission_leases(")
            && body.contains("run_mtls_dns_mutations("),
        "rename must acquire both source and target mTLS DNS fences through the \
         multi-lease helper:\n{body}"
    );
    assert!(
        !body.contains("acquire_mtls_dns_admission_lease(current_name)"),
        "a single current_name fence would bypass a retained restore owner on the target:\n{body}"
    );
}

#[test]
fn mtls_dns_multi_lease_acquire_releases_already_held_guards_on_partial_failure() {
    let body = mongo_method("acquire_mtls_dns_admission_leases_for_mode<'a>(");
    assert!(
        body.contains("release_mtls_dns_admission_leases(&mut leases)"),
        "a later acquire error must release already-held guards rather than stranding \
         them:\n{body}"
    );
}

#[test]
fn document_to_namespace_record_is_strict_and_does_not_synthesize() {
    let body = mongo_fn_body("        fn document_to_namespace_record(");
    assert!(
        body.contains("require_namespace_identity")
            && body.contains("parse_namespace_rfc3339")
            && body.contains("require_canonical_stored_description")
            && body.contains("NamespaceRegistryCorrupt::field"),
        "corrupt durable documents must fail closed:\n{body}"
    );
    assert!(
        !body.contains("Utc::now()")
            && !body.contains("unwrap_or_else(|| fallback_name")
            && !body.contains("normalize_description"),
        "missing timestamps/names must not be fabricated and stored descriptions must not be normalized:\n{body}"
    );
}

#[test]
fn mongo_namespace_registry_mutations_require_canonical_lease_set_before_session() {
    for (entry, names_needle) in [
        ("create_namespace(", "&[record.name.as_str()]"),
        ("update_namespace(", "&[current_name, new_name]"),
        (
            "delete_namespace(",
            "owned_namespace_registry_leases_for_names(&[name], leases)",
        ),
    ] {
        let body = mongo_method(entry);
        assert!(
            body.contains("owned_namespace_registry_leases_for_names"),
            "{entry} must validate the canonical lease set at the backend boundary:\n{body}"
        );
        assert!(
            body.contains(names_needle),
            "{entry} must pass the canonical names {names_needle}:\n{body}"
        );
        let require_at = body
            .find("owned_namespace_registry_leases_for_names")
            .expect("lease-set gate");
        let session_at = body.find("start_session()").expect("start_session");
        assert!(
            require_at < session_at,
            "{entry} must reject a substituted lease set before opening a session:\n{body}"
        );
    }

    let owned = mongo_fn_body("        fn owned_namespace_registry_leases_for_names(");
    assert!(
        owned.contains("require_namespace_registry_admission_leases(names, leases)")
            && owned.contains("map_err(anyhow::Error::new)"),
        "owned lease copy must fail closed as BatchAdmissionLeaseLost without echoing keys:\n{owned}"
    );

    let verify = mongo_method("verify_namespace_registry_leases_in_session(");
    assert!(
        verify.contains("require_namespace_registry_admission_keys(names, &supplied)")
            && verify.contains("NamespaceRegistryAbort::AdmissionLeaseLost")
            && verify.contains("verify_namespace_config_admission_lease_in_session"),
        "in-session verify must re-check the canonical key set then owner/generation:\n{verify}"
    );
}

#[test]
fn mongo_namespace_occupancy_scans_split_durable_identities() {
    let occupancy = mongo_method("namespace_has_resources_in_session(");
    assert!(
        occupancy.contains("collection_has_namespace_occupancy_in_session")
            && occupancy.contains("\"consumer_identity_index\""),
        "occupancy must inspect split-identity collections, including the identity index:\n{occupancy}"
    );
    assert!(
        !occupancy.contains("doc! { \"namespace\": name }"),
        "occupancy must not look only at the embedded namespace field:\n{occupancy}"
    );

    let filter = mongo_fn_body("        fn namespace_occupancy_filter(");
    assert!(
        filter.contains("\"consumers\"")
            && filter.contains("\"consumer_identity_index\"")
            && filter.contains("namespace_identity_scan_filter(namespace)")
            && filter.contains("\"gateway_trust_bundles\"")
            && filter.contains("namespace_keyed_identity_scan_filter(namespace)"),
        "occupancy filters must union embedded and key identities for split collections:\n{filter}"
    );

    let keyed = mongo_fn_body("        fn namespace_keyed_identity_scan_filter(");
    assert!(
        keyed.contains("\"$or\"")
            && keyed.contains("\"namespace\": namespace")
            && keyed.contains("\"_id\": namespace")
            && !keyed.contains("namespace_id_prefix_filter"),
        "trust-bundle occupancy must use the exact `_id = namespace` key, not a prefix:\n{keyed}"
    );

    let in_use = mongo_method("namespace_name_in_use(");
    assert!(
        in_use.contains("namespace_has_resources(name)")
            || in_use.contains("namespace_occupancy_filter"),
        "unconfirmed delete must not treat a key-only split identity as absent:\n{in_use}"
    );
}

#[test]
fn mongo_namespace_cascade_validates_split_identities_before_delete() {
    let delete_ns = mongo_method("delete_namespace_in_session(");
    let trust_validate_at = delete_ns
        .find("collect_validated_namespace_keyed_docs_in_session")
        .expect("trust-bundle validation before cascade");
    let resources_at = delete_ns
        .find("delete_all_namespace_resources_in_session")
        .expect("resource cascade");
    assert!(
        trust_validate_at < resources_at,
        "a split trust-bundle identity must abort before any resource delete:\n{delete_ns}"
    );

    let cascade = mongo_method("delete_all_namespace_resources_in_session(");
    let consumers_at = cascade
        .find("collect_validated_namespace_prefixed_docs_in_session")
        .expect("consumer validation");
    let first_delete = cascade.find("delete_many").expect("delete_many");
    assert!(
        consumers_at < first_delete,
        "split consumer identities must be validated before deleting anything:\n{cascade}"
    );
    assert!(
        cascade.contains("\"consumers\"")
            && cascade.contains("\"consumer_identity_index\"")
            && cascade.contains("delete_validated_namespace_ids_in_session"),
        "cascade must delete only validated consumer and identity-index `_id`s:\n{cascade}"
    );
    assert!(
        !cascade.contains("self.consumers()")
            && !cascade.contains("self.consumer_identity_index()"),
        "cascade must not broad-delete consumers by embedded namespace:\n{cascade}"
    );

    let prefixed = mongo_method("collect_validated_namespace_prefixed_docs_in_session(");
    assert!(
        prefixed.contains("namespace_identity_scan_filter(namespace)")
            && prefixed.contains("require_namespace_prefixed_identity(")
            && prefixed.contains("document.get_str(\"namespace\").ok()")
            && prefixed.contains("NamespaceRegistryCorrupt::field"),
        "prefixed collect must scan both identity surfaces and fail closed on mismatch:\n{prefixed}"
    );
    assert!(
        !prefixed.contains("delete_one") && !prefixed.contains("delete_many"),
        "validation collect must not delete:\n{prefixed}"
    );

    let keyed = mongo_method("collect_validated_namespace_keyed_docs_in_session(");
    assert!(
        keyed.contains("namespace_keyed_identity_scan_filter(namespace)")
            && keyed.contains("require_namespace_keyed_identity(")
            && keyed.contains("document.get_str(\"namespace\").ok()")
            && keyed.contains("document.get_str(\"id\").ok()")
            && keyed.contains("NamespaceRegistryCorrupt::field"),
        "keyed collect must require source-matching `_id` and embedded namespace, plus a \
         nonempty resource id:\n{keyed}"
    );
    assert!(
        !keyed.contains("delete_one") && !keyed.contains("delete_many"),
        "keyed validation collect must not delete:\n{keyed}"
    );

    let delete_ids = mongo_method("delete_validated_namespace_ids_in_session(");
    assert!(
        delete_ids.contains("\"$in\"") && delete_ids.contains("ids.to_vec()"),
        "deletes must target already-validated `_id`s only:\n{delete_ids}"
    );
    assert!(
        !delete_ids.contains("\"namespace\""),
        "validated-id deletes must not use a broad embedded-namespace filter:\n{delete_ids}"
    );

    let trust_delete = mongo_method("delete_namespace_trust_bundle_in_session(");
    assert!(
        trust_delete.contains("collect_validated_namespace_keyed_docs_in_session")
            && trust_delete.contains("delete_validated_namespace_ids_in_session")
            && trust_delete.contains("\"gateway_trust_bundles\""),
        "trust-bundle cascade must delete only validated `_id`s:\n{trust_delete}"
    );
    assert!(
        !trust_delete.contains("delete_many(doc! { \"namespace\": namespace })"),
        "trust-bundle cascade must not broad-delete by embedded namespace:\n{trust_delete}"
    );

    let tx_error = mongo_fn_body("        fn namespace_registry_transaction_error(");
    assert!(
        tx_error.contains("get_custom::<NamespaceRegistryCorrupt>()"),
        "split-identity corruption must abort the transaction as typed NamespaceRegistryCorrupt:\n{tx_error}"
    );

    let guards = mongo_method("delete_namespace_guard_docs_in_session(");
    assert!(
        guards.contains("namespace_id_prefix_filter(namespace)")
            && guards.contains("proxy_route_locks()"),
        "proxy_route_locks must remain escaped-prefix cleanup:\n{guards}"
    );
}

#[test]
fn mongo_namespace_rename_validates_split_trust_identity_before_any_mutation() {
    let rename = mongo_method("rename_namespace_documents_in_session(");
    let collect_at = rename
        .find("collect_validated_namespace_keyed_docs_in_session")
        .expect("rename must scan gateway-trust identity before rewriting");
    let first_mutation = rename.find("delete_one").expect("registry-row delete");
    assert!(
        collect_at < first_mutation,
        "a split trust-bundle identity must abort before any rename write:\n{rename}"
    );
    assert!(
        rename.contains("\"gateway_trust_bundles\""),
        "the pre-mutation scan must target gateway_trust_bundles:\n{rename}"
    );
}

#[test]
fn mongo_namespace_registry_reads_validate_both_identity_surfaces() {
    let filter = mongo_fn_body("        fn namespace_registry_identity_scan_filter(");
    assert!(
        filter.contains("{ \"_id\": name }") && filter.contains("{ \"name\": name }"),
        "registry reads must expose both halves of a split identity:\n{filter}"
    );

    let session_get = mongo_method("get_namespace_in_session(");
    assert!(
        session_get.contains("namespace_registry_identity_scan_filter(name)")
            && session_get.contains("document_to_namespace_record(")
            && session_get.contains("Some(name)"),
        "transactional create/rename/delete vacancy checks must validate every registry \
         document claiming the name:\n{session_get}"
    );
    assert!(
        !session_get.contains("find_one(doc! { \"_id\": name })"),
        "an _id-only read would ignore `_id = other, name = target` corruption:\n{session_get}"
    );

    let public_get = mongo_method("get_namespace(\n");
    assert!(
        public_get.contains("namespace_registry_identity_scan_filter(name)")
            && public_get.contains("document_to_namespace_record("),
        "the public GET/precheck path must fail closed on the same split identity:\n{public_get}"
    );
}

#[test]
fn mongo_namespace_delete_rechecks_protected_namespaces_in_session() {
    let session = mongo_method("delete_namespace_in_session(");
    assert!(
        session.contains("plan.protected_namespaces")
            && session.contains("PROTECTED_CONFIGURED_NAMESPACE")
            && session.contains("namespace_protected_abort"),
        "delete must recheck the whole configured set inside the committing transaction:\n{session}"
    );
    let start_at = session
        .find("NamespaceRegistryPhase::Start")
        .expect("start fault");
    let protected_at = session
        .find("plan.protected_namespaces")
        .expect("protected namespaces");
    let occupancy_at = session
        .find("namespace_name_in_use_in_session")
        .expect("existence check");
    assert!(
        start_at < protected_at && protected_at < occupancy_at,
        "the protected set must be rechecked at the start of the session callback:\n{session}"
    );

    let outer = mongo_method("delete_namespace(");
    assert!(
        outer.contains("protected_namespaces_contains(&self.protected_namespaces")
            && outer.contains("PROTECTED_CONFIGURED_NAMESPACE"),
        "the outer precheck may stay for a fast response:\n{outer}"
    );
}

/// `delete_namespace` used a single `MongoLockGuard` and propagated
/// `mtls_lease.release().await?` after a confirmed commit. The global vector
/// helper regression does not catch that form.
#[test]
fn mongo_namespace_delete_cannot_fail_the_response_after_commit() {
    let body = mongo_method("delete_namespace(");
    assert!(
        body.contains("acquire_mtls_dns_admission_leases(")
            && body.contains("run_mtls_dns_mutations(")
            && body.contains(
                "release_mtls_dns_admission_leases_after_commit(&mut mtls_leases).await;"
            ),
        "delete must use the vector acquire/run/infallible-after-commit lease path:\n{body}"
    );
    assert!(
        !body.contains("acquire_mtls_dns_admission_lease(name)")
            && !body.contains(".release().await?")
            && !body.contains("run_mutation(")
            && !body.contains("release_mtls_dns_admission_leases(&mut mtls_leases).await?"),
        "a single-guard .release().await? after commit turns a durable delete into an error \
         and can suppress follow-up/audit behavior:\n{body}"
    );
}

/// Every namespace this process is configured to serve — `FERRUM_NAMESPACE`
/// plus each explicit `FERRUM_CP_NAMESPACES` entry — must reach the committing
/// transaction, not just the one resolved default (issue #3955 review).
#[test]
fn mongo_namespace_registry_plan_carries_the_whole_protected_set() {
    for method in [
        "create_namespace(",
        "update_namespace(",
        "delete_namespace(",
    ] {
        let body = mongo_method(method);
        assert!(
            body.contains("protected_namespaces: self.protected_namespaces.clone()"),
            "{method} must hand the whole configured set to the transaction plan:\n{body}"
        );
    }
    let rename = mongo_method("update_namespace_in_session(");
    assert!(
        rename.contains("protected_namespaces_contains(&plan.protected_namespaces, current_name)")
            && rename.contains("PROTECTED_CONFIGURED_NAMESPACE"),
        "rename-away must be refused for every configured namespace in-session:\n{rename}"
    );
    assert!(
        !MONGO_STORE_SOURCE.contains("effective_default_namespace"),
        "the single-namespace protection field must be fully replaced by the protected set"
    );
}

/// The one-time compatibility backfill must serialize against live namespace
/// CRUD on the same global registry admission key, and it must commit as ONE
/// transaction (issue #3955 review).
///
/// Renewals bracketing an unbounded run of durable upserts are not a fence: the
/// lease can lapse mid-run, another gateway can acquire it and commit a
/// namespace delete, and a later upsert from the pre-delete name set resurrects
/// that document. The second renewal only notices afterwards, and an absent
/// marker does not undo a durable write.
#[test]
fn mongo_namespace_registry_backfill_holds_the_global_registry_lease() {
    let entry = mongo_method("backfill_namespaces_registry(");
    let standalone_at = entry
        .find("replica_set_configured()")
        .expect("a topology with no transactions must be handled explicitly");
    let acquire_at = entry
        .find("try_acquire_namespace_config_admission_lease")
        .expect("the pass must take the global registry admission lease");
    let under_at = entry
        .find(".backfill_namespaces_registry_under_lease(")
        .expect("the pass must run under that lease");
    let release_at = entry
        .find("release_namespace_config_admission_lease")
        .expect("the pass must release the lease");
    assert!(
        standalone_at < acquire_at,
        "a standalone mongod must defer before taking the lease or writing anything:\n{entry}"
    );
    assert!(
        acquire_at < under_at && under_at < release_at,
        "the lease must be held across the whole compatibility pass:\n{entry}"
    );
    assert!(
        entry.contains("NAMESPACE_REGISTRY_ADMISSION_KEY"),
        "the pass must use the SAME global key live registry mutations take:\n{entry}"
    );
    assert!(
        entry.contains("(Err(backfill_error), _) => Err(backfill_error)"),
        "the lease must be released on the error path too, without masking the failure:\n{entry}"
    );

    let runner = mongo_method("backfill_namespaces_registry_under_lease(");
    assert!(
        runner.contains("start_transaction()")
            && runner.contains("backfill_namespaces_registry_in_session("),
        "the pass must commit as ONE transaction, not a sequence of unfenced upserts:\n{runner}"
    );
    assert!(
        runner.contains("BatchAdmissionLeaseLost"),
        "a lost lease must roll the pass back and defer to a later startup, not fail \
         startup:\n{runner}"
    );

    assert!(
        !MONGO_STORE_SOURCE.contains("namespaces_registry_backfill_lease_still_held"),
        "conditional renewals bracketing unbounded durable writes are not a fence and must not \
         come back"
    );
}

/// A standalone `mongod` has no multi-document transactions, so the pass writes
/// nothing at all there rather than claiming a cross-process atomicity the
/// topology does not have. `GET /namespaces` is the union of registry names and
/// derived resource names, and namespace create/rename/delete already return
/// `501` before mutating anything, so nothing observable changes.
#[test]
fn mongo_namespace_registry_backfill_writes_nothing_without_transactions() {
    let entry = mongo_method("backfill_namespaces_registry(");
    let guard_at = entry
        .find("replica_set_configured()")
        .expect("standalone guard");
    let acquire_at = entry
        .find("try_acquire_namespace_config_admission_lease")
        .expect("lease acquisition");
    assert!(
        guard_at < acquire_at,
        "the standalone guard must run before any lease or write:\n{entry}"
    );
    assert!(
        !entry.contains("namespaces()"),
        "the entry point must not upsert registry documents outside the transaction:\n{entry}"
    );

    let in_session = mongo_method("backfill_namespaces_registry_in_session(");
    assert!(
        in_session.contains(".session(&mut *session)"),
        "every read and write of the pass must run inside the caller's transaction:\n{in_session}"
    );
    assert!(
        !in_session.contains("self.distinct_namespaces(")
            && !in_session.contains("self.registry_namespace_names("),
        "the sessionless scan helpers would read outside the transaction snapshot:\n{in_session}"
    );

    let scan = mongo_method("distinct_namespaces_in_session(");
    assert!(
        scan.contains("$group") && !scan.contains(".distinct("),
        "the in-transaction scan must use an aggregation; `distinct` is not accepted inside a \
         transaction on every supported server:\n{scan}"
    );
}

#[test]
fn mongo_namespace_registry_backfill_is_one_time_and_crash_retryable() {
    let entry = mongo_method("backfill_namespaces_registry(");
    assert!(
        entry.contains("namespaces_registry_backfill_completed()"),
        "a completed backfill must short-circuit before acquiring anything:\n{entry}"
    );

    let body = mongo_method("backfill_namespaces_registry_in_session(");
    let completed_at = body
        .find("namespaces_registry_backfill_completed_in_session")
        .expect("authoritative completion check inside the transaction");
    let scan_at = body
        .find("distinct_namespaces_in_session")
        .expect("derived-name scan");
    let insert_at = body.find("namespaces()").expect("registry upserts");
    let validate_at = body
        .find("registry_namespace_names_in_session")
        .expect("registry identity validation before completion");
    let mark_at = body
        .find("mark_namespaces_registry_backfill_complete")
        .expect("completion mark");
    let verify_at = body
        .find("verify_namespace_config_admission_lease_in_session")
        .expect("commit-boundary owner/generation lease proof");
    assert!(
        completed_at < scan_at && scan_at < insert_at,
        "the name set must be discovered inside the same transaction that makes it durable, so \
         no delete can commit in between:\n{body}"
    );
    assert!(
        insert_at < validate_at && validate_at < mark_at,
        "a split registry identity must abort before the compatibility marker is durable:\n{body}"
    );
    assert!(
        mark_at < verify_at,
        "the marker must be written last, and the owner/generation lease proof must be the final \
         gate before the commit:\n{body}"
    );

    let completed = mongo_method("namespaces_registry_backfill_completed(");
    assert!(
        completed.contains("schema_compat()")
            && completed.contains("NAMESPACES_REGISTRY_BACKFILL_ID")
            && !completed.contains("namespaces()"),
        "completion must not live as a fake namespaces document:\n{completed}"
    );

    let mark = mongo_method("mark_namespaces_registry_backfill_complete(");
    assert!(
        mark.contains("schema_compat()")
            && mark.contains("NAMESPACES_REGISTRY_BACKFILL_ID")
            && mark.contains("completed_at")
            && !mark.contains("namespaces()"),
        "the marker must be written to the internal compatibility collection:\n{mark}"
    );

    let migrations = mongo_method("run_migrations(");
    let lease_at = migrations
        .find("acquire_migration_lease")
        .expect("migration lease");
    let backfill_at = migrations
        .find("backfill_namespaces_registry")
        .expect("backfill still runs during migrate");
    let release_at = migrations
        .find("migration_lease.release()")
        .expect("release");
    assert!(
        lease_at < backfill_at && backfill_at < release_at,
        "the first compatibility run must stay serialized by the migration lease:\n{migrations}"
    );
}

fn well_formed_change_doc(sequence: i64, resource_id: &str, operation: &str) -> Document {
    doc! {
        "sequence": sequence,
        "namespace": "ferrum",
        "resource_type": "proxy",
        "resource_id": resource_id,
        "operation": operation,
        "created_at": "2026-08-28T00:00:00Z",
    }
}

fn incremental_cursor_after(after_sequence: u64, docs: &[Document]) -> Result<u64, anyhow::Error> {
    let mut sequence_cursor = after_sequence;
    for doc in docs {
        let change = decode_mongo_config_change_record(doc)?;
        sequence_cursor = sequence_cursor.max(change.sequence);
    }
    Ok(sequence_cursor)
}

fn assert_decode_error_is_opaque(error: &anyhow::Error, forbidden: &[&str]) {
    let message = error.to_string();
    for needle in forbidden {
        assert!(
            !message.contains(needle),
            "decode error must not leak record content {needle:?}: {message}"
        );
    }
}

#[test]
fn incremental_poll_decodes_canonical_upsert_and_delete() {
    let upsert = decode_mongo_config_change_record(&well_formed_change_doc(3, "proxy-a", "upsert"))
        .expect("canonical upsert must decode");
    assert_eq!(upsert.sequence, 3);
    assert_eq!(upsert.resource_type, "proxy");
    assert_eq!(upsert.resource_id, "proxy-a");
    assert_eq!(upsert.operation, MongoConfigChangeOp::Upsert);

    let delete = decode_mongo_config_change_record(&well_formed_change_doc(4, "proxy-a", "delete"))
        .expect("canonical delete must decode");
    assert_eq!(delete.operation, MongoConfigChangeOp::Delete);
}

#[test]
fn incremental_poll_accepts_int32_sequence() {
    let mut doc = well_formed_change_doc(1, "proxy-a", "upsert");
    doc.insert("sequence", Bson::Int32(9));
    let change = decode_mongo_config_change_record(&doc).expect("Int32 sequence must decode");
    assert_eq!(change.sequence, 9);
}

#[test]
fn incremental_poll_rejects_wrong_bson_types() {
    for field in ["resource_type", "resource_id", "operation"] {
        let mut doc = well_formed_change_doc(1, "secret-resource-id", "upsert");
        doc.insert(field, Bson::Int32(7));
        let error = decode_mongo_config_change_record(&doc)
            .expect_err("wrong BSON type must abort the poll");
        let message = error.to_string();
        assert!(
            message.contains("non-string field") && message.contains(field),
            "wrong-type error must name the field, got: {message}"
        );
        assert_decode_error_is_opaque(&error, &["secret-resource-id", "7"]);
    }
}

#[test]
fn incremental_poll_rejects_missing_fields() {
    for field in ["sequence", "resource_type", "resource_id", "operation"] {
        let mut doc = well_formed_change_doc(1, "secret-resource-id", "upsert");
        doc.remove(field);
        let error =
            decode_mongo_config_change_record(&doc).expect_err("missing field must abort the poll");
        let message = error.to_string();
        if field == "sequence" {
            // Issue #4530: the shared decoder names the field in quotes and
            // states the expected shape, never the payload.
            assert!(
                message.contains("invalid 'sequence'")
                    && message.contains("expected a non-negative integral number"),
                "missing sequence must fail closed, got: {message}"
            );
        } else {
            assert!(
                message.contains("missing field") && message.contains(field),
                "missing-field error must name the field, got: {message}"
            );
        }
        assert_decode_error_is_opaque(&error, &["secret-resource-id"]);
    }
}

#[test]
fn incremental_poll_rejects_invalid_operations() {
    for operation in ["", "update", "patch", "UPSERT", "Delete"] {
        let doc = well_formed_change_doc(1, "secret-resource-id", operation);
        let error = decode_mongo_config_change_record(&doc)
            .expect_err("non-canonical operation must abort the poll");
        assert!(
            error.to_string().contains("unsupported operation"),
            "invalid operation must not default to upsert, got: {error}"
        );
        assert_decode_error_is_opaque(&error, &["secret-resource-id"]);
    }
}

#[test]
fn incremental_poll_rejects_empty_resource_identity() {
    for (field, value) in [("resource_id", ""), ("resource_type", "")] {
        let mut doc = well_formed_change_doc(1, "proxy-a", "upsert");
        doc.insert(field, value);
        let error = decode_mongo_config_change_record(&doc)
            .expect_err("empty identity fields must abort the poll");
        assert!(
            error.to_string().contains("empty"),
            "empty {field} must fail closed, got: {error}"
        );
    }
}

#[test]
fn malformed_change_does_not_advance_cursor_past_later_well_formed_record() {
    let malformed = {
        let mut doc = well_formed_change_doc(5, "secret-resource-id", "upsert");
        doc.insert("resource_id", Bson::Int32(42));
        doc
    };
    let later = well_formed_change_doc(6, "later-proxy", "upsert");
    let error = incremental_cursor_after(0, &[malformed, later])
        .expect_err("typed decode failure must abort before the cursor can skip the record");
    assert!(error.to_string().contains("non-string field 'resource_id'"));
    assert_decode_error_is_opaque(&error, &["secret-resource-id", "later-proxy", "42"]);
}

#[test]
fn well_formed_batch_advances_cursor_to_max_sequence() {
    let cursor = incremental_cursor_after(
        1,
        &[
            well_formed_change_doc(2, "proxy-a", "upsert"),
            well_formed_change_doc(4, "proxy-b", "delete"),
        ],
    )
    .expect("canonical batch must decode");
    assert_eq!(cursor, 4);
}

#[test]
fn load_incremental_config_decodes_before_advancing_cursor() {
    let body = mongo_method("load_incremental_config");
    let decode_at = body
        .find("decode_mongo_config_change_record")
        .expect("incremental poll must use the fail-closed decoder");
    let cursor_at = body
        .find("sequence_cursor = sequence_cursor.max(")
        .expect("incremental poll must advance the cursor after a record is accepted");
    let question_at = body[decode_at..]
        .find('?')
        .map(|offset| decode_at + offset)
        .expect("typed decode failure must abort the poll with ?");
    assert!(
        decode_at < question_at && question_at < cursor_at,
        "cursor must advance only after a successful typed decode:\n{body}"
    );
    assert!(
        !body.contains("get_str(\"resource_type\")")
            && !body.contains("get_str(\"resource_id\")")
            && !body.contains("get_str(\"operation\")")
            && !body.contains("unwrap_or_default()"),
        "incremental poll must not default wrong-typed BSON fields:\n{body}"
    );
    assert!(
        body.contains("split_mongo_change_ops"),
        "incremental poll must split only canonical upsert/delete operations:\n{body}"
    );
}

#[test]
fn unknown_resource_type_still_decodes_so_the_cursor_can_advance() {
    let mut doc = well_formed_change_doc(8, "spec-1", "upsert");
    doc.insert("resource_type", "api_spec");
    let change = decode_mongo_config_change_record(&doc)
        .expect("unknown resource_type is ignored after a successful typed decode");
    assert_eq!(change.sequence, 8);
    assert_eq!(change.resource_type, "api_spec");
}
