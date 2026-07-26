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
        "delete_proxy(&self, namespace: &str, id: &str)",
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
    // Issue #2989: the hash-unchanged metadata-only shortcut must verify the
    // `replace_one` (no upsert) matched a document before reporting success, so
    // a spec raced away by a concurrent DELETE surfaces an error, not a 200.
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
