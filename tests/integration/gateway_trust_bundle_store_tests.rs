//! Integration coverage for the authoritative gateway trust-bundle store and
//! its control-plane propagation (issue #3727).
//!
//! The SQL half exercises the SQLite path because every SQL backend
//! (PostgreSQL, MySQL, SQLite) shares one `DatabaseStore` implementation behind
//! dialect-specific rendering — the same reasoning `db_incremental_poll_tests`
//! documents. Backend-specific rendering is covered by the shared v001 baseline
//! (`sql_dialect.rs`), and the MongoDB implementation is exercised by the
//! MongoDB functional suite; what is unique to this resource — transactional
//! change recording, namespace predication, optimistic concurrency, validate-
//! before-swap, and the ConfigSync projection — is backend-independent and is
//! asserted here.

use base64::Engine;
use chrono::Utc;
use ferrum_edge::config::db_backend::{
    FullConfigLoadPurpose, IncrementalFullReloadReason, IncrementalResult,
    gateway_trust_bundle_revision_conflict, is_incremental_full_reload_required,
};
use ferrum_edge::config::db_loader::{DatabaseStore, DbPoolConfig};
use ferrum_edge::config::gateway_trust::GatewayTrustBundleRecord;
use ferrum_edge::config::types::GatewayConfig;
use ferrum_edge::grpc::cp_server::{CpGrpcServer, CpScope};
use ferrum_edge::identity::TrustDomain;
use ferrum_edge::modes::mesh::config::{TrustBundle, TrustBundleSet};
use tempfile::TempDir;

async fn sqlite_store() -> (DatabaseStore, TempDir) {
    let temp_dir = TempDir::new().expect("temp dir");
    let db_path = temp_dir.path().join("gateway_trust_bundle_test.db");
    let db_url = format!("sqlite:{}?mode=rwc", db_path.to_string_lossy());
    let store = DatabaseStore::connect_with_pool_config("sqlite", &db_url, DbPoolConfig::default())
        .await
        .expect("SQLite store creation must succeed");
    (store, temp_dir)
}

/// Reopen the same on-disk database with a fresh store, standing in for a
/// control-plane restart: nothing survives in process memory, so whatever the
/// reopened store returns came solely from the authoritative database.
async fn reopen(temp_dir: &TempDir) -> DatabaseStore {
    let db_path = temp_dir.path().join("gateway_trust_bundle_test.db");
    let db_url = format!("sqlite:{}?mode=rwc", db_path.to_string_lossy());
    DatabaseStore::connect_with_pool_config("sqlite", &db_url, DbPoolConfig::default())
        .await
        .expect("SQLite store reopen must succeed")
}

fn root_ca_der_base64(common_name: &str) -> String {
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
        .expect("test CA key generates");
    let mut params =
        rcgen::CertificateParams::new(Vec::<String>::new()).expect("test CA params build");
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, common_name);
    let cert = params.self_signed(&key).expect("test CA self-signs");
    base64::engine::general_purpose::STANDARD.encode(cert.der())
}

fn record(
    namespace: &str,
    trust_domain: &str,
    authorities: Vec<String>,
) -> GatewayTrustBundleRecord {
    let bundle = TrustBundleSet {
        local: TrustBundle {
            trust_domain: TrustDomain::new(trust_domain).expect("fixture trust domain"),
            x509_authorities: authorities,
            jwt_authorities: Vec::new(),
            refresh_hint_seconds: None,
        },
        federated: Vec::new(),
    };
    GatewayTrustBundleRecord::new(namespace, namespace, bundle)
}

// ── CRUD lifecycle ──────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn create_rotate_revoke_round_trips_through_the_authoritative_store() {
    let (store, temp_dir) = sqlite_store().await;
    let root_a = root_ca_der_base64("root-a");
    let created = record("ferrum", "cluster.local", vec![root_a.clone()]);

    store
        .create_gateway_trust_bundle(&created)
        .await
        .expect("create must succeed");

    let loaded = store
        .get_namespace_gateway_trust_bundle("ferrum")
        .await
        .expect("read must succeed")
        .expect("the record must exist");
    assert_eq!(loaded.trust_domain, "cluster.local");
    assert_eq!(loaded.bundle.local.x509_authorities, vec![root_a.clone()]);
    // The store assigns the revision from its durable change sequence, so the
    // only contract is "positive and backend-assigned" — deliberately NOT
    // "starts at 1", which is the per-incarnation counter this resource must
    // not have.
    assert!(
        loaded.revision >= 1,
        "create must receive a backend-assigned positive revision"
    );

    // Rotation with overlap: the new root is added alongside the old one so
    // in-flight workloads keep validating during rollout.
    let root_b = root_ca_der_base64("root-b");
    let mut rotated = loaded.clone();
    rotated.bundle.local.x509_authorities = vec![root_a.clone(), root_b.clone()];
    assert!(
        store
            .update_gateway_trust_bundle(&rotated, Some(loaded.revision))
            .await
            .expect("rotation must succeed")
    );

    let after_rotation = store
        .get_namespace_gateway_trust_bundle("ferrum")
        .await
        .expect("read must succeed")
        .expect("record still exists");
    assert_eq!(
        after_rotation.bundle.local.x509_authorities,
        vec![root_a.clone(), root_b.clone()]
    );
    assert!(
        after_rotation.revision > loaded.revision,
        "the store assigns the next revision itself, strictly advancing it"
    );

    // A restart must reconstruct exactly this state from the database alone.
    drop(store);
    let reopened = reopen(&temp_dir).await;
    let after_restart = reopened
        .get_namespace_gateway_trust_bundle("ferrum")
        .await
        .expect("read after restart must succeed")
        .expect("record survives restart");
    assert_eq!(after_restart, after_rotation);

    // Explicit revocation.
    assert!(
        reopened
            .delete_gateway_trust_bundle("ferrum", &after_restart.id)
            .await
            .expect("delete must succeed")
    );
    assert!(
        reopened
            .get_namespace_gateway_trust_bundle("ferrum")
            .await
            .expect("read must succeed")
            .is_none()
    );
    assert!(
        !reopened
            .delete_gateway_trust_bundle("ferrum", &after_restart.id)
            .await
            .expect("second delete must not error"),
        "a repeat delete reports 'nothing matched', not a phantom success"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn an_update_that_matches_no_row_reports_not_found_instead_of_a_phantom_success() {
    let (store, _temp_dir) = sqlite_store().await;
    let ghost = record("ferrum", "cluster.local", vec![root_ca_der_base64("ghost")]);
    assert!(
        !store
            .update_gateway_trust_bundle(&ghost, None)
            .await
            .expect("update of an absent record must not error")
    );
    // A phantom update must not leave a change-log record behind either.
    let sequence = store
        .latest_change_sequence("ferrum")
        .await
        .expect("sequence read");
    assert_eq!(sequence, 0, "a phantom update must record no config change");
}

// ── Optimistic concurrency ──────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn a_stale_revision_loses_the_race_without_overwriting() {
    let (store, _temp_dir) = sqlite_store().await;
    let root_a = root_ca_der_base64("root-a");
    let created = record("ferrum", "cluster.local", vec![root_a.clone()]);
    store
        .create_gateway_trust_bundle(&created)
        .await
        .expect("create must succeed");

    let read_by_both = store
        .get_namespace_gateway_trust_bundle("ferrum")
        .await
        .expect("read")
        .expect("exists");

    // Writer A commits.
    let mut writer_a = read_by_both.clone();
    writer_a.bundle.local.x509_authorities = vec![root_ca_der_base64("writer-a")];
    assert!(
        store
            .update_gateway_trust_bundle(&writer_a, Some(read_by_both.revision))
            .await
            .expect("first writer wins")
    );

    // Writer B still holds the revision it read before A committed.
    let mut writer_b = read_by_both.clone();
    writer_b.bundle.local.x509_authorities = vec![root_ca_der_base64("writer-b")];
    let error = store
        .update_gateway_trust_bundle(&writer_b, Some(read_by_both.revision))
        .await
        .expect_err("the stale writer must be refused");
    let conflict =
        gateway_trust_bundle_revision_conflict(&error).expect("a typed revision conflict");
    assert_eq!(conflict.expected, read_by_both.revision);
    assert!(
        conflict.current > read_by_both.revision,
        "the conflict must report the strictly newer revision the winner committed"
    );

    // Writer A's material is still the one stored.
    let stored = store
        .get_namespace_gateway_trust_bundle("ferrum")
        .await
        .expect("read")
        .expect("exists");
    assert_eq!(
        stored.bundle.local.x509_authorities, writer_a.bundle.local.x509_authorities,
        "the lost race must not overwrite the winner's roots"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_second_record_in_one_namespace_is_refused_by_the_store() {
    let (store, _temp_dir) = sqlite_store().await;
    store
        .create_gateway_trust_bundle(&record(
            "ferrum",
            "cluster.local",
            vec![root_ca_der_base64("first")],
        ))
        .await
        .expect("first create must succeed");

    let mut second = record("ferrum", "other.local", vec![root_ca_der_base64("second")]);
    second.id = "second".to_string();
    store
        .create_gateway_trust_bundle(&second)
        .await
        .expect_err("the namespace primary key must refuse a second record");
}

// ── Namespace isolation ─────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn one_namespace_can_neither_read_nor_delete_another_namespaces_record() {
    let (store, _temp_dir) = sqlite_store().await;
    let tenant_a = record("tenant-a", "a.local", vec![root_ca_der_base64("a-root")]);
    let tenant_b = record("tenant-b", "b.local", vec![root_ca_der_base64("b-root")]);
    store
        .create_gateway_trust_bundle(&tenant_a)
        .await
        .expect("tenant-a create");
    store
        .create_gateway_trust_bundle(&tenant_b)
        .await
        .expect("tenant-b create");

    // Addressing tenant B's id from tenant A's namespace resolves to nothing —
    // the namespace is in the WHERE clause, not applied after the read.
    assert!(
        store
            .get_gateway_trust_bundle("tenant-a", &tenant_b.id)
            .await
            .expect("read must succeed")
            .is_none()
    );
    assert!(
        !store
            .delete_gateway_trust_bundle("tenant-a", &tenant_b.id)
            .await
            .expect("delete must succeed")
    );
    assert!(
        store
            .get_namespace_gateway_trust_bundle("tenant-b")
            .await
            .expect("read must succeed")
            .is_some(),
        "tenant-b's record must survive tenant-a's delete attempt"
    );

    // Listing is namespace-scoped too.
    let page = store
        .list_gateway_trust_bundles_paginated("tenant-a", 50, 0)
        .await
        .expect("list must succeed");
    assert_eq!(page.total, 1);
    assert_eq!(page.items.len(), 1);
    assert_eq!(page.items[0].namespace, "tenant-a");
}

// ── Change detection ────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn every_trust_mutation_escalates_the_incremental_poll_to_a_full_reload() {
    let (store, _temp_dir) = sqlite_store().await;
    let start = store
        .latest_change_sequence("ferrum")
        .await
        .expect("sequence read");

    let created = record("ferrum", "cluster.local", vec![root_ca_der_base64("root")]);
    store
        .create_gateway_trust_bundle(&created)
        .await
        .expect("create");

    // `IncrementalResult` is not `Debug`, so the success arm is unwrapped by
    // hand rather than through `expect_err`.
    let error = match store.load_incremental_config("ferrum", start).await {
        Ok(_) => panic!("a trust change must escalate to a full reload"),
        Err(error) => error,
    };
    assert!(
        is_incremental_full_reload_required(&error),
        "the escalation must be the typed full-reload marker, not a generic failure"
    );
    let typed = error
        .chain()
        .find_map(|cause| {
            cause.downcast_ref::<ferrum_edge::config::db_backend::IncrementalFullReloadRequired>()
        })
        .expect("typed marker present");
    assert_eq!(
        typed.reason(),
        IncrementalFullReloadReason::GatewayTrustBundleChanges
    );

    // The same holds for a revocation, so a subscribed data plane learns about
    // a withdrawn root without a restart.
    let after_create = store
        .latest_change_sequence("ferrum")
        .await
        .expect("sequence read");
    store
        .delete_gateway_trust_bundle("ferrum", &created.id)
        .await
        .expect("delete");
    let revocation_error = match store.load_incremental_config("ferrum", after_create).await {
        Ok(_) => panic!("a revocation must escalate to a full reload too"),
        Err(error) => error,
    };
    assert!(is_incremental_full_reload_required(&revocation_error));
}

// ── Full loads and validate-before-swap ─────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn a_full_load_carries_only_the_requested_namespaces_record() {
    let (store, _temp_dir) = sqlite_store().await;
    store
        .create_gateway_trust_bundle(&record(
            "tenant-a",
            "a.local",
            vec![root_ca_der_base64("a-root")],
        ))
        .await
        .expect("tenant-a create");
    store
        .create_gateway_trust_bundle(&record(
            "tenant-b",
            "b.local",
            vec![root_ca_der_base64("b-root")],
        ))
        .await
        .expect("tenant-b create");

    let config = store
        .load_full_config_for_purpose("tenant-a", FullConfigLoadPurpose::ControlPlane)
        .await
        .expect("full load must succeed");
    assert_eq!(config.gateway_trust_bundles.len(), 1);
    assert_eq!(config.gateway_trust_bundles[0].namespace, "tenant-a");
    assert_eq!(config.gateway_trust_bundles[0].trust_domain, "a.local");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_corrupted_stored_bundle_rejects_the_load_without_leaking_material() {
    let (store, _temp_dir) = sqlite_store().await;
    let secret_marker = "SUPER-SECRET-TRUST-MATERIAL";
    store
        .create_gateway_trust_bundle(&record(
            "ferrum",
            "cluster.local",
            vec![root_ca_der_base64("root")],
        ))
        .await
        .expect("create");

    // Corrupt the stored material out-of-band, as a bad migration or a direct
    // database edit would. The load must fail closed rather than publishing an
    // unverifiable generation.
    let bad_bundle = serde_json::json!({
        "local": {
            "trust_domain": "cluster.local",
            "x509_authorities": [secret_marker],
        }
    })
    .to_string();
    sqlx::query("UPDATE gateway_trust_bundles SET bundle = ? WHERE namespace = ?")
        .bind(&bad_bundle)
        .bind("ferrum")
        .execute(&store.pool())
        .await
        .expect("out-of-band corruption applies");

    let error = store
        .load_full_config_for_purpose("ferrum", FullConfigLoadPurpose::ControlPlane)
        .await
        .expect_err("an invalid stored bundle must reject the load");
    let rendered = format!("{error:#}");
    assert!(
        !rendered.contains(secret_marker),
        "a rejection must never echo stored trust material: {rendered}"
    );
}

// ── ConfigSync projection ───────────────────────────────────────────────────

fn config_with_records(records: Vec<GatewayTrustBundleRecord>) -> GatewayConfig {
    GatewayConfig {
        version: "1".to_string(),
        loaded_at: Utc::now(),
        gateway_trust_bundles: records,
        ..Default::default()
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn the_control_plane_projects_only_the_subscribers_namespace() {
    let tenant_a = record("tenant-a", "a.local", vec![root_ca_der_base64("a-root")]);
    let tenant_b = record("tenant-b", "b.local", vec![root_ca_der_base64("b-root")]);
    let config = config_with_records(vec![tenant_a.clone(), tenant_b.clone()]);

    let scope = CpScope::Set(
        ["tenant-a".to_string(), "tenant-b".to_string()]
            .into_iter()
            .collect(),
    );
    let filtered = CpGrpcServer::filter_config_to_namespace_for_scope(&config, "tenant-a", &scope);

    let projected = filtered
        .trust_bundles
        .as_deref()
        .expect("tenant-a receives its own record");
    assert_eq!(projected.local.trust_domain.as_str(), "a.local");
    assert_eq!(
        filtered.gateway_trust_bundles.len(),
        1,
        "the record vector must be pruned to the subscriber's namespace"
    );
    assert_eq!(filtered.gateway_trust_bundles[0].namespace, "tenant-a");

    // Nothing anywhere in the filtered snapshot mentions tenant B's identity.
    let rendered = serde_json::to_string(&filtered).expect("filtered config serializes");
    assert!(
        !rendered.contains("b.local"),
        "tenant-a's slice must not carry tenant-b's trust domain"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_namespace_without_a_record_receives_no_trust_material() {
    let tenant_a = record("tenant-a", "a.local", vec![root_ca_der_base64("a-root")]);
    let config = config_with_records(vec![tenant_a]);

    let scope = CpScope::Set(
        ["tenant-a".to_string(), "tenant-b".to_string()]
            .into_iter()
            .collect(),
    );
    let filtered = CpGrpcServer::filter_config_to_namespace_for_scope(&config, "tenant-b", &scope);
    assert!(
        filtered.trust_bundles.is_none(),
        "a namespace with no record must receive nothing, not another tenant's roots"
    );
    assert!(filtered.gateway_trust_bundles.is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn a_single_namespace_control_plane_still_publishes_its_database_record() {
    let ferrum = record("ferrum", "cluster.local", vec![root_ca_der_base64("root")]);
    let config = config_with_records(vec![ferrum]);

    let filtered = CpGrpcServer::filter_config_to_namespace_for_scope(
        &config,
        "ferrum",
        &CpScope::Single("ferrum".to_string()),
    );
    let projected = filtered
        .trust_bundles
        .as_deref()
        .expect("a single-namespace CP publishes its record");
    assert_eq!(projected.local.trust_domain.as_str(), "cluster.local");
}

/// Two authorities are a REFUSAL, not a revocation: subscribers keep the last
/// generation they accepted while the misconfiguration is surfaced.
#[tokio::test(flavor = "multi_thread")]
async fn two_simultaneous_authorities_keep_previously_accepted_trust() {
    let ferrum = record(
        "ferrum",
        "cluster.local",
        vec![root_ca_der_base64("db-root")],
    );
    let mut config = config_with_records(vec![ferrum]);
    config.trust_bundles = Some(Box::new(TrustBundleSet {
        local: TrustBundle {
            trust_domain: TrustDomain::new("file.local").expect("fixture trust domain"),
            x509_authorities: vec![root_ca_der_base64("file-root")],
            jwt_authorities: Vec::new(),
            refresh_hint_seconds: None,
        },
        federated: Vec::new(),
    }));

    let (filtered, side_channel) = CpGrpcServer::filter_config_and_trust_for_scope(
        &config,
        "ferrum",
        &CpScope::Single("ferrum".to_string()),
    )
    .expect("ambiguous trust is a valid keep-previous projection");
    assert!(
        filtered.trust_bundles.is_none(),
        "an ambiguous deployment must not publish either authority's material"
    );
    assert_eq!(
        side_channel, "",
        "ambiguity must say NOTHING on the wire so the subscriber keeps its last accepted trust; \
         encoding it as `null` would revoke a working generation over a leftover file value"
    );

    // The ambiguity must be detected from the authorities as they exist BEFORE
    // namespace partitioning clears the unpartitioned slot. On a claim-requiring
    // scope the clear runs first, so a projection that classified afterwards
    // would see "database only" and publish.
    let scope = CpScope::Set(["ferrum".to_string()].into_iter().collect());
    let (multi_ns_filtered, multi_ns_side_channel) =
        CpGrpcServer::filter_config_and_trust_for_scope(&config, "ferrum", &scope)
            .expect("ambiguous trust is a valid keep-previous projection");
    assert!(multi_ns_filtered.trust_bundles.is_none());
    assert_eq!(
        multi_ns_side_channel, "",
        "the pre-clear classification must survive the multi-namespace clear"
    );
}

// ── Simultaneous writers ────────────────────────────────────────────────────

/// Two writers that raced from the SAME read must not both win.
///
/// The sequential stale-write test above only proves the store rejects a
/// revision it can see is old. This one actually issues both updates
/// concurrently, which is the case a read-then-write guard cannot survive under
/// ordinary READ COMMITTED isolation: both transactions read revision N and both
/// would write N+1, silently destroying the first rotation. The compare-and-set
/// lives in the `UPDATE` predicate, so the database serializes them.
#[tokio::test(flavor = "multi_thread")]
async fn two_simultaneous_writers_cannot_both_commit_a_rotation() {
    let (store, _temp_dir) = sqlite_store().await;
    let created = record("ferrum", "cluster.local", vec![root_ca_der_base64("root")]);
    store
        .create_gateway_trust_bundle(&created)
        .await
        .expect("create must succeed");

    let read_by_both = store
        .get_namespace_gateway_trust_bundle("ferrum")
        .await
        .expect("read")
        .expect("exists");

    let store = std::sync::Arc::new(store);
    let mut writer_a = read_by_both.clone();
    writer_a.bundle.local.x509_authorities = vec![root_ca_der_base64("writer-a")];
    let mut writer_b = read_by_both.clone();
    writer_b.bundle.local.x509_authorities = vec![root_ca_der_base64("writer-b")];

    let expected = read_by_both.revision;
    let store_a = std::sync::Arc::clone(&store);
    let store_b = std::sync::Arc::clone(&store);
    let (result_a, result_b) = tokio::join!(
        async move {
            store_a
                .update_gateway_trust_bundle(&writer_a, Some(expected))
                .await
        },
        async move {
            store_b
                .update_gateway_trust_bundle(&writer_b, Some(expected))
                .await
        }
    );

    let winners = [&result_a, &result_b]
        .iter()
        .filter(|result| matches!(result, Ok(true)))
        .count();
    assert_eq!(
        winners, 1,
        "exactly one simultaneous rotation may commit; got a={result_a:?} b={result_b:?}"
    );

    // The loser must fail, never silently no-op. When the store observed the
    // winner's commit it reports the typed conflict admin surfaces render as a
    // 409; a backend that instead refuses the interleaving outright (SQLite can
    // return a snapshot-busy error rather than letting the second transaction
    // upgrade) is equally safe, and both are asserted as "did not commit".
    let loser = [result_a, result_b]
        .into_iter()
        .find(|result| !matches!(result, Ok(true)))
        .expect("one writer must have lost");
    let error = loser.expect_err("the losing writer must report an error, not Ok(false)");
    if let Some(conflict) = gateway_trust_bundle_revision_conflict(&error) {
        assert_eq!(conflict.expected, expected);
        assert!(
            conflict.current > expected,
            "the conflict must report the strictly newer revision the winner committed"
        );
    }

    // Exactly one commit, and the stored material belongs to the winner. The
    // revision is backend-assigned from the change sequence, so the contract is
    // "strictly advanced", not "expected + 1".
    let stored = store
        .get_namespace_gateway_trust_bundle("ferrum")
        .await
        .expect("read")
        .expect("exists");
    assert!(
        stored.revision > expected,
        "the committed rotation must advance the revision past the shared read"
    );
    assert_ne!(
        stored.bundle.local.x509_authorities, created.bundle.local.x509_authorities,
        "the committed rotation must be one of the two writers', not the pre-race material"
    );
}

/// A restore/import write states no expectation, but must still compare against
/// the revision it read inside its own transaction rather than blind-writing.
#[tokio::test(flavor = "multi_thread")]
async fn an_unexpecting_writer_still_compares_and_sets() {
    let (store, _temp_dir) = sqlite_store().await;
    let created = record("ferrum", "cluster.local", vec![root_ca_der_base64("root")]);
    store
        .create_gateway_trust_bundle(&created)
        .await
        .expect("create must succeed");

    let read_by_both = store
        .get_namespace_gateway_trust_bundle("ferrum")
        .await
        .expect("read")
        .expect("exists");

    let store = std::sync::Arc::new(store);
    let mut writer_a = read_by_both.clone();
    writer_a.bundle.local.x509_authorities = vec![root_ca_der_base64("writer-a")];
    let mut writer_b = read_by_both.clone();
    writer_b.bundle.local.x509_authorities = vec![root_ca_der_base64("writer-b")];

    let store_a = std::sync::Arc::clone(&store);
    let store_b = std::sync::Arc::clone(&store);
    let (result_a, result_b) = tokio::join!(
        async move { store_a.update_gateway_trust_bundle(&writer_a, None).await },
        async move { store_b.update_gateway_trust_bundle(&writer_b, None).await }
    );

    let committed = [&result_a, &result_b]
        .iter()
        .filter(|result| matches!(result, Ok(true)))
        .count();
    assert!(
        committed >= 1,
        "at least one unexpecting writer must commit; got a={result_a:?} b={result_b:?}"
    );

    // Whatever the interleaving, every committed write strictly advanced the
    // revision — never two writes onto the same revision. The exact value comes
    // from the backend's change sequence (which other mutations also advance),
    // so the assertion is monotonicity, not arithmetic.
    let stored = store
        .get_namespace_gateway_trust_bundle("ferrum")
        .await
        .expect("read")
        .expect("exists");
    assert!(
        committed >= 1 && stored.revision > read_by_both.revision,
        "each committed write must advance the revision"
    );
}

/// A lost compare-and-set must be CLASSIFIED from an authoritative re-read, not
/// from the value the transaction read before the race.
///
/// The store re-reads after ending the failed transaction, which is what makes
/// the classification backend-independent: MySQL's default REPEATABLE READ
/// serves every later consistent read in a transaction from the snapshot the
/// first SELECT established, so an in-transaction re-read would report the
/// pre-race revision on MySQL while PostgreSQL and SQLite reported the winner's.
/// Two consequences are asserted here because they are observable on every
/// backend and are exactly what the stale report produced:
///
/// 1. a conflict must never say `current == expected` — that is a conflict with
///    itself, and it tells an admin client to retry with the revision that just
///    failed;
/// 2. a PUT that lost to a concurrent DELETE must report not-found, never a
///    conflict, because asserting a revision for a revoked record claims the
///    trust material still exists.
///
/// The interleaving is genuinely racy, so every assertion is an invariant that
/// must hold for whichever outcome the round produced. It is deliberately not
/// written to require a particular winner: pinning one would make the test
/// flaky, and a test that only ever passes because the writer won would be
/// asserting nothing. The deterministic halves of the same contract are covered
/// by `an_update_that_matches_no_row_reports_not_found_instead_of_a_phantom_success`
/// (pre-read not-found) and `a_stale_revision_loses_the_race_without_overwriting`
/// (pre-read conflict). MySQL's snapshot behaviour itself is not reproducible on
/// the SQLite path this suite runs; the store avoids it structurally by
/// re-reading outside the failed transaction.
#[tokio::test(flavor = "multi_thread")]
async fn a_lost_compare_and_set_is_classified_from_an_authoritative_re_read() {
    let (store, _temp_dir) = sqlite_store().await;
    let store = std::sync::Arc::new(store);

    for round in 0..24 {
        // Each round starts from a known-absent record so the revision the
        // writer expects is the one this round created.
        let _ = store.delete_gateway_trust_bundle("ferrum", "ferrum").await;
        let created = record(
            "ferrum",
            "cluster.local",
            vec![root_ca_der_base64(&format!("root-{round}"))],
        );
        store
            .create_gateway_trust_bundle(&created)
            .await
            .expect("create must succeed");
        let read = store
            .get_namespace_gateway_trust_bundle("ferrum")
            .await
            .expect("read")
            .expect("exists");

        let mut writer = read.clone();
        writer.bundle.local.x509_authorities = vec![root_ca_der_base64("rotation")];
        let expected = read.revision;
        let store_writer = std::sync::Arc::clone(&store);
        let store_revoker = std::sync::Arc::clone(&store);
        let (update_result, _) = tokio::join!(
            async move {
                store_writer
                    .update_gateway_trust_bundle(&writer, Some(expected))
                    .await
            },
            async move {
                store_revoker
                    .delete_gateway_trust_bundle("ferrum", "ferrum")
                    .await
            }
        );

        match update_result {
            // Committed, or lost to the revocation and reported not-found.
            Ok(_) => {}
            Err(error) => {
                if let Some(conflict) = gateway_trust_bundle_revision_conflict(&error) {
                    assert_eq!(
                        conflict.expected, expected,
                        "the reported expectation must be the one the caller stated"
                    );
                    assert_ne!(
                        conflict.current, conflict.expected,
                        "a conflict reporting the expectation back as the current revision is \
                         the stale pre-race read, not an authoritative observation"
                    );
                }
                // A backend that refuses the interleaving outright (SQLite can
                // return a snapshot-busy error rather than letting the second
                // transaction upgrade) is equally safe: it did not commit.
            }
        }
    }
}

// ── Incarnation safety (delete/recreate ABA) ────────────────────────────────

/// A recreated record must never reuse a revision the deleted incarnation held.
///
/// This is the property that makes the compare-and-set meaningful across a
/// revocation. With a per-record counter that restarts at 1, every incarnation
/// of the namespace singleton would hand out the same first revision, and a
/// client that read the old one would hold a token that still "matches".
#[tokio::test(flavor = "multi_thread")]
async fn delete_and_recreate_assigns_a_strictly_newer_revision() {
    let (store, _temp_dir) = sqlite_store().await;

    let mut previous_revision = 0_u64;
    for round in 0..4 {
        store
            .create_gateway_trust_bundle(&record(
                "ferrum",
                "cluster.local",
                vec![root_ca_der_base64(&format!("root-{round}"))],
            ))
            .await
            .expect("create must succeed");
        let created = store
            .get_namespace_gateway_trust_bundle("ferrum")
            .await
            .expect("read")
            .expect("exists");
        assert!(
            created.revision > previous_revision,
            "incarnation {round} reused or regressed a revision: {} after {}",
            created.revision,
            previous_revision
        );
        previous_revision = created.revision;

        // A rotation inside the incarnation also strictly advances.
        let mut rotated = created.clone();
        rotated.bundle.local.x509_authorities = vec![root_ca_der_base64("rotated")];
        assert!(
            store
                .update_gateway_trust_bundle(&rotated, Some(created.revision))
                .await
                .expect("rotation must succeed")
        );
        let after = store
            .get_namespace_gateway_trust_bundle("ferrum")
            .await
            .expect("read")
            .expect("exists");
        assert!(after.revision > previous_revision);
        previous_revision = after.revision;

        assert!(
            store
                .delete_gateway_trust_bundle("ferrum", &after.id)
                .await
                .expect("delete must succeed")
        );
    }
}

/// The ABA attack itself: read, someone else revokes and recreates, then the
/// stale reader writes back with the revision it saw.
///
/// The namespace admission lease serializes the individual writes but cannot
/// span the gap between the reader's GET and its later PUT, so only a revision
/// that is never reused can refuse this. The replacement's material must
/// survive untouched.
#[tokio::test(flavor = "multi_thread")]
async fn a_stale_expectation_from_a_previous_incarnation_cannot_overwrite_the_replacement() {
    let (store, _temp_dir) = sqlite_store().await;
    store
        .create_gateway_trust_bundle(&record(
            "ferrum",
            "cluster.local",
            vec![root_ca_der_base64("original-root")],
        ))
        .await
        .expect("create must succeed");

    // The victim reads the first incarnation.
    let stale_read = store
        .get_namespace_gateway_trust_bundle("ferrum")
        .await
        .expect("read")
        .expect("exists");

    // A second actor revokes and immediately recreates the singleton.
    assert!(
        store
            .delete_gateway_trust_bundle("ferrum", &stale_read.id)
            .await
            .expect("delete must succeed")
    );
    let replacement_root = root_ca_der_base64("replacement-root");
    let recreated = record("ferrum", "cluster.local", vec![replacement_root.clone()]);
    store
        .create_gateway_trust_bundle(&recreated)
        .await
        .expect("recreate must succeed");
    let replacement = store
        .get_namespace_gateway_trust_bundle("ferrum")
        .await
        .expect("read")
        .expect("exists");
    assert!(
        replacement.revision > stale_read.revision,
        "the replacement incarnation must not reuse the deleted one's revision"
    );

    // The stale client now writes back with the revision it read before the
    // delete. It must be refused.
    let mut stale_write = stale_read.clone();
    stale_write.bundle.local.x509_authorities = vec![root_ca_der_base64("attacker-root")];
    let error = store
        .update_gateway_trust_bundle(&stale_write, Some(stale_read.revision))
        .await
        .expect_err("a stale pre-delete expectation must never commit");
    let conflict =
        gateway_trust_bundle_revision_conflict(&error).expect("a typed revision conflict");
    assert_eq!(conflict.expected, stale_read.revision);
    assert_eq!(conflict.current, replacement.revision);

    let stored = store
        .get_namespace_gateway_trust_bundle("ferrum")
        .await
        .expect("read")
        .expect("exists");
    assert_eq!(
        stored.bundle.local.x509_authorities,
        vec![replacement_root],
        "the recreated incarnation's roots must survive the stale write"
    );
    assert_eq!(stored.revision, replacement.revision);
}

/// The same expectation against a namespace whose record is simply GONE must be
/// not-found, not a conflict and never a resurrection.
#[tokio::test(flavor = "multi_thread")]
async fn a_stale_expectation_after_a_revocation_reports_not_found() {
    let (store, _temp_dir) = sqlite_store().await;
    store
        .create_gateway_trust_bundle(&record(
            "ferrum",
            "cluster.local",
            vec![root_ca_der_base64("original-root")],
        ))
        .await
        .expect("create must succeed");
    let stale_read = store
        .get_namespace_gateway_trust_bundle("ferrum")
        .await
        .expect("read")
        .expect("exists");
    assert!(
        store
            .delete_gateway_trust_bundle("ferrum", &stale_read.id)
            .await
            .expect("delete must succeed")
    );

    assert!(
        !store
            .update_gateway_trust_bundle(&stale_read, Some(stale_read.revision))
            .await
            .expect("a revoked record must report not-found, not error"),
        "a stale expectation against a revoked record must not resurrect it"
    );
    assert!(
        store
            .get_namespace_gateway_trust_bundle("ferrum")
            .await
            .expect("read")
            .is_none(),
        "the namespace must remain revoked"
    );
}

/// A caller-authored revision is never persisted: the store stamps the value it
/// assigns. Without this, a restore payload or a hand-built record could seed a
/// revision a later incarnation repeats.
#[tokio::test(flavor = "multi_thread")]
async fn a_caller_supplied_revision_is_ignored_on_create() {
    let (store, _temp_dir) = sqlite_store().await;
    let mut seeded = record("ferrum", "cluster.local", vec![root_ca_der_base64("root")]);
    seeded.revision = 9_000_000;
    store
        .create_gateway_trust_bundle(&seeded)
        .await
        .expect("create must succeed");

    let stored = store
        .get_namespace_gateway_trust_bundle("ferrum")
        .await
        .expect("read")
        .expect("exists");
    assert_ne!(
        stored.revision, 9_000_000,
        "the store must assign the revision, not adopt the caller's"
    );
    assert!(stored.revision >= 1);
}

// ── Fail-closed stored-row decoding ─────────────────────────────────────────

/// Security metadata must fail closed. A revision that is not a positive
/// integer means the row is not the monotonic record the concurrency contract
/// assumes; silently substituting `1` would let a corrupt row win a
/// compare-and-set.
#[tokio::test(flavor = "multi_thread")]
async fn a_row_with_an_out_of_range_revision_is_refused_rather_than_defaulted() {
    let (store, _temp_dir) = sqlite_store().await;
    store
        .create_gateway_trust_bundle(&record(
            "ferrum",
            "cluster.local",
            vec![root_ca_der_base64("root")],
        ))
        .await
        .expect("create");

    sqlx::query("UPDATE gateway_trust_bundles SET revision = ? WHERE namespace = ?")
        .bind(-1_i64)
        .bind("ferrum")
        .execute(&store.pool())
        .await
        .expect("out-of-band corruption applies");

    store
        .get_namespace_gateway_trust_bundle("ferrum")
        .await
        .expect_err("a non-positive revision must refuse the row");
}

/// An unparseable timestamp is corrupt security metadata too: inventing
/// `Utc::now()` would make a corrupted row look like a fresh rotation on every
/// single load.
#[tokio::test(flavor = "multi_thread")]
async fn a_row_with_an_unparseable_timestamp_is_refused_rather_than_defaulted() {
    let (store, _temp_dir) = sqlite_store().await;
    store
        .create_gateway_trust_bundle(&record(
            "ferrum",
            "cluster.local",
            vec![root_ca_der_base64("root")],
        ))
        .await
        .expect("create");

    sqlx::query("UPDATE gateway_trust_bundles SET updated_at = ? WHERE namespace = ?")
        .bind("not-a-timestamp")
        .bind("ferrum")
        .execute(&store.pool())
        .await
        .expect("out-of-band corruption applies");

    let error = store
        .get_namespace_gateway_trust_bundle("ferrum")
        .await
        .expect_err("an unparseable timestamp must refuse the row");
    let rendered = format!("{error:#}");
    assert!(
        !rendered.contains("not-a-timestamp"),
        "a rejection must not echo the stored value: {rendered}"
    );
}

// ── Side-channel encoding across scopes ─────────────────────────────────────

/// `Replace` for the subscriber's own record, `null` for a namespace with
/// nothing — across every scope shape.
#[tokio::test(flavor = "multi_thread")]
async fn every_scope_publishes_replace_for_a_record_and_clear_for_none() {
    let tenant_a = record("tenant-a", "a.local", vec![root_ca_der_base64("a-root")]);
    let config = config_with_records(vec![tenant_a]);

    let scopes = [
        CpScope::Single("tenant-a".to_string()),
        CpScope::Set(
            ["tenant-a".to_string(), "tenant-b".to_string()]
                .into_iter()
                .collect(),
        ),
        CpScope::All,
    ];

    for scope in &scopes {
        let (_, side_channel) =
            CpGrpcServer::filter_config_and_trust_for_scope(&config, "tenant-a", scope)
                .expect("valid tenant trust must encode");
        assert!(
            side_channel.contains("a.local"),
            "a namespace with a record must receive it on {scope:?}"
        );

        let (other, other_side_channel) =
            CpGrpcServer::filter_config_and_trust_for_scope(&config, "tenant-b", scope)
                .expect("authoritative absence must encode as clear");
        assert_eq!(
            other_side_channel, "null",
            "a namespace with no record must be told so explicitly on {scope:?}"
        );
        assert!(
            !other_side_channel.contains("a.local"),
            "tenant-b must never observe tenant-a's material"
        );
        assert!(other.gateway_trust_bundles.is_empty());
    }
}

/// An ordinary resource delta says NOTHING about trust. Before issue #3727 it
/// encoded `null`, which the data plane reads as an explicit revocation, so
/// every unrelated configuration change silently revoked trust.
#[tokio::test(flavor = "multi_thread")]
async fn an_ordinary_resource_delta_leaves_applied_trust_untouched() {
    use ferrum_edge::config::gateway_trust::GatewayTrustPublication;

    let (tx, mut rx) = tokio::sync::broadcast::channel(4);
    let delta = IncrementalResult {
        added_or_modified_proxies: vec![],
        removed_proxy_ids: vec![],
        added_or_modified_consumers: vec![],
        removed_consumer_ids: vec![],
        added_or_modified_plugin_configs: vec![],
        removed_plugin_config_ids: vec![],
        added_or_modified_upstreams: vec![],
        removed_upstream_ids: vec![],
        sequence_cursor: 0,
        poll_timestamp: Utc::now(),
    };
    let version = delta.poll_timestamp.to_rfc3339();
    assert!(CpGrpcServer::broadcast_delta_with_trust_bundles(
        &tx,
        &delta,
        &version,
        GatewayTrustPublication::Unchanged,
    ));
    assert_eq!(
        rx.try_recv()
            .expect("the delta reaches the subscriber channel")
            .trust_bundles_json,
        "",
        "an unrelated delta must encode as an EMPTY side channel"
    );
}
