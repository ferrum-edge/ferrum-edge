//! `POST /batch` graph-level atomicity contract (issue #2401).
//!
//! The behavioural proof for the SQL backend lives in
//! `tests/integration/admin_batch_atomicity_tests.rs`, which drives a real
//! SQLite-backed admin API through an injected fault at every dependency phase
//! and after a chunk boundary.
//!
//! These tests cover the two things that suite cannot:
//!
//! 1. The pure fault/graph vocabulary (trip points, namespace keying, the
//!    per-namespace override registry).
//! 2. The MongoDB path's structure. CI has only a standalone `mongod`, and
//!    multi-document transactions require a replica set, so the replica-set
//!    branch is pinned by asserting the shape of the source that runs it — the
//!    same technique `mongo_store_tests.rs` uses for the DocumentDB lease
//!    fallbacks. The standalone refusal itself is exercised live against CI's
//!    standalone `mongod` by
//!    `functional_mongodb_test.rs::test_mongodb_batch_atomicity_refused_on_standalone`,
//!    and the replica-set transactional path by
//!    `test_mongodb_batch_atomicity_all_or_nothing_on_replica_set` (which CI's
//!    data-plane shard runs against a single-node replica set).

use ferrum_edge::_test_support::{
    AtomicBatchFault, AtomicBatchPhase, set_atomic_batch_chunk_size_for_test,
    set_atomic_batch_fault_for_test,
};
use ferrum_edge::config::batch_atomicity::{
    ATOMIC_BATCH_UNSUPPORTED_MESSAGE, AtomicBatchCounts, AtomicBatchGraph, AtomicBatchUnsupported,
    BATCH_ADMISSION_LEASE_LOST_MESSAGE, BatchAdmissionLeaseLost, atomic_batch_test_overrides,
    atomic_batch_unsupported, is_batch_admission_lease_lost,
};
use ferrum_edge::config::types::{Consumer, PluginAssociation, PluginConfig, Proxy, Upstream};
use serde_json::json;

const SQL_STORE_SOURCE: &str = include_str!("../../../src/config/db_loader.rs");
const MONGO_STORE_SOURCE: &str = include_str!("../../../src/config/mongo_store.rs");
const ADMIN_SOURCE: &str = include_str!("../../../src/admin/mod.rs");
const BATCH_DOC: &str = include_str!("../../../docs/admin_batch_api.md");
const OPENAPI: &str = include_str!("../../../openapi.yaml");

/// Build fixtures through serde so the crate's own `#[serde(default)]` rules
/// supply every field this test does not care about (these types intentionally
/// have no `Default` impl).
fn consumer(namespace: &str, id: &str) -> Consumer {
    serde_json::from_value(json!({
        "id": id,
        "namespace": namespace,
        "username": format!("user-{id}"),
    }))
    .expect("consumer fixture")
}

fn upstream(namespace: &str, id: &str) -> Upstream {
    serde_json::from_value(json!({
        "id": id,
        "namespace": namespace,
        "name": format!("upstream-{id}"),
        "targets": [{"host": "10.0.0.10", "port": 8080, "weight": 100}],
    }))
    .expect("upstream fixture")
}

fn proxy(namespace: &str, id: &str) -> Proxy {
    serde_json::from_value(json!({
        "id": id,
        "namespace": namespace,
        "name": format!("proxy-{id}"),
        "listen_path": format!("/{id}"),
        "backend_scheme": "http",
        "backend_host": "127.0.0.1",
        "backend_port": 8080,
    }))
    .expect("proxy fixture")
}

fn plugin_config(namespace: &str, id: &str) -> PluginConfig {
    serde_json::from_value(json!({
        "id": id,
        "namespace": namespace,
        "plugin_name": "request_size_limiting",
        "scope": "global",
        "config": {"max_bytes": 1048576},
    }))
    .expect("plugin config fixture")
}

#[test]
fn fault_trips_only_at_its_exact_phase_and_chunk_boundary() {
    let fault = AtomicBatchFault::new(AtomicBatchPhase::Proxies, 2);

    assert!(fault.trips(AtomicBatchPhase::Proxies, 2));
    // Not the phase before it, not the phase after it.
    assert!(!fault.trips(AtomicBatchPhase::Upstreams, 2));
    assert!(!fault.trips(AtomicBatchPhase::PluginConfigs, 2));
    // Not an earlier or later chunk boundary in the same phase: a fault that
    // tripped on every boundary could not distinguish "failed after the first
    // chunk committed" from "failed before writing anything".
    assert!(!fault.trips(AtomicBatchPhase::Proxies, 1));
    assert!(!fault.trips(AtomicBatchPhase::Proxies, 3));

    let pre_write = AtomicBatchFault::new(AtomicBatchPhase::Commit, 0);
    assert!(pre_write.trips(AtomicBatchPhase::Commit, 0));
    assert!(!pre_write.trips(AtomicBatchPhase::Commit, 1));
}

#[test]
fn every_dependency_phase_has_a_distinct_label() {
    let labels: Vec<&str> = [
        AtomicBatchPhase::Consumers,
        AtomicBatchPhase::Upstreams,
        AtomicBatchPhase::Proxies,
        AtomicBatchPhase::PluginConfigs,
        AtomicBatchPhase::ProxyPluginAssociations,
        AtomicBatchPhase::AdmissionRevalidation,
        AtomicBatchPhase::Commit,
    ]
    .iter()
    .map(|phase| phase.as_str())
    .collect();
    let unique: std::collections::HashSet<&&str> = labels.iter().collect();
    assert_eq!(
        unique.len(),
        labels.len(),
        "phase labels appear in injected-fault errors and must be distinguishable: {labels:?}"
    );
}

#[test]
fn graph_locks_the_union_of_request_and_resource_namespaces() {
    let consumers = vec![consumer("tenant-a", "c1")];
    let upstreams = vec![upstream("tenant-b", "u1")];
    let proxies = vec![proxy("tenant-a", "p1")];
    let plugin_configs = vec![plugin_config("tenant-c", "pc1")];
    let graph = AtomicBatchGraph {
        namespace: "tenant-a",
        consumers: &consumers,
        upstreams: &upstreams,
        proxies: &proxies,
        plugin_configs: &plugin_configs,
        admission_lease: None,
    };

    // Sorted, deduplicated, and including the request namespace even when no
    // resource carries it — a payload that reaches another namespace must not
    // slip past that namespace's admission row.
    assert_eq!(
        graph.admission_namespaces(),
        vec!["tenant-a", "tenant-b", "tenant-c"]
    );
    assert!(!graph.is_empty());
}

#[test]
fn empty_graph_is_recognized_and_reports_no_counts() {
    let graph = AtomicBatchGraph {
        namespace: "ferrum",
        consumers: &[],
        upstreams: &[],
        proxies: &[],
        plugin_configs: &[],
        admission_lease: None,
    };
    assert!(graph.is_empty());
    assert_eq!(graph.admission_namespaces(), vec!["ferrum"]);
    assert!(!AtomicBatchCounts::default().any());
    let one_upstream = AtomicBatchCounts {
        upstreams: 1,
        ..Default::default()
    };
    assert!(one_upstream.any());
}

#[test]
fn http_only_graphs_skip_post_write_policy_admission() {
    let consumers = vec![consumer("ferrum", "c1")];
    let proxies = vec![proxy("ferrum", "p1")];
    let plugin_configs = vec![plugin_config("ferrum", "pc1")];
    let http_graph = AtomicBatchGraph {
        namespace: "ferrum",
        consumers: &consumers,
        upstreams: &[],
        proxies: &proxies,
        plugin_configs: &[],
        admission_lease: None,
    };
    assert!(
        !http_graph.requires_post_write_policy_admission(),
        "HTTP proxy/consumer chunks with empty associations skip the namespace reload"
    );

    let plugin_graph = AtomicBatchGraph {
        namespace: "ferrum",
        consumers: &[],
        upstreams: &[],
        proxies: &[],
        plugin_configs: &plugin_configs,
        admission_lease: None,
    };
    assert!(
        !plugin_graph.requires_post_write_policy_admission(),
        "unrelated plugin types do not require post-write policy admission"
    );

    let mut mtls_consumer = consumer("ferrum", "c-mtls");
    mtls_consumer.credentials.insert(
        "mtls_auth".to_string(),
        json!([{ "identity": "spiffe://example.test/ns/default/sa/app" }]),
    );
    let mtls_consumers = vec![mtls_consumer];
    let mtls_graph = AtomicBatchGraph {
        namespace: "ferrum",
        consumers: &mtls_consumers,
        upstreams: &[],
        proxies: &[],
        plugin_configs: &[],
        admission_lease: None,
    };
    assert!(mtls_graph.requires_post_write_policy_admission());

    let mut associated = proxy("ferrum", "p-assoc");
    associated.plugins.push(PluginAssociation {
        plugin_config_id: "existing-plugin".to_string(),
    });
    let associated_proxies = vec![associated];
    let associated_graph = AtomicBatchGraph {
        namespace: "ferrum",
        consumers: &[],
        upstreams: &[],
        proxies: &associated_proxies,
        plugin_configs: &[],
        admission_lease: None,
    };
    assert!(associated_graph.requires_post_write_policy_admission());
}

#[test]
fn test_overrides_are_scoped_to_one_namespace_and_clear_completely() {
    let namespace = "override-scoped-ns";
    let other = "override-other-ns";
    assert_eq!(atomic_batch_test_overrides(namespace), (None, None));

    let fault = AtomicBatchFault::new(AtomicBatchPhase::Upstreams, 1);
    set_atomic_batch_fault_for_test(namespace, Some(fault));
    set_atomic_batch_chunk_size_for_test(namespace, Some(2));
    assert_eq!(
        atomic_batch_test_overrides(namespace),
        (Some(fault), Some(2))
    );
    // Integration tests share one process per shard, so a fault installed for
    // one namespace must be invisible to every other namespace.
    assert_eq!(atomic_batch_test_overrides(other), (None, None));

    // A zero chunk size would panic `chunks()`, so it is rejected rather than
    // stored.
    set_atomic_batch_chunk_size_for_test(namespace, Some(0));
    assert_eq!(atomic_batch_test_overrides(namespace).1, None);

    set_atomic_batch_fault_for_test(namespace, None);
    set_atomic_batch_chunk_size_for_test(namespace, None);
    assert_eq!(atomic_batch_test_overrides(namespace), (None, None));
}

#[test]
fn typed_refusals_are_recoverable_from_an_error_chain() {
    let unsupported: anyhow::Error =
        anyhow::Error::new(AtomicBatchUnsupported::new("start a replica set"))
            .context("wrapped by a caller");
    let recovered = atomic_batch_unsupported(&unsupported).expect("typed refusal in chain");
    assert_eq!(recovered.detail(), "start a replica set");
    // Responders render the typed message, never the outermost context, so
    // driver detail a future caller wraps above it cannot reach the wire.
    let rendered = recovered.to_string();
    assert!(rendered.starts_with(ATOMIC_BATCH_UNSUPPORTED_MESSAGE));

    let lease_lost: anyhow::Error =
        anyhow::Error::new(BatchAdmissionLeaseLost).context("wrapped by a caller");
    assert!(is_batch_admission_lease_lost(&lease_lost));
    assert!(!is_batch_admission_lease_lost(&unsupported));
    assert_eq!(
        BatchAdmissionLeaseLost.to_string(),
        BATCH_ADMISSION_LEASE_LOST_MESSAGE
    );
}

/// The SQL backend must persist the whole graph in ONE transaction: one
/// `begin()`, one `commit()`, every phase between them.
#[test]
fn sql_atomic_batch_uses_a_single_transaction_for_every_phase() {
    let wrapper = SQL_STORE_SOURCE
        .split("    pub async fn batch_create_config_graph_atomically(")
        .nth(1)
        .and_then(|tail| {
            tail.split("\n    async fn write_config_graph_atomically(")
                .next()
        })
        .expect("SQL batch delegates to the shared transaction writer");
    let delegation = "self.write_config_graph_atomically(graph, mode, None).await";
    assert!(wrapper.contains(delegation));
    assert!(!wrapper.contains("begin_write_tx"));
    assert!(!wrapper.contains("commit()"));

    let start = SQL_STORE_SOURCE
        .find("    async fn write_config_graph_atomically(")
        .expect("SQL shared atomic graph writer must exist");
    let end = SQL_STORE_SOURCE[start..]
        .find("\n    fn check_atomic_batch_fault(")
        .expect("fault helper must follow the writer")
        + start;
    let body = &SQL_STORE_SOURCE[start..end];

    assert_eq!(
        body.matches("self.begin_write_tx()").count(),
        1,
        "the atomic batch graph write must open exactly one transaction"
    );
    assert_eq!(
        body.matches("tx.commit()").count(),
        1,
        "the atomic batch graph write must commit exactly once"
    );
    // Dependency order inside that single transaction.
    let consumers = body
        .find("insert_consumers_in_tx")
        .expect("consumers phase");
    let upstreams = body
        .find("insert_upstreams_in_tx")
        .expect("upstreams phase");
    let proxies = body.find("insert_proxies_in_tx").expect("proxies phase");
    let plugins = body
        .find("insert_plugin_configs_in_tx")
        .expect("plugin configs phase");
    let associations = body
        .find("attach_proxy_plugins_in_tx")
        .expect("association phase");
    let revalidation = body
        .find("validate_namespace_admission_tx")
        .expect("in-transaction admission re-validation");
    let entry_lease = body
        .find("verify_namespace_config_admission_lease_tx")
        .expect("restore entry lease pin");
    let snapshot = body
        .find("conditional_namespace_snapshot_tx")
        .expect("conditional restore snapshot");
    let clear = body
        .find("delete_all_resources_in_tx")
        .expect("conditional restore clear");
    let batch_lease = body
        .rfind("verify_namespace_config_admission_lease_tx")
        .expect("batch commit lease fence");
    let compaction = body
        .find("compact_config_changes_tx")
        .expect("change log compaction");
    let renewal = body
        .find("renew_pinned_restore_lease_tx")
        .expect("restore commit lease renewal");
    let commit_fault_call = "Self::check_atomic_batch_fault(fault, AtomicBatchPhase::Commit, 0)?;";
    let commit_fault = body
        .find(commit_fault_call)
        .expect("last rollback fault before commit");
    let commit = body.find("tx.commit()").expect("commit");
    assert!(entry_lease < snapshot);
    assert!(snapshot < clear);
    assert!(clear < consumers);
    assert!(consumers < upstreams);
    assert!(upstreams < proxies);
    assert!(proxies < plugins, "plugin configs reference proxies");
    assert!(
        plugins < associations,
        "associations attach after both endpoints exist"
    );
    assert!(associations < revalidation);
    assert!(
        revalidation < batch_lease,
        "batch ownership must be fenced after the exact candidate is validated"
    );
    assert!(batch_lease < compaction);
    assert!(compaction < renewal);
    assert!(renewal < commit_fault);
    assert!(commit_fault < commit);
    assert_eq!(
        body.matches("verify_namespace_config_admission_lease_tx")
            .count(),
        2,
        "restore pins at entry; batch fences after graph validation"
    );
    assert!(body.contains("if restore.is_none()\n            && let Some(lease)"));
    assert!(body.contains("if restore.is_some()\n            && let Some(lease)"));
    assert_eq!(
        body[renewal..commit].matches(".await").count(),
        1,
        "only the final restore renewal may await after compaction and before commit"
    );

    let renewal_body = SQL_STORE_SOURCE
        .split("    async fn renew_pinned_restore_lease_tx(")
        .nth(1)
        .and_then(|tail| tail.split("    pub async fn delete_all_resources(").next())
        .expect("restore renewal remains inspectable");
    assert!(renewal_body.contains("WHERE namespace = ? AND owner = ? AND generation = ?"));
    assert!(renewal_body.contains(".bind(CONFIG_ADMISSION_LEASE_DURATION_MILLIS)"));
    assert!(renewal_body.contains(".bind(namespace)"));
    assert!(renewal_body.contains(".bind(lease.owner)"));
    assert!(renewal_body.contains(".bind(generation)"));
    assert!(renewal_body.contains(".execute(&mut **tx)"));
    assert!(renewal_body.contains("result.rows_affected() != 1"));
    assert!(renewal_body.contains("anyhow::Error::new(BatchAdmissionLeaseLost)"));

    // Proxies are inserted without associations so a plugin config submitted in
    // the same graph is present before anything references it.
    assert!(body.contains("self.insert_proxies_in_tx(&mut tx, chunk, false,"));
    // Every chunked phase is chunk-aware inside the one transaction, so a fault
    // after a chunk boundary is reachable and still rolls everything back.
    assert_eq!(
        body.matches(".chunks(chunk_size).enumerate()").count(),
        5,
        "consumers, upstreams, proxies, plugin configs, and associations must all be chunked"
    );
    assert!(SQL_STORE_SOURCE.contains("FOR UPDATE"));
    assert!(
        SQL_STORE_SOURCE.contains("anyhow::Error::new(BatchAdmissionLeaseLost)"),
        "a lapsed lease must abort the transaction with the typed error"
    );
}

/// MongoDB: standalone is refused before any mutation, and the replica-set path
/// is one session transaction covering every phase.
#[test]
fn mongo_atomic_batch_refuses_standalone_and_uses_one_session_transaction() {
    let start = MONGO_STORE_SOURCE
        .find("        async fn batch_create_config_graph_atomically(")
        .expect("Mongo atomic batch writer must exist");
    let end = MONGO_STORE_SOURCE[start..]
        .find("\n        async fn batch_create_proxies(")
        .expect("batch_create_proxies must follow the atomic writer")
        + start;
    let body = &MONGO_STORE_SOURCE[start..end];

    // The capability check is re-run inside the write, not just at the admin
    // preflight: a reconnect between the two must not open a partial-commit
    // window.
    let refusal = body
        .find("if !self.replica_set_configured() {")
        .expect("in-writer topology re-check");
    let session = body
        .find("connection.client.start_session()")
        .expect("session start");
    assert!(
        refusal < session,
        "standalone MongoDB must be refused before the writer touches anything"
    );
    assert!(body.contains("Self::atomic_batch_standalone_refusal()"));
    assert_eq!(
        body.matches("start_session()").count(),
        1,
        "the whole graph must share one session"
    );
    assert_eq!(
        body.matches(".start_transaction()").count(),
        1,
        "the whole graph must share one transaction"
    );
    assert!(
        MONGO_STORE_SOURCE.contains("fn ensure_atomic_batch_supported(&self)"),
        "the backend must advertise its atomic-batch capability"
    );

    // The in-session phase writer covers every phase and ends on the lease
    // check, and application-level aborts travel as a custom payload so the
    // convenient-transaction runner actually aborts.
    let writer_start = MONGO_STORE_SOURCE
        .find("        async fn write_atomic_batch_graph_in_session(")
        .expect("in-session writer must exist");
    let writer_end = MONGO_STORE_SOURCE[writer_start..]
        .find("\n    /// Everything one atomic batch transaction needs")
        .expect("plan struct must follow the in-session writer")
        + writer_start;
    let writer = &MONGO_STORE_SOURCE[writer_start..writer_end];
    for phase in [
        "AtomicBatchPhase::Consumers",
        "AtomicBatchPhase::Upstreams",
        "AtomicBatchPhase::Proxies",
        "AtomicBatchPhase::PluginConfigs",
        "AtomicBatchPhase::ProxyPluginAssociations",
        "AtomicBatchPhase::AdmissionRevalidation",
        "AtomicBatchPhase::Commit",
    ] {
        assert!(
            writer.contains(phase),
            "MongoDB must honor the {phase} fault point so both backends share one fault matrix"
        );
    }
    assert_eq!(
        writer
            .matches(".chunks(plan.chunk_size).enumerate()")
            .count(),
        4,
        "consumers, upstreams, proxies, and plugin configs must all be chunked in-session"
    );
    // A conditional in-session WRITE, not a read: the lease document has to join
    // the transaction's write set or the transaction's read snapshot would hide
    // a competing acquirer.
    let lease_check = writer
        .find("verify_namespace_config_admission_lease_in_session(")
        .expect("in-session lease verification");
    let commit_fault = writer
        .find("AtomicBatchPhase::Commit")
        .expect("commit fault point");
    let helper_start = MONGO_STORE_SOURCE
        .find("        async fn verify_namespace_config_admission_lease_in_session(")
        .expect("shared in-session lease verifier");
    let helper_end = MONGO_STORE_SOURCE[helper_start..]
        .find("\n        // ---------------------------------------------------------------")
        .expect("namespace-registry section must follow the shared lease verifier")
        + helper_start;
    let helper = &MONGO_STORE_SOURCE[helper_start..helper_end];
    assert!(helper.contains("config_admission_locks_in_transaction()"));
    assert!(helper.contains("update_one("));
    assert!(helper.contains("result.matched_count == 1"));
    assert!(
        lease_check < commit_fault,
        "the lease check is the last gate before the runner commits"
    );
    assert!(writer.contains("AtomicBatchAbort::AdmissionLeaseLost"));
    assert!(MONGO_STORE_SOURCE.contains("fn atomic_batch_transaction_error("));
    assert!(MONGO_STORE_SOURCE.contains("error.get_custom::<AtomicBatchAbort>()"));
}

/// Both backends must compare the admission lease's expiry against the
/// *database's own current* clock at the final gate.
///
/// A timestamp captured before the transaction opened is already stale by the
/// time the graph has been written, and staler still when MongoDB's convenient
/// transaction runner retries the callback. With owner and generation still
/// matching (the lease lapsed but nobody has reacquired it yet), such a
/// comparison would let the batch commit after expiry — exactly the
/// fail-closed guarantee the gate exists to provide. This test fails if a
/// precomputed expiry timestamp is reintroduced on either path.
#[test]
fn atomic_batch_lease_gate_compares_expiry_against_current_database_time() {
    // ---- MongoDB ----------------------------------------------------------
    let outer_start = MONGO_STORE_SOURCE
        .find("        async fn batch_create_config_graph_atomically(")
        .expect("Mongo atomic batch writer must exist");
    let outer_end = MONGO_STORE_SOURCE[outer_start..]
        .find("\n        async fn batch_create_proxies(")
        .expect("batch_create_proxies must follow the atomic writer")
        + outer_start;
    let outer = &MONGO_STORE_SOURCE[outer_start..outer_end];
    assert!(
        !outer.contains("lease_server_time()"),
        "the atomic-batch plan must not capture a server timestamp before the transaction: \
         it would be stale at the in-session lease gate"
    );

    let plan_start = MONGO_STORE_SOURCE
        .find("    struct MongoAtomicBatchPlan {")
        .expect("atomic batch plan struct must exist");
    let plan_end = MONGO_STORE_SOURCE[plan_start..]
        .find("\n    }")
        .expect("plan struct must terminate")
        + plan_start;
    let plan = &MONGO_STORE_SOURCE[plan_start..plan_end];
    assert!(
        !plan.contains("BsonDateTime"),
        "the atomic batch plan must carry no precomputed timestamp; the lease gate reads \
         MongoDB's clock in-session instead"
    );

    let writer_start = MONGO_STORE_SOURCE
        .find("        async fn write_atomic_batch_graph_in_session(")
        .expect("in-session writer must exist");
    let writer_end = MONGO_STORE_SOURCE[writer_start..]
        .find("\n    /// Everything one atomic batch transaction needs")
        .expect("plan struct must follow the in-session writer")
        + writer_start;
    let writer = &MONGO_STORE_SOURCE[writer_start..writer_end];
    assert!(
        writer.contains("verify_namespace_config_admission_lease_in_session("),
        "the atomic writer must use the shared in-session lease verifier"
    );
    let gate_start = MONGO_STORE_SOURCE
        .find("        async fn verify_namespace_config_admission_lease_in_session(")
        .expect("shared in-session lease verifier");
    let gate_end = MONGO_STORE_SOURCE[gate_start..]
        .find("\n        // ---------------------------------------------------------------")
        .expect("namespace-registry section must follow the shared lease verifier")
        + gate_start;
    let gate = &MONGO_STORE_SOURCE[gate_start..gate_end];
    // Owner and generation still have to match, and the expiry comparison is
    // evaluated by the server at this gate, on every runner retry.
    assert!(gate.contains("\"owner\": owner,"));
    assert!(gate.contains("\"generation\": generation,"));
    assert!(
        gate.contains("\"$expr\": { \"$gt\": [ \"$expires_at\", \"$$NOW\" ] },"),
        "the lease gate must compare expires_at against MongoDB's own $$NOW, following the \
         lease-renewal convention"
    );
    // The write that enlists the lease document in the transaction's write set
    // must stamp a truthful timestamp, not a captured one.
    assert!(gate.contains("Self::server_time_lease_touch_pipeline()"));
    let touch_start = MONGO_STORE_SOURCE
        .find("        fn server_time_lease_touch_pipeline() -> Vec<Document> {")
        .expect("server-time touch pipeline must exist");
    let touch_end = MONGO_STORE_SOURCE[touch_start..]
        .find("\n        }")
        .expect("touch pipeline must terminate")
        + touch_start;
    assert!(
        MONGO_STORE_SOURCE[touch_start..touch_end].contains("\"updated_at\": \"$$NOW\""),
        "the lease-gate write must stamp updated_at from the server clock"
    );
    // The only fallback is the DocumentDB one: reuse the same in-session
    // `$expr`/`$$NOW` filter with a classic update. A client timestamp must
    // never become the expiry predicate.
    assert!(
        gate.contains("is_pipeline_update_unsupported(&error)"),
        "pipeline-form rejection (AWS DocumentDB) must be the only fallback trigger"
    );
    let fallback_start = gate
        .find("is_pipeline_update_unsupported(&error)")
        .expect("fallback arm");
    let fallback = &gate[fallback_start..];
    assert!(
        fallback.contains("$currentDate") && fallback.contains("filter"),
        "the classic fallback must reuse the in-session $$NOW filter with a classic update"
    );
    assert!(
        !fallback.contains("lease_server_time()"),
        "the DocumentDB fallback must never reintroduce lease_server_time() as the expiry \
         authority"
    );
    assert!(
        !fallback.contains("\"expires_at\": { \"$gt\": now }"),
        "a pre-read timestamp must not become the expiry predicate"
    );
    assert!(
        gate.contains("result.matched_count == 1"),
        "the shared verifier must report only one matched live lease as valid"
    );
    assert!(writer.contains("AtomicBatchAbort::AdmissionLeaseLost"));

    // ---- SQL --------------------------------------------------------------
    let sql_start = SQL_STORE_SOURCE
        .find("    async fn verify_namespace_config_admission_lease_tx(")
        .expect("SQL in-transaction lease verification must exist");
    let sql_end = match SQL_STORE_SOURCE[sql_start..].find("\n    async fn ") {
        Some(offset) => sql_start + offset,
        None => SQL_STORE_SOURCE.len(),
    };
    let sql = &SQL_STORE_SOURCE[sql_start..sql_end];
    assert!(
        sql.contains("self.config_admission_lease_now_sql()") && sql.contains("expires_at > {now}"),
        "the SQL lease gate must compare expires_at against the database's current time"
    );
}

/// The admin handler must refuse an unsupported deployment before it mutates
/// anything, and must never report partial counts.
#[test]
fn admin_batch_handler_refuses_before_mutating_and_never_reports_partial_counts() {
    let handler_start = ADMIN_SOURCE
        .find("async fn handle_batch_create(")
        .expect("batch handler must exist");
    let handler_end = ADMIN_SOURCE[handler_start..]
        .find("\n// ---- Backup & Restore ----")
        .expect("backup section must follow the batch handler")
        + handler_start;
    let handler = &ADMIN_SOURCE[handler_start..handler_end];

    let capability = handler
        .find("db.ensure_atomic_batch_supported()")
        .expect("capability precheck");
    let lease = handler
        .find("crud::lock_namespace_config_admission(")
        .expect("admission lease acquisition");
    assert!(
        capability < lease,
        "an unsupported backend must be refused before the request takes a lease"
    );
    assert!(handler.contains("batch_create_config_graph_atomically(&graph,"));
    assert!(
        !handler.contains("persist_payload_resources("),
        "batch create must not fall back to per-family persistence"
    );
    assert!(
        handler.contains("StatusCode::CREATED"),
        "a committed graph reports 201"
    );
    assert!(
        ADMIN_SOURCE.contains("StatusCode::NOT_IMPLEMENTED"),
        "an unsupported deployment reports 501"
    );
    // Audit still fires exactly once, and only for a committed graph.
    assert_eq!(handler.matches("\"batch_create\",").count(), 1);
    assert!(handler.contains("if created.any() {"));
}

#[test]
fn atomic_batch_persist_skips_namespace_policy_reload_when_unneeded() {
    let sql_start = SQL_STORE_SOURCE
        .find("    pub async fn batch_create_config_graph_atomically(")
        .expect("SQL atomic batch writer");
    let sql_end = SQL_STORE_SOURCE[sql_start..]
        .find("\n    fn check_atomic_batch_fault(")
        .expect("fault helper follows SQL atomic writer")
        + sql_start;
    let sql = &SQL_STORE_SOURCE[sql_start..sql_end];
    assert!(
        sql.contains("requires_post_write_policy_admission()"),
        "SQL persist admission must skip the O(namespace) reload for HTTP-only chunks:\n{sql}"
    );

    let mongo_start = MONGO_STORE_SOURCE
        .find("        async fn batch_create_config_graph_atomically(")
        .expect("Mongo atomic batch writer");
    let mongo_end = MONGO_STORE_SOURCE[mongo_start..]
        .find("\n        async fn batch_create_proxies(")
        .expect("batch_create_proxies follows Mongo atomic writer")
        + mongo_start;
    let mongo = &MONGO_STORE_SOURCE[mongo_start..mongo_end];
    assert!(
        mongo.contains("requires_post_write_policy_admission()"),
        "Mongo persist admission must skip the O(namespace) reload for HTTP-only chunks:\n{mongo}"
    );
}

/// Documented semantics have to match the implementation: no `207` for
/// `POST /batch`, and the atomicity guarantee stated in both surfaces.
#[test]
fn batch_docs_and_openapi_state_the_atomic_contract() {
    let batch_path = OPENAPI
        .find("  /batch:")
        .expect("openapi must document POST /batch");
    let next_path = OPENAPI[batch_path..]
        .find("\n  /backup:")
        .expect("backup path must follow /batch")
        + batch_path;
    let batch_spec = &OPENAPI[batch_path..next_path];
    assert!(
        !batch_spec.contains("\"207\""),
        "POST /batch must not advertise a partial-success status"
    );
    assert!(
        batch_spec.contains("all-or-nothing"),
        "the openapi description must state the guarantee"
    );
    assert!(
        batch_spec.contains("\"501\""),
        "the openapi description must document the unsupported-backend refusal"
    );
    assert!(
        batch_spec.contains("\"409\""),
        "a conflicting graph is rejected in full with 409"
    );

    assert!(
        !BATCH_DOC.contains("Partial Success"),
        "the batch doc must not document a partial-success response"
    );
    assert!(
        BATCH_DOC.contains("never returns a partial success"),
        "the batch doc must state the guarantee explicitly"
    );
    assert!(BATCH_DOC.contains("all-or-nothing"));
    assert!(
        BATCH_DOC.contains("FERRUM_MONGO_REPLICA_SET"),
        "the batch doc must tell MongoDB operators what the guarantee requires"
    );
}
