//! Static parity extends the original admission/restore guards to the opt-in paths.

const SQL: &str = include_str!("../../../src/config/db_loader.rs");
const MONGO: &str = include_str!("../../../src/config/mongo_store.rs");
const ADMIN: &str = include_str!("../../../src/admin/deployment_mutations.rs");
const HANDLERS: &str = include_str!("../../../src/admin/api_specs/handlers.rs");
const ROUTES: &str = include_str!("../../../src/admin/mod.rs");

fn section<'a>(source: &'a str, start: &str, end: &str) -> &'a str {
    source
        .split(start)
        .nth(1)
        .unwrap()
        .split(end)
        .next()
        .unwrap()
}

#[test]
fn deployment_entry_pins_precede_dependency_reads_and_original_comparison() {
    let sql = section(
        SQL,
        "async fn enter_deployment_mutation_tx(",
        "async fn remove_deployment_inner(",
    );
    let mongo = section(
        MONGO,
        "async fn mutate_deployment_in_session(",
        "async fn mutate_deployment(",
    );
    for (source, pin, read) in [
        (
            sql,
            "verify_namespace_config_admission_lease_tx(",
            "deployment_snapshot_tx(",
        ),
        (
            mongo,
            "verify_namespace_config_admission_lease_in_session(",
            "deployment_snapshot_in_session(",
        ),
    ] {
        assert!(source.find(pin).unwrap() < source.find(read).unwrap());
        assert!(source.find(read).unwrap() < source.find("!= precondition.expected").unwrap());
        assert!(!source.contains("precondition.expected ="));
    }
    assert!(sql.contains("REPEATABLE READ"));
    assert!(sql.contains("SET TRANSACTION ISOLATION LEVEL READ COMMITTED"));
    assert!(
        mongo.find("deployment_pin").unwrap()
            < mongo.find("deployment_snapshot_in_session(").unwrap()
    );
    for (start, end) in [
        ("async fn remove_deployment_inner(", "/// Count ApiSpecs"),
        (
            "async fn replace_api_spec_bundle_inner(",
            "async fn preserve_deployment_unknown_columns_tx(",
        ),
    ] {
        let mutation = section(SQL, start, end);
        assert!(mutation.contains("renew_pinned_restore_lease_tx("));
        assert!(mutation.contains("tx.commit().await?"));
    }
    assert!(mongo.contains("renew_pinned_restore_lease_in_session("));
    assert!(mongo.contains("deleted.deleted_count != 1"));
    assert!(mongo.contains("replaced.matched_count != 1"));
    assert!(mongo.contains("validate_deployment_candidate("));
    assert!(!mongo.contains("PluginHttpClient::default()"));
    assert!(SQL.contains("precondition.validation_http_client"));
    assert!(ADMIN.contains("super::plugin_validation_http_client(&state)"));
    assert!(MONGO.contains(".read_concern(ReadConcern::snapshot())"));
    assert!(MONGO.contains(".write_concern(WriteConcern::majority())"));
}

#[test]
fn deployment_operations_never_restore_the_namespace_or_compensate_uncertain_commits() {
    let remove = section(
        SQL,
        "async fn remove_deployment_inner(",
        "/// Count ApiSpecs",
    );
    let mongo = section(
        MONGO,
        "async fn mutate_deployment_in_session(",
        "async fn write_conditional_namespace(",
    );
    for source in [remove, mongo, ADMIN] {
        for forbidden in [
            "delete_all_resources",
            "delete_all_namespace_resources",
            "restore_namespace_conditionally",
            "compensate_late",
            "cleanup_orphaned_proxy_group_plugins(",
        ] {
            assert!(
                !source.contains(forbidden),
                "unexpected broad mutation: {forbidden}"
            );
        }
    }
    assert!(remove.contains("for plugin_id in &plan.plugins"));
    assert!(remove.contains("for upstream_id in &plan.upstreams"));
    assert!(mongo.contains("merge_deployment_document("));
    assert!(mongo.contains("old_associations"));
    assert!(SQL.contains("preserve_deployment_unknown_columns_tx("));
    // Preserve the released ordinary settlement and restore profiles.
    assert!(HANDLERS.contains(
        "persistence_db.replace_api_spec_bundle(&persistence_bundle, &persistence_spec)"
    ));
    assert!(SQL.contains("self.replace_api_spec_bundle_inner(bundle, spec, None).await"));
    assert!(SQL.contains("self.write_config_graph_atomically(graph, mode, None).await"));
}

#[test]
fn deployment_ack_requires_audit_release_and_live_evidence() {
    let finish = section(ADMIN, "async fn finish(", "pub(super) async fn remove(");
    for check in [
        "hand_off_to_restore_transaction()",
        "prepare_live_apply_after_commit(",
        "release_after_deployment()",
        "await_prepared_live_apply(",
        "admit_security_sensitive_event(",
    ] {
        assert!(finish.contains(check), "missing completion fence: {check}");
    }
    assert!(
        finish.find("prepare_live_apply_after_commit(").unwrap()
            < finish.find("drop(permit)").unwrap()
    );
    assert!(
        finish.find("drop(permit)").unwrap() < finish.find("await_prepared_live_apply(").unwrap()
    );
    assert!(finish.contains("\"recovery_cleanup_authorized\": applicable"));
    assert!(finish.contains("unavailable(\"committed\")"));
    assert!(ADMIN.contains("get_all(hyper::header::IF_MATCH)"));
    assert!(ADMIN.contains("conditional != 1"));
    assert!(ADMIN.contains("cleanup != 1"));
    assert!(ADMIN.contains("digest.len() != 32"));
    assert!(ADMIN.contains("spawn_with_request_slot(finish_boxed("));
    assert!(HANDLERS.contains("deployment_mutations::finish_boxed("));
    assert!(ROUTES.contains("\"deployment-snapshot\" => \"deployment-snapshot\""));
}
