//! Tests for admin API validation improvements.
//!
//! Tests credential type whitelist, credential redaction coverage,
//! and validation constants.

use serde_json::json;

#[test]
fn test_proxy_and_plugin_writes_run_hmac_transform_candidate_validation() {
    let source = include_str!("../../../src/admin/crud.rs");
    assert!(
        source
            .matches("validate_hmac_request_transform_candidates(")
            .count()
            >= 3,
        "the helper definition plus Proxy and PluginConfig admission calls must exist"
    );
    assert!(
        source.matches("std::slice::from_ref(resource)").count() >= 2,
        "both resource write paths must overlay their candidate"
    );
    let validation = source
        .rfind("validate_hmac_request_transform_candidates(")
        .expect("candidate validation call must exist");
    let persistence = source
        .rfind("resource.prepare_for_write()")
        .expect("CRUD persistence boundary must exist");
    assert!(
        validation < persistence,
        "candidate composition must be rejected before persistence"
    );
}

#[test]
fn test_batch_writes_run_hmac_transform_candidate_validation() {
    let source = include_str!("../../../src/admin/mod.rs");
    assert!(
        source.contains("crud::validate_hmac_request_transform_candidates("),
        "batch Proxy and PluginConfig admission must validate the candidate chain"
    );
    assert!(source.contains("&batch.proxies,"));
    assert!(source.contains("&batch.plugin_configs,"));
}

#[test]
fn test_plugin_graph_mutations_run_prospective_validation_before_persistence() {
    let crud_source = include_str!("../../../src/admin/crud.rs");
    assert!(crud_source.contains("validate_transaction_log_schema_candidates("));
    assert!(crud_source.contains("std::slice::from_ref(resource)"));
    assert!(crud_source.contains("Some(&existing.id)"));
    assert!(crud_source.contains(".chain(replaced_plugins.iter())"));
    assert!(crud_source.contains("is_enabled_config_graph_participant(resource)"));
    assert!(crud_source.contains("const SERIALIZE_NAMESPACE_CONFIG_ADMISSION: bool = true;"));
    assert!(crud_source.contains("tokio::task::spawn_blocking(move ||"));
    assert!(crud_source.contains("try_acquire_namespace_config_admission_lease("));
    assert!(crud_source.contains("renew_namespace_config_admission_lease("));
    assert!(crud_source.contains("release_namespace_config_admission_lease("));
    assert!(crud_source.contains("guard.ensure_held()"));
    assert!(crud_source.contains("Some(guard) => guard.run_while_held(future).await,"));
    assert!(crud_source.contains("valid_until_millis: AtomicU64"));
    assert!(crud_source.contains("sleep_until(tokio::time::Instant::from_std(valid_until))"));
    let guard_drop = crud_source
        .find("impl Drop for NamespaceConfigAdmissionGuard")
        .map(|position| &crud_source[position..])
        .expect("namespace admission guard drop implementation must exist");
    let drop_invalidation = guard_drop
        .find("self.lease_state.lose_ownership()")
        .expect("dropping the guard must invalidate its local lease state");
    let drop_stop_signal = guard_drop
        .find("self.stop_tx.take()")
        .expect("dropping the guard must stop lease renewal");
    assert!(drop_invalidation < drop_stop_signal);
    let durable_release = guard_drop
        .find("release_namespace_config_admission_lease(&namespace, &owner)")
        .expect("dropping the guard must release the owner-qualified durable lease");
    let local_unlock = guard_drop
        .find("drop(local);")
        .expect("the local writer lock must be released explicitly");
    assert!(
        durable_release < local_unlock,
        "the local writer must remain excluded until durable release finishes"
    );

    let handle_write = crud_source
        .find("async fn handle_write<R: AdminResource>(")
        .map(|position| &crud_source[position..])
        .expect("direct CRUD write handler must exist");
    let create_persistence = handle_write
        .find("R::db_create(db, &resource),")
        .expect("direct create persistence dispatch must exist");
    let create_fence = handle_write[..create_persistence]
        .rfind("run_db_write_while_held(")
        .expect("direct create persistence must remain fenced for its full lifetime");
    let update_persistence = handle_write
        .find("R::db_update(db, &resource),")
        .expect("direct update persistence dispatch must exist");
    let update_fence = handle_write[..update_persistence]
        .rfind("run_db_write_while_held(")
        .expect("direct update persistence must remain fenced for its full lifetime");
    let timestamping = handle_write
        .find("resource.set_updated_at(now);")
        .expect("server-side timestamping must precede persistence");
    assert!(
        timestamping < create_fence && timestamping < update_fence,
        "the persistence fences must follow validation, preparation, and timestamping"
    );
    assert!(create_fence < create_persistence);
    assert!(update_fence < update_persistence);
    assert!(
        handle_write[create_persistence..update_fence]
            .contains("Err(error) => return Ok(R::map_precheck_db_error(&error))"),
        "lease loss during create must retain the pre-persistence 503 contract"
    );
    let post_write = handle_write
        .find("R::after_write(db, state, namespace, &resource, existing.as_ref(), action),")
        .expect("generic post-write persistence hook must exist");
    let post_write_fence = handle_write[..post_write]
        .rfind("run_db_write_while_held(")
        .expect("post-write persistence must remain fenced for its full lifetime");
    assert!(update_persistence < post_write_fence);
    assert!(post_write_fence < post_write);
    assert!(
        handle_write[update_persistence..post_write_fence]
            .contains("Err(error) => return Ok(R::map_precheck_db_error(&error))"),
        "lease loss during update must retain the pre-persistence 503 contract"
    );

    let delete_handler = crud_source
        .find("pub(crate) async fn handle_delete<R: AdminResource>(")
        .map(|position| &crud_source[position..])
        .expect("delete handler must exist");
    let delete_validation = delete_handler
        .find("R::before_delete(db, state, namespace, &existing, &validation_ctx).await")
        .expect("delete prospective validation must exist");
    let delete_fence = delete_handler
        .find("run_db_write_while_held(")
        .expect("delete persistence must remain fenced for its full lifetime");
    let delete_persistence = delete_handler
        .find("R::db_delete(db, namespace, id),")
        .expect("delete persistence dispatch must exist");
    assert!(delete_validation < delete_fence);
    assert!(delete_fence < delete_persistence);
    assert!(
        delete_handler[delete_persistence..]
            .contains("Err(error) => return Ok(R::map_precheck_db_error(&error))"),
        "lease loss during delete must retain the pre-persistence 503 contract"
    );

    let graph_validation = crud_source
        .rfind("validate_transaction_log_schema_candidates(")
        .expect("delete candidate validation call must exist");
    let persistence = crud_source
        .rfind("resource.prepare_for_write()")
        .expect("CRUD persistence boundary must exist");
    assert!(
        graph_validation < persistence,
        "prospective graph validation must run before CRUD persistence"
    );

    let batch_source = include_str!("../../../src/admin/mod.rs");
    assert!(batch_source.contains("crud::validate_transaction_log_schema_candidates("));
    assert!(batch_source.contains("&batch.plugin_configs,"));
    assert!(batch_source.contains("is_enabled_config_graph_participant"));
    let restore_validator = batch_source
        .find("async fn validate_restore_candidate_on_blocking_pool(")
        .expect("restore candidate validator must exist");
    let restore_handler = batch_source
        .find("async fn handle_restore(")
        .expect("restore handler must exist");
    assert!(
        batch_source[restore_validator..restore_handler]
            .contains("tokio::task::spawn_blocking(move ||"),
        "restore graph construction must run off the Tokio worker"
    );
    assert!(
        batch_source[restore_handler..].contains("validate_restore_candidate_on_blocking_pool("),
        "restore must use the blocking candidate validator"
    );
    assert!(
        batch_source
            .matches("crud::lock_namespace_config_admission(db.clone(), namespace).await")
            .count()
            >= 6,
        "credential, batch, and restore mutations must share namespace admission"
    );
    assert!(
        batch_source.matches(".run_while_held(").count() >= 5,
        "credential, batch, restore, and compensating persistence must remain fenced"
    );
    let credential_persistence = batch_source
        .find("async fn persist_consumer_update(")
        .map(|position| &batch_source[position..])
        .expect("credential persistence helper must exist");
    let hmac_validation = credential_persistence
        .find("ensure_hmac_consumer_candidate(")
        .expect("final asynchronous credential validation must exist");
    let credential_fence = credential_persistence
        .find(".run_while_held(")
        .expect("credential persistence fence must exist");
    let consumer_update = credential_persistence
        .find("db.update_consumer(&consumer))")
        .expect("credential persistence dispatch must exist");
    assert!(hmac_validation < credential_fence);
    assert!(credential_fence < consumer_update);
    for handler_name in [
        "async fn handle_update_credentials(",
        "async fn handle_delete_credentials(",
        "async fn handle_append_credential(",
        "async fn handle_delete_credential_by_index(",
    ] {
        let handler = batch_source
            .find(handler_name)
            .map(|position| &batch_source[position..])
            .unwrap_or_else(|| panic!("credential handler must exist: {handler_name}"));
        let persistence = handler
            .find("persist_consumer_update(")
            .expect("credential handler must use the fenced persistence helper");
        let persistence_end = handler[persistence..]
            .find(".await")
            .map(|position| position + persistence)
            .expect("credential persistence helper must be awaited");
        assert!(
            handler[persistence..persistence_end]
                .contains("&_namespace_config_admission_guard"),
            "credential handler must pass its namespace guard: {handler_name}"
        );
    }
    let batch_persistence = batch_source
        .find("persist_payload_resources(db.as_ref(), &batch, true))")
        .expect("batch persistence dispatch must exist");
    let batch_fence = batch_source[..batch_persistence]
        .rfind(".run_while_held(")
        .expect("batch persistence must remain fenced for its full lifetime");
    assert!(batch_fence < batch_persistence);
    let restore_persistence = batch_source[restore_handler..]
        .find("db.delete_all_resources(namespace))")
        .map(|position| position + restore_handler)
        .expect("restore destructive persistence dispatch must exist");
    let restore_fence = batch_source[..restore_persistence]
        .rfind(".run_while_held(")
        .expect("restore clear must remain fenced for its full lifetime");
    assert!(restore_fence < restore_persistence);
    let restore_import = batch_source[restore_persistence..]
        .find("persist_payload_resources(db.as_ref(), &payload, false))")
        .map(|position| position + restore_persistence)
        .expect("restore import persistence dispatch must exist");
    let restore_import_fence = batch_source[..restore_import]
        .rfind(".run_while_held(")
        .expect("restore import must remain fenced for its full lifetime");
    assert!(restore_persistence < restore_import_fence);
    assert!(restore_import_fence < restore_import);
    let restore_rollback = batch_source
        .find(".run_while_held(finish_failed_restore(")
        .expect("restore compensation must remain fenced for its full lifetime");
    assert!(restore_rollback < restore_handler);
    let restore_handler_source = &batch_source[restore_handler..];
    assert!(
        restore_handler_source
            .matches("finish_failed_restore_while_held(")
            .count()
            >= 2,
        "atomic-commit and non-atomic clear failures must compensate under the lease"
    );
    let loss_marker = restore_handler_source
        .find("namespace admission was lost during import")
        .expect("restore import lease-loss recovery must exist");
    let recovery = &restore_handler_source[loss_marker..];
    let drop_invalid_guard = recovery
        .find("drop(_namespace_config_admission_guard);")
        .expect("the invalid restore guard must be dropped before reacquisition");
    let reacquire = recovery
        .find("crud::lock_namespace_config_admission(db.clone(), namespace)")
        .expect("restore compensation must reacquire namespace admission");
    let rollback = recovery
        .find("let rollback = finish_failed_restore(")
        .expect("restore compensation must be constructed under the replacement guard");
    let rollback_fence = recovery
        .find("rollback_guard.run_while_held(rollback).await")
        .expect("restore compensation must run under the replacement guard");
    assert!(drop_invalid_guard < reacquire);
    assert!(reacquire < rollback);
    assert!(rollback < rollback_fence);
    let sql_store_source = include_str!("../../../src/config/db_loader.rs");
    assert!(sql_store_source.contains("config_admission_locks"));
    assert!(sql_store_source.contains("config_admission_lease_now_sql"));
    assert!(sql_store_source.contains("self.batch_create_plugin_configs_chunk(configs).await?"));
    assert!(sql_store_source.contains("for chunk in configs.chunks(Self::BATCH_CHUNK_SIZE)"));
    assert!(sql_store_source.contains("expires_at > {now}"));
    assert!(sql_store_source.contains(
        "DELETE FROM config_admission_locks WHERE namespace = ? AND owner = ?"
    ));
    let graph_batch_persistence = sql_store_source
        .find("pub async fn batch_create_plugin_configs(")
        .map(|position| &sql_store_source[position..])
        .expect("SQL plugin batch persistence must exist");
    let graph_single_transaction = graph_batch_persistence
        .find("self.batch_create_plugin_configs_chunk(configs).await?")
        .expect("graph-aware batches must use one transaction");
    let unrelated_chunking = graph_batch_persistence
        .find("for chunk in configs.chunks(Self::BATCH_CHUNK_SIZE)")
        .expect("unrelated plugin batches must retain bounded chunks");
    assert!(graph_single_transaction < unrelated_chunking);
    let mongo_store_source = include_str!("../../../src/config/mongo_store.rs");
    assert!(mongo_store_source.contains("config_admission_locks"));
    assert!(mongo_store_source.contains("server_time_lease_acquire_pipeline"));
    assert!(mongo_store_source.contains("$$NOW"));
    assert!(mongo_store_source.contains("lease_server_time().await?"));
    assert!(mongo_store_source.contains(
        "delete_one(doc! { \"_id\": namespace, \"owner\": owner })"
    ));
    let mongo_graph_batch = mongo_store_source
        .find("async fn batch_create_plugin_configs(")
        .map(|position| &mongo_store_source[position..])
        .expect("Mongo plugin batch persistence must exist");
    let next_mongo_batch = mongo_graph_batch
        .find("async fn batch_create_upstreams(")
        .expect("Mongo upstream batch persistence must follow plugin persistence");
    let mongo_graph_batch = &mongo_graph_batch[..next_mongo_batch];
    assert!(mongo_graph_batch.contains(".start_transaction()"));
    assert!(mongo_graph_batch.contains(".insert_many(docs.clone())"));
    assert!(mongo_graph_batch.contains("rollback_standalone_created_documents("));
    assert!(
        !mongo_graph_batch.contains("configs.chunks("),
        "Mongo graph-aware batches must not split across an admission boundary"
    );

    let pipeline_source = include_str!("../../../src/config/validation_pipeline.rs");
    assert!(pipeline_source.contains("transaction_log_schema::validate_config_graph("));

    let api_spec_source = include_str!("../../../src/admin/api_specs/handlers.rs");
    assert!(api_spec_source.contains("validate_transaction_log_schema_candidates("));
    assert!(
        api_spec_source.contains("validate_transaction_log_schema_api_spec_replacement_candidate(")
    );
    assert_eq!(
        api_spec_source
            .matches(
                "crate::admin::crud::lock_namespace_config_admission(db.clone(), namespace).await",
            )
            .count(),
        3,
        "API-spec POST, PUT, and DELETE must serialize through persistence"
    );
    let post_lock = api_spec_source
        .find("crate::admin::crud::lock_namespace_config_admission(db.clone(), namespace).await")
        .expect("POST admission guard");
    let post_persist = api_spec_source
        .find("db.submit_api_spec_bundle(&bundle, &spec))")
        .expect("POST persistence");
    assert!(post_lock < post_persist);
    let post_fence = api_spec_source[..post_persist]
        .rfind(".run_while_held(")
        .expect("POST full-lifetime persistence fence");
    assert!(post_lock < post_fence);
    let put_lock = api_spec_source[post_lock + 1..]
        .find("crate::admin::crud::lock_namespace_config_admission(db.clone(), namespace).await")
        .map(|position| position + post_lock + 1)
        .expect("PUT admission guard");
    let put_persist = api_spec_source
        .find("db.replace_api_spec_bundle(&bundle, &spec))")
        .expect("PUT persistence");
    assert!(put_lock < put_persist);
    let put_fence = api_spec_source[..put_persist]
        .rfind(".run_while_held(")
        .expect("PUT full-lifetime persistence fence");
    assert!(put_lock < put_fence);
    let delete_lock = api_spec_source[put_lock + 1..]
        .find("crate::admin::crud::lock_namespace_config_admission(db.clone(), namespace).await")
        .map(|position| position + put_lock + 1)
        .expect("DELETE admission guard");
    let delete_persist = api_spec_source
        .find("db.delete_api_spec(namespace, id))")
        .expect("DELETE persistence");
    let delete_validation = api_spec_source
        .find("validate_transaction_log_schema_api_spec_deletion_candidate(")
        .expect("DELETE prospective graph validation");
    let delete_fence = api_spec_source[..delete_persist]
        .rfind(".run_while_held(")
        .expect("DELETE full-lifetime persistence fence");
    assert!(delete_lock < delete_validation);
    assert!(delete_validation < delete_fence);
    assert!(delete_fence < delete_persist);
}

#[test]
fn test_batch_hmac_uniqueness_is_gated_on_submitted_hmac_consumers() {
    let source = include_str!("../../../src/admin/mod.rs");
    let gate = r#".any(|consumer| !consumer.credential_entries("hmac_auth").is_empty())"#;
    let validation = "candidate_config.validate_unique_hmac_credentials()";
    let gate_position = source
        .find(gate)
        .expect("batch admission must detect submitted HMAC consumers");
    let validation_position = source
        .find(validation)
        .expect("batch admission must validate the authoritative HMAC candidate");
    assert!(
        gate_position < validation_position,
        "legacy HMAC duplicates must not block unrelated batch writes"
    );
}

// --- Credential type whitelist tests ---

#[test]
fn test_allowed_credential_types_contains_expected() {
    let expected = &["basicauth", "keyauth", "jwt", "hmac_auth", "mtls_auth"];
    for cred_type in expected {
        assert!(
            ferrum_edge::admin::ALLOWED_CREDENTIAL_TYPES.contains(cred_type),
            "Expected '{}' to be in ALLOWED_CREDENTIAL_TYPES",
            cred_type
        );
    }
}

#[test]
fn test_disallowed_credential_types_rejected() {
    let disallowed = &[
        "admin_flag",
        "custom",
        "unknown",
        "",
        "BASICAUTH",
        "basic_auth",
    ];
    for cred_type in disallowed {
        assert!(
            !ferrum_edge::admin::ALLOWED_CREDENTIAL_TYPES.contains(cred_type),
            "Expected '{}' to NOT be in ALLOWED_CREDENTIAL_TYPES",
            cred_type
        );
    }
}

#[test]
fn test_credential_types_count() {
    // Ensure we have exactly the 5 known credential types
    assert_eq!(
        ferrum_edge::admin::ALLOWED_CREDENTIAL_TYPES.len(),
        5,
        "Expected exactly 5 allowed credential types"
    );
}

// --- Credential redaction tests ---

fn make_consumer(
    credentials: std::collections::HashMap<String, serde_json::Value>,
) -> ferrum_edge::config::types::Consumer {
    ferrum_edge::config::types::Consumer {
        id: "test-consumer".to_string(),
        namespace: ferrum_edge::config::types::default_namespace(),
        username: "test-user".to_string(),
        custom_id: None,
        credentials,
        acl_groups: Vec::new(),
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    }
}

#[test]
fn test_redact_basicauth_password_hash_by_omission() {
    let mut credentials = std::collections::HashMap::new();
    credentials.insert(
        "basicauth".to_string(),
        json!({"username": "alice", "password_hash": "$2b$12$realhashabcdef"}),
    );
    let consumer = make_consumer(credentials);

    let redacted = ferrum_edge::admin::redact_consumer_credentials(&consumer);
    assert!(!redacted.credentials.contains_key("basicauth"));
}

#[test]
fn test_redact_basicauth_plaintext_password_by_omission() {
    let mut credentials = std::collections::HashMap::new();
    credentials.insert(
        "basicauth".to_string(),
        json!({"password": "must-not-escape"}),
    );
    let consumer = make_consumer(credentials);

    let redacted = ferrum_edge::admin::redact_consumer_credentials(&consumer);
    assert!(!redacted.credentials.contains_key("basicauth"));
}

#[test]
fn test_basic_credential_user_shape_failure_is_bad_request() {
    let mut credential = json!({
        "password": "x".repeat(ferrum_edge::config::types::MAX_CREDENTIAL_VALUE_LENGTH + 1)
    });

    let status =
        ferrum_edge::_test_support::prepare_basic_auth_credential_for_test(&mut credential)
            .expect_err("oversized Basic password must be rejected");

    assert_eq!(status, hyper::StatusCode::BAD_REQUEST);
    assert!(credential.get("password").is_some());
    assert!(credential.get("password_hash").is_none());
}

#[test]
fn test_basic_credential_server_configuration_failures_are_internal_errors() {
    assert_eq!(
        ferrum_edge::_test_support::basic_auth_server_configuration_status_for_test(None),
        Some(hyper::StatusCode::INTERNAL_SERVER_ERROR)
    );
    assert_eq!(
        ferrum_edge::_test_support::basic_auth_server_configuration_status_for_test(Some("weak")),
        Some(hyper::StatusCode::INTERNAL_SERVER_ERROR)
    );
}

#[test]
fn test_disabled_basic_auth_config_skips_plugin_construction() {
    let now = chrono::Utc::now();
    let mut plugin_config = ferrum_edge::config::types::PluginConfig {
        id: "disabled-basic-auth".to_string(),
        plugin_name: "basic_auth".to_string(),
        namespace: ferrum_edge::config::types::default_namespace(),
        // An unsupported field makes constructor invocation fail regardless of
        // process environment, so this deterministically proves the disabled
        // admin path does not construct the plugin.
        config: json!({"realm": "staged-but-unused"}),
        scope: ferrum_edge::config::types::PluginScope::Global,
        proxy_id: None,
        enabled: false,
        priority_override: None,
        api_spec_id: None,
        created_at: now,
        updated_at: now,
    };

    assert!(
        ferrum_edge::_test_support::validate_admin_plugin_config_for_test(&plugin_config).is_ok()
    );

    plugin_config.enabled = true;
    assert!(
        ferrum_edge::_test_support::validate_admin_plugin_config_for_test(&plugin_config).is_err()
    );
}

#[test]
fn test_disabled_unknown_plugin_name_remains_invalid() {
    let now = chrono::Utc::now();
    let plugin_config = ferrum_edge::config::types::PluginConfig {
        id: "disabled-unknown-plugin".to_string(),
        plugin_name: "not_a_registered_plugin".to_string(),
        namespace: ferrum_edge::config::types::default_namespace(),
        config: json!({"staged": true}),
        scope: ferrum_edge::config::types::PluginScope::Global,
        proxy_id: None,
        enabled: false,
        priority_override: None,
        api_spec_id: None,
        created_at: now,
        updated_at: now,
    };

    assert!(
        ferrum_edge::_test_support::validate_admin_plugin_config_for_test(&plugin_config).is_err()
    );
}

#[test]
fn test_admin_transaction_log_schema_rejects_unknown_closed_object_keys() {
    let now = chrono::Utc::now();
    for (id, config, expected_path) in [
        (
            "outer-key",
            json!({"schemas": {"audit": {}}, "strict": true}),
            "config.strict",
        ),
        (
            "derived-key",
            json!({
                "schemas": {
                    "audit": {
                        "derived_fields": [
                            {"name": "outcome", "kind": "outcome", "from": "status"}
                        ]
                    }
                }
            }),
            "derived_fields[0].from",
        ),
        (
            "metadata-key",
            json!({
                "schemas": {
                    "audit": {
                        "metadata": {"mode": "flatten", "on_collison": "overwrite"}
                    }
                }
            }),
            "metadata.on_collison",
        ),
    ] {
        let plugin_config = ferrum_edge::config::types::PluginConfig {
            id: id.to_string(),
            plugin_name: "transaction_log_schema".to_string(),
            namespace: ferrum_edge::config::types::default_namespace(),
            config,
            scope: ferrum_edge::config::types::PluginScope::Global,
            proxy_id: None,
            enabled: true,
            priority_override: None,
            api_spec_id: None,
            created_at: now,
            updated_at: now,
        };
        let error =
            ferrum_edge::_test_support::validate_admin_plugin_config_for_test(&plugin_config)
                .expect_err("admin constructor validation must reject unknown keys");
        assert!(error.contains(expected_path), "unexpected error: {error}");
    }
}

#[test]
fn test_basic_auth_audit_redaction_uses_one_shape_independent_marker() {
    let password_hash = format!("hmac_sha256:{}", "a".repeat(64));
    let mut credentials = std::collections::HashMap::new();
    credentials.insert(
        "basicauth".to_string(),
        json!([{
            "password_hash": password_hash.clone(),
            "credential_label": "must-not-escape"
        }]),
    );
    let consumer = make_consumer(credentials);

    let redacted = ferrum_edge::config::types::redact_consumer_credentials_for_audit(&consumer);
    assert_eq!(redacted.credentials["basicauth"], "[REDACTED]");

    let serialized = serde_json::to_string(&redacted).expect("redacted consumer serializes");
    assert!(!serialized.contains("password_hash"));
    assert!(!serialized.contains("credential_label"));
    assert!(!serialized.contains("must-not-escape"));
    assert!(!serialized.contains(&password_hash));
}

#[test]
fn test_redact_hmac_auth_secret() {
    let mut credentials = std::collections::HashMap::new();
    credentials.insert(
        "hmac_auth".to_string(),
        json!({"username": "bob", "secret": "supersecret123"}),
    );
    let consumer = make_consumer(credentials);

    let redacted = ferrum_edge::admin::redact_consumer_credentials(&consumer);
    let hmac = redacted.credentials.get("hmac_auth").unwrap();
    assert_eq!(hmac["secret"], "[REDACTED]");
    assert_eq!(hmac["username"], "bob");
}

#[test]
fn test_redact_jwt_secret() {
    let mut credentials = std::collections::HashMap::new();
    credentials.insert(
        "jwt".to_string(),
        json!({"secret": "my-jwt-secret", "algorithm": "HS256"}),
    );
    let consumer = make_consumer(credentials);

    let redacted = ferrum_edge::admin::redact_consumer_credentials(&consumer);
    let jwt = redacted.credentials.get("jwt").unwrap();
    assert_eq!(jwt["secret"], "[REDACTED]");
    assert_eq!(jwt["algorithm"], "HS256");
}

#[test]
fn test_redact_keyauth_key() {
    let mut credentials = std::collections::HashMap::new();
    credentials.insert("keyauth".to_string(), json!({"key": "api-key-value"}));
    let consumer = make_consumer(credentials);

    let redacted = ferrum_edge::admin::redact_consumer_credentials(&consumer);
    let keyauth = redacted.credentials.get("keyauth").unwrap();
    assert_eq!(keyauth["key"], "[REDACTED]");
}

#[test]
fn test_redact_multiple_credential_types() {
    let mut credentials = std::collections::HashMap::new();
    credentials.insert(
        "basicauth".to_string(),
        json!({"username": "alice", "password_hash": "hash123"}),
    );
    credentials.insert(
        "hmac_auth".to_string(),
        json!({"username": "alice", "secret": "secret123"}),
    );
    credentials.insert("keyauth".to_string(), json!({"key": "api-key-value"}));
    let consumer = make_consumer(credentials);

    let redacted = ferrum_edge::admin::redact_consumer_credentials(&consumer);

    assert!(!redacted.credentials.contains_key("basicauth"));
    assert_eq!(redacted.credentials["hmac_auth"]["secret"], "[REDACTED]");
    assert_eq!(redacted.credentials["keyauth"]["key"], "[REDACTED]");
}

#[test]
fn test_redact_mtls_identity_unchanged() {
    let mut credentials = std::collections::HashMap::new();
    credentials.insert(
        "mtls_auth".to_string(),
        json!({"identity": "CN=client.example.com"}),
    );
    let consumer = make_consumer(credentials);

    let redacted = ferrum_edge::admin::redact_consumer_credentials(&consumer);
    assert_eq!(
        redacted.credentials["mtls_auth"]["identity"],
        "CN=client.example.com"
    );
}

#[test]
fn test_redact_empty_credentials() {
    let consumer = make_consumer(std::collections::HashMap::new());
    let redacted = ferrum_edge::admin::redact_consumer_credentials(&consumer);
    assert!(redacted.credentials.is_empty());
}

// ---- Multi-credential array redaction tests ----

#[test]
fn test_redact_array_jwt_secrets() {
    let mut credentials = std::collections::HashMap::new();
    credentials.insert(
        "jwt".to_string(),
        json!([
            {"secret": "old-secret", "algorithm": "HS256"},
            {"secret": "new-secret", "algorithm": "HS256"}
        ]),
    );
    let consumer = make_consumer(credentials);

    let redacted = ferrum_edge::admin::redact_consumer_credentials(&consumer);
    let jwt = redacted.credentials.get("jwt").unwrap();
    let arr = jwt.as_array().unwrap();
    assert_eq!(arr.len(), 2);
    assert_eq!(arr[0]["secret"], "[REDACTED]");
    assert_eq!(arr[0]["algorithm"], "HS256");
    assert_eq!(arr[1]["secret"], "[REDACTED]");
    assert_eq!(arr[1]["algorithm"], "HS256");
}

#[test]
fn test_redact_array_basicauth_passwords_by_omission() {
    let mut credentials = std::collections::HashMap::new();
    credentials.insert(
        "basicauth".to_string(),
        json!([
            {"password_hash": "hash-old"},
            {"password_hash": "hash-new"}
        ]),
    );
    let consumer = make_consumer(credentials);

    let redacted = ferrum_edge::admin::redact_consumer_credentials(&consumer);
    assert!(!redacted.credentials.contains_key("basicauth"));
}

#[test]
fn test_redact_array_hmac_secrets() {
    let mut credentials = std::collections::HashMap::new();
    credentials.insert(
        "hmac_auth".to_string(),
        json!([
            {"secret": "secret-1"},
            {"secret": "secret-2"}
        ]),
    );
    let consumer = make_consumer(credentials);

    let redacted = ferrum_edge::admin::redact_consumer_credentials(&consumer);
    let hmac = redacted.credentials.get("hmac_auth").unwrap();
    let arr = hmac.as_array().unwrap();
    assert_eq!(arr.len(), 2);
    assert_eq!(arr[0]["secret"], "[REDACTED]");
    assert_eq!(arr[1]["secret"], "[REDACTED]");
}
