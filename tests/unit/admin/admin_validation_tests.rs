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
    assert!(crud_source.contains("pub(crate) async fn run_persistence<F, T>("));
    assert!(crud_source.contains("self.persistence_task = Some(tokio::spawn(async move"));
    assert!(
        crud_source.matches(".run_persistence(async move").count() >= 2,
        "generic guarded create/update and delete must own persistence futures"
    );

    let guard_drop = crud_source
        .find("impl Drop for NamespaceConfigAdmissionGuard")
        .map(|position| &crud_source[position..])
        .expect("namespace admission guard Drop implementation");
    let wait_for_persistence = guard_drop
        .find("if let Some(task) = persistence_task")
        .expect("Drop cleanup must await an in-flight persistence task");
    let durable_release = guard_drop
        .find(".release_namespace_config_admission_lease(&namespace, &owner)")
        .expect("Drop cleanup must owner-qualify durable release");
    let local_release = guard_drop
        .find("drop(local);")
        .expect("Drop cleanup must explicitly release the local mutex last");
    assert!(wait_for_persistence < durable_release);
    assert!(durable_release < local_release);
    assert!(guard_drop.contains("store_namespace_config_admission_handoff("));
    assert!(guard_drop.contains("handing ownership to the next local writer"));
    assert!(crud_source.contains("NamespaceConfigAdmissionLeaseState"));
    assert!(crud_source.contains("let mut renewal_task = tokio::spawn(async move"));
    assert!(crud_source.contains(
        "Namespace config admission lease renewal settled after local expiry"
    ));
    assert!(crud_source.contains("renewal completed after local expiry"));
    assert!(crud_source.contains("let post_write_error = if matches!(&result, Ok(true))"));

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
        batch_source.contains("admission_guard.ensure_held()"),
        "credential persistence must recheck namespace admission after async validation"
    );
    assert!(
        batch_source.matches(".run_persistence(async move").count() >= 3,
        "credentials, batch, and restore must own their persistence futures"
    );
    let restore_owned_future = batch_source
        .find("persist_restore_after_validation(")
        .expect("restore persistence helper must exist");
    let restore_run = batch_source
        .rfind(".run_persistence(async move")
        .expect("restore handler must run an owned persistence future");
    assert!(restore_owned_future < restore_run);
    assert!(batch_source.contains("rollback_failed_restore(db.as_ref(), namespace"));
    let sql_store_source = include_str!("../../../src/config/db_loader.rs");
    assert!(sql_store_source.contains("config_admission_locks"));
    assert!(sql_store_source.contains("config_admission_lease_now_sql"));
    assert!(sql_store_source.contains("self.batch_create_plugin_configs_chunk(configs).await?"));
    let mongo_store_source = include_str!("../../../src/config/mongo_store.rs");
    assert!(mongo_store_source.contains("config_admission_locks"));
    assert!(mongo_store_source.contains("server_time_lease_acquire_pipeline"));

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
    assert_eq!(
        api_spec_source.matches(".run_persistence(async move").count(),
        3,
        "API-spec POST, PUT, and DELETE must own persistence through completion"
    );
    let post_lock = api_spec_source
        .find("crate::admin::crud::lock_namespace_config_admission(db.clone(), namespace).await")
        .expect("POST admission guard");
    let post_persist = api_spec_source
        .find(".submit_api_spec_bundle(&persistence_bundle, &persistence_spec)")
        .expect("POST persistence");
    assert!(post_lock < post_persist);
    let put_lock = api_spec_source[post_lock + 1..]
        .find("crate::admin::crud::lock_namespace_config_admission(db.clone(), namespace).await")
        .map(|position| position + post_lock + 1)
        .expect("PUT admission guard");
    let put_persist = api_spec_source
        .find(".replace_api_spec_bundle(&persistence_bundle, &persistence_spec)")
        .expect("PUT persistence");
    assert!(put_lock < put_persist);
    let delete_lock = api_spec_source[put_lock + 1..]
        .find("crate::admin::crud::lock_namespace_config_admission(db.clone(), namespace).await")
        .map(|position| position + put_lock + 1)
        .expect("DELETE admission guard");
    let delete_persist = api_spec_source
        .find(".delete_api_spec(&persistence_namespace, &persistence_id)")
        .expect("DELETE persistence");
    let delete_validation = api_spec_source
        .find("validate_transaction_log_schema_api_spec_deletion_candidate(")
        .expect("DELETE prospective graph validation");
    assert!(delete_lock < delete_validation);
    assert!(delete_validation < delete_persist);
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
