//! Tests for the `transaction_log_schema` plugin — the config-only plugin
//! that registers named [`SummarySchema`] definitions for other logging
//! plugins to resolve via `schema_ref:`.
//!
//! These tests exercise the construction-time validation path. Tests that
//! touch the process-global named-schemas registry hold the reload-bracket
//! serializer for their entire scope so parallel sibling tests booting
//! gateways don't stomp the registry between the test's writes and its
//! assertions.

use std::collections::{BTreeSet, HashMap};

use ferrum_edge::plugins::transaction_log_schema::TransactionLogSchema;
use ferrum_edge::plugins::utils::log_schema::{
    SchemaCapabilities, SchemaView, SummarySchema, registry,
};
use ferrum_edge::plugins::{Plugin, TransactionSummary, priority, validate_plugin_config};
use serde_json::{Value, json};

/// Hold the reload-bracket serializer across both writes and assertions
/// so parallel tests that boot gateways (and therefore drive their own
/// `begin_reload` / `commit_reload`) cannot stomp the registry mid-test.
fn registry_lock() -> registry::ReloadBracketTestGuard {
    registry::lock_for_tests()
}

// ── Plugin identity ─────────────────────────────────────────────────

#[test]
fn test_plugin_identity() {
    let _g = registry_lock();
    registry::reset_for_tests();
    let plugin = TransactionLogSchema::new(&json!({
        "schemas": { "splunk_cim": { "summary_type": "both" } }
    }))
    .expect("plugin constructs with a single valid schema");
    assert_eq!(plugin.name(), "transaction_log_schema");
    assert_eq!(plugin.priority(), priority::TRANSACTION_LOG_SCHEMA);
}

// ── Valid construction ──────────────────────────────────────────────

#[test]
fn test_valid_config_with_named_schemas_constructs() {
    let _g = registry_lock();
    registry::reset_for_tests();
    let plugin = TransactionLogSchema::new(&json!({
        "schemas": {
            "splunk_cim": {
                "summary_type": "both",
                "rename": { "proxy_id": "route_id" }
            },
            "datadog": {
                "summary_type": "http",
                "static_fields": { "source": "ferrum-edge" }
            }
        }
    }))
    .expect("plugin constructs with multiple valid schemas");
    assert_eq!(plugin.schemas().len(), 2);
    assert!(plugin.schemas().contains_key("splunk_cim"));
    assert!(plugin.schemas().contains_key("datadog"));
}

#[test]
fn test_schema_with_rename_omit_and_derived_fields_constructs() {
    let _g = registry_lock();
    registry::reset_for_tests();
    let plugin = TransactionLogSchema::new(&json!({
        "schemas": {
            "rich_schema": {
                "summary_type": "http",
                "rename": { "proxy_id": "route_id" },
                "omit": ["latency_plugin_external_io_ms"],
                "derived_fields": [
                    { "name": "status_class", "kind": "status_class" },
                    { "name": "outcome", "kind": "outcome" }
                ]
            }
        }
    }))
    .expect("plugin constructs with rename, omit, and derived_fields");
    assert_eq!(plugin.schemas().len(), 1);
}

#[test]
fn test_validate_plugin_config_path_accepts_valid_config() {
    // Validation path used by file_loader / db_loader / admin handlers.
    let _g = registry_lock();
    registry::reset_for_tests();
    validate_plugin_config(
        "transaction_log_schema",
        &json!({
            "schemas": { "datadog": { "summary_type": "http" } }
        }),
    )
    .expect("validate_plugin_config accepts a valid schema config");
}

// ── Missing / empty schemas list ────────────────────────────────────

#[test]
fn test_missing_schemas_key_rejected() {
    let _g = registry_lock();
    registry::reset_for_tests();
    let err =
        TransactionLogSchema::new(&json!({})).expect_err("missing 'schemas' must be rejected");
    assert!(err.contains("'schemas' is required"), "got: {err}");
}

#[test]
fn test_empty_schemas_object_rejected() {
    let _g = registry_lock();
    registry::reset_for_tests();
    let err = TransactionLogSchema::new(&json!({ "schemas": {} }))
        .expect_err("empty 'schemas' object must be rejected");
    assert!(err.contains("at least one"), "got: {err}");
}

#[test]
fn test_empty_schemas_via_validate_plugin_config_rejected() {
    // Same validation surface used by file_loader / admin API.
    let _g = registry_lock();
    registry::reset_for_tests();
    let err = validate_plugin_config("transaction_log_schema", &json!({ "schemas": {} }))
        .expect_err("validate_plugin_config rejects empty schemas");
    assert!(err.contains("at least one"), "got: {err}");
}

#[test]
fn test_schemas_not_object_rejected() {
    let _g = registry_lock();
    registry::reset_for_tests();
    let err = TransactionLogSchema::new(&json!({ "schemas": [] }))
        .expect_err("array-typed 'schemas' must be rejected");
    assert!(err.contains("must be an object"), "got: {err}");
}

#[test]
fn test_unknown_outer_config_key_rejected_with_path() {
    let _g = registry_lock();
    registry::reset_for_tests();
    let err = TransactionLogSchema::new(&json!({
        "schemas": { "default": {} },
        "strict": true
    }))
    .expect_err("unknown outer config keys must be rejected");
    assert!(err.contains("unknown config key 'strict'"), "got: {err}");
    assert!(err.contains("config.strict"), "got: {err}");
}

// ── Empty schema name ───────────────────────────────────────────────

#[test]
fn test_empty_schema_name_rejected() {
    let _g = registry_lock();
    registry::reset_for_tests();
    let err = TransactionLogSchema::new(&json!({
        "schemas": { "": { "summary_type": "http" } }
    }))
    .expect_err("empty schema name must be rejected");
    assert!(err.contains("non-empty"), "got: {err}");
}

// ── Invalid inner schema definitions ────────────────────────────────

#[test]
fn test_invalid_inner_schema_unknown_field_rejected() {
    let _g = registry_lock();
    registry::reset_for_tests();
    let err = TransactionLogSchema::new(&json!({
        "schemas": {
            "bad": { "omit": ["not_a_real_field"] }
        }
    }))
    .expect_err("schema with unknown field must be rejected");
    // The compile error is prefixed with the schema entry label.
    assert!(err.contains("[bad]"), "got: {err}");
    assert!(
        err.contains("unknown field 'not_a_real_field'"),
        "got: {err}"
    );
}

#[test]
fn test_invalid_inner_schema_unknown_top_level_key_rejected() {
    let _g = registry_lock();
    registry::reset_for_tests();
    let err = TransactionLogSchema::new(&json!({
        "schemas": {
            "typo": { "renaime": { "proxy_id": "route_id" } }
        }
    }))
    .expect_err("schema with typo'd top-level key must be rejected");
    assert!(err.contains("[typo]"), "got: {err}");
    assert!(err.contains("unknown schema key 'renaime'"), "got: {err}");
}

#[test]
fn test_unknown_derived_field_entry_key_rejected_with_path() {
    let _g = registry_lock();
    registry::reset_for_tests();
    let err = TransactionLogSchema::new(&json!({
        "schemas": {
            "audit": {
                "derived_fields": [
                    { "name": "outcome", "kind": "outcome", "from": "response_status_code" }
                ]
            }
        }
    }))
    .expect_err("unknown derived-field keys must be rejected");
    assert!(err.contains("[audit]"), "got: {err}");
    assert!(err.contains("derived_fields[0].from"), "got: {err}");
}

#[test]
fn test_unknown_metadata_key_rejected_with_path() {
    let _g = registry_lock();
    registry::reset_for_tests();
    let err = TransactionLogSchema::new(&json!({
        "schemas": {
            "audit": {
                "metadata": {
                    "mode": "flatten",
                    "on_collison": "overwrite"
                }
            }
        }
    }))
    .expect_err("unknown metadata keys must be rejected");
    assert!(err.contains("[audit]"), "got: {err}");
    assert!(err.contains("metadata.on_collison"), "got: {err}");
}

#[test]
fn test_invalid_inner_schema_bad_summary_type_rejected() {
    let _g = registry_lock();
    registry::reset_for_tests();
    let err = TransactionLogSchema::new(&json!({
        "schemas": {
            "bad": { "summary_type": "not_a_summary_type" }
        }
    }))
    .expect_err("schema with bogus summary_type must be rejected");
    assert!(
        err.contains("'summary_type' must be 'http', 'stream', or 'both'"),
        "got: {err}"
    );
}

#[test]
fn test_invalid_inner_schema_omit_rename_conflict_rejected() {
    let _g = registry_lock();
    registry::reset_for_tests();
    let err = TransactionLogSchema::new(&json!({
        "schemas": {
            "bad": {
                "summary_type": "http",
                "omit": ["proxy_id"],
                "rename": { "proxy_id": "route_id" }
            }
        }
    }))
    .expect_err("schema with both omit and rename for the same field must be rejected");
    assert!(err.contains("both omitted and renamed"), "got: {err}");
}

// ── Multi-entry: first valid, second invalid is rejected ────────────

#[test]
fn test_multi_entry_with_one_invalid_rejects_whole_config() {
    // The invalid entry must fail the whole construction — no silent skip.
    let _g = registry_lock();
    registry::reset_for_tests();
    let err = TransactionLogSchema::new(&json!({
        "schemas": {
            "good": { "summary_type": "http" },
            "bad":  { "omit": ["not_a_real_field"] }
        }
    }))
    .expect_err("config containing an invalid schema must be rejected");
    assert!(err.contains("[bad]"), "got: {err}");
}

// ── Registry interaction: validation-mode is a no-op ────────────────

#[test]
fn test_construction_without_reload_bracket_does_not_pollute_registry() {
    // Mirrors the admin-API single-plugin validation path: no
    // begin_reload bracket is open, so register_named must be a no-op and
    // the live registry must remain empty.
    let _g = registry_lock();
    registry::reset_for_tests();
    let plugin = TransactionLogSchema::new(&json!({
        "schemas": {
            "datadog": { "summary_type": "http" }
        }
    }))
    .expect("plugin constructs without a reload bracket");
    // The plugin owns its compiled schema...
    assert!(plugin.schemas().contains_key("datadog"));
    // ...but the live (committed) registry remains empty.
    assert!(registry::lookup_named("datadog").is_none());
}

// ── Metadata policy: known options are validated in every mode ──────

/// Compile one named schema through the plugin's shape-only validation path,
/// which never stages anything in the process-global registry.
fn validate_schema(schema: Value) -> Result<(), String> {
    validate_plugin_config(
        "transaction_log_schema",
        &json!({ "schemas": { "basic": schema } }),
    )
}

fn assert_contains(err: &str, needle: &str) {
    assert!(err.contains(needle), "expected {needle:?} in: {err}");
}

#[test]
fn test_metadata_options_are_validated_in_nested_and_omit_modes() {
    // Regression for issue #5169: `nested` and `omit` used to return before
    // the prefix / on_collision checks, so an invalid known option was
    // accepted and discarded. The config then validated until the day an
    // operator flipped the mode to `flatten`.
    for mode in ["nested", "omit", "flatten"] {
        let err = validate_schema(json!({ "metadata": { "mode": mode, "prefix": 3 } }))
            .expect_err("a non-string metadata.prefix must be rejected");
        assert_contains(&err, "'metadata.prefix' must be a string");

        let err = validate_schema(json!({
            "metadata": { "mode": mode, "prefix": "bad\u{1}" }
        }))
        .expect_err("a control character in metadata.prefix must be rejected");
        assert_contains(&err, "must not contain control characters");

        let err = validate_schema(json!({
            "metadata": { "mode": mode, "on_collision": "bad" }
        }))
        .expect_err("an unknown metadata.on_collision must be rejected");
        assert_contains(&err, "must be 'skip' or 'overwrite'");

        let err = validate_schema(json!({
            "metadata": { "mode": mode, "on_collision": 7 }
        }))
        .expect_err("a non-string metadata.on_collision must be rejected");
        assert_contains(&err, "'metadata.on_collision' must be a string");
    }
}

#[test]
fn test_valid_metadata_options_still_accepted_in_every_mode() {
    for mode in ["nested", "omit", "flatten"] {
        validate_schema(json!({
            "metadata": { "mode": mode, "prefix": "meta_", "on_collision": "overwrite" }
        }))
        .unwrap_or_else(|e| panic!("{mode} mode with valid options must compile: {e}"));
    }
}

#[test]
fn test_unknown_metadata_mode_still_names_the_mode() {
    // Option validation must not steal the diagnostic from an unknown mode.
    let err = validate_schema(json!({ "metadata": { "mode": "nope", "prefix": 3 } }))
        .expect_err("unknown mode rejected");
    assert_contains(&err, "must be 'nested', 'omit', or 'flatten' (got 'nope')");
}

// ── Native gRPC message counters are projectable ────────────────────

/// Compile a schema through the shared compiler under the base capability —
/// the same entry point `transaction_log_schema` uses per named entry.
fn compile(schema: Value) -> Result<std::sync::Arc<SummarySchema>, String> {
    SummarySchema::compile(&schema, "test", SchemaCapabilities::BASE)
}

/// Serialize `summary` through `schema`, the way every logging sink does.
fn project(summary: &TransactionSummary, schema: Value) -> Value {
    let compiled = compile(schema).expect("schema compiles");
    serde_json::to_value(SchemaView {
        summary,
        schema: &compiled,
    })
    .expect("schema view serializes")
}

fn number_at(record: &Value, key: &str) -> Option<u64> {
    record.get(key).and_then(Value::as_u64)
}

fn text_at<'a>(record: &'a Value, key: &str) -> Option<&'a str> {
    record.get(key).and_then(Value::as_str)
}

fn grpc_summary() -> TransactionSummary {
    TransactionSummary {
        namespace: "ferrum".into(),
        timestamp_received: "2026-05-11T12:00:00Z".into(),
        client_ip: "10.0.0.1".into(),
        http_method: "POST".into(),
        request_path: "/audit.Echo/Many".into(),
        proxy_id: Some("p1".into()),
        backend_target: Some("http://backend.internal:50051".into()),
        response_status_code: 200,
        grpc_request_messages: 1,
        grpc_response_messages: 3,
        metadata: HashMap::from([("grpc_status".to_string(), "0".to_string())]),
        ..TransactionSummary::default()
    }
}

#[test]
fn test_grpc_message_counters_survive_schema_projection() {
    // Regression for issue #5170: both counters were emitted by native
    // serialization but absent from HTTP_FIELDS and from the schema
    // serializer, so attaching ANY schema silently dropped gRPC message
    // observability.
    let summary = grpc_summary();
    let projected = project(&summary, json!({ "summary_type": "http" }));
    assert_eq!(number_at(&projected, "grpc_request_messages"), Some(1));
    assert_eq!(number_at(&projected, "grpc_response_messages"), Some(3));

    // An identity projection must reproduce the native line exactly.
    let native = serde_json::to_value(&summary).expect("native serializes");
    assert_eq!(projected, native);
}

#[test]
fn test_grpc_message_counters_keep_the_nonzero_native_guard() {
    // Zero means "not gRPC"; native serialization skips both keys, and so
    // must the projection.
    let summary = TransactionSummary {
        grpc_request_messages: 0,
        grpc_response_messages: 0,
        ..grpc_summary()
    };
    let projected = project(&summary, json!({ "summary_type": "http" }));
    assert_eq!(number_at(&projected, "grpc_request_messages"), None);
    assert_eq!(number_at(&projected, "grpc_response_messages"), None);
    let native = serde_json::to_value(&summary).expect("native serializes");
    assert_eq!(projected, native);
}

#[test]
fn test_grpc_message_counters_are_addressable_by_name() {
    let summary = grpc_summary();

    let renamed = project(
        &summary,
        json!({
            "summary_type": "http",
            "rename": { "grpc_request_messages": "grpc.req_msgs" }
        }),
    );
    assert_eq!(number_at(&renamed, "grpc.req_msgs"), Some(1));
    assert_eq!(number_at(&renamed, "grpc_request_messages"), None);

    let omitted = project(
        &summary,
        json!({ "summary_type": "http", "omit": ["grpc_response_messages"] }),
    );
    assert_eq!(number_at(&omitted, "grpc_response_messages"), None);
    assert_eq!(number_at(&omitted, "grpc_request_messages"), Some(1));

    // `order` accepts them like any other native output key.
    compile(json!({
        "summary_type": "http",
        "order": ["grpc_request_messages", "grpc_response_messages", "*"]
    }))
    .expect("both counters are valid order entries");
}

// ── Flatten collision reservation is precomputed ────────────────────

fn reserved(schema: &SummarySchema) -> BTreeSet<String> {
    let keys = schema.flatten_reserved.iter();
    keys.map(|key| key.to_string()).collect()
}

#[test]
fn test_flatten_reservation_set_is_compiled_once_and_only_for_flatten() {
    // Regression for issue #5171: the native and static output keys are
    // invariant across records, so they are compiled once instead of being
    // cloned into a fresh HashSet on every emitted line. Nested and omit
    // never consult the set and must not build it at all.
    for mode in ["nested", "omit"] {
        let compiled = compile(json!({
            "summary_type": "http",
            "static_fields": { "env": "production" },
            "metadata": { "mode": mode }
        }))
        .expect("schema compiles");
        assert!(
            compiled.flatten_reserved.is_empty(),
            "{mode} mode must not build a flatten reservation set"
        );
    }

    let compiled = compile(json!({
        "summary_type": "http",
        "rename": { "proxy_id": "route_id" },
        "static_fields": { "env": "production" },
        "derived_fields": [{ "name": "backend_host", "kind": "backend_host" }],
        "metadata": { "mode": "flatten" }
    }))
    .expect("schema compiles");
    let keys = reserved(&compiled);
    // Every native output key, under its RENAMED name.
    assert!(keys.contains("route_id"));
    assert!(!keys.contains("proxy_id"));
    assert!(keys.contains("response_status_code"));
    // Static keys are unconditional too.
    assert!(keys.contains("env"));
    // `metadata` is not a field under flatten, so it reserves nothing.
    assert!(!keys.contains("metadata"));
    // A derived key is reserved per record — only when the value is actually
    // emitted — so it is deliberately absent from the compiled set.
    assert!(!keys.contains("backend_host"));
}

#[test]
fn test_flatten_collision_semantics_are_unchanged_by_precomputation() {
    let summary = TransactionSummary {
        metadata: HashMap::from([
            ("client_ip".to_string(), "from-metadata".to_string()),
            ("trace_id".to_string(), "abc-123".to_string()),
        ]),
        ..grpc_summary()
    };

    // `skip`: the native field keeps the key, the metadata entry is dropped.
    let skipped = project(
        &summary,
        json!({
            "summary_type": "http",
            "metadata": { "mode": "flatten", "on_collision": "skip" }
        }),
    );
    assert_eq!(text_at(&skipped, "client_ip"), Some("10.0.0.1"));
    assert_eq!(text_at(&skipped, "trace_id"), Some("abc-123"));

    // `overwrite`: the metadata entry is emitted as a duplicate key, and
    // last-wins parsing surfaces the metadata value.
    let overwritten = project(
        &summary,
        json!({
            "summary_type": "http",
            "metadata": { "mode": "flatten", "on_collision": "overwrite" }
        }),
    );
    assert_eq!(text_at(&overwritten, "client_ip"), Some("from-metadata"));

    // A derived value that was NOT emitted does not reserve its key, so a
    // metadata entry of the same name still lands.
    let derived_flatten = json!({
        "summary_type": "http",
        "derived_fields": [{ "name": "edge", "kind": "backend_host" }],
        "metadata": { "mode": "flatten", "on_collision": "skip" }
    });
    let no_backend = TransactionSummary {
        backend_target: None,
        metadata: HashMap::from([("edge".to_string(), "from-metadata".to_string())]),
        ..grpc_summary()
    };
    let projected = project(&no_backend, derived_flatten.clone());
    assert_eq!(text_at(&projected, "edge"), Some("from-metadata"));

    // ...and when it IS emitted, it wins.
    let with_backend = TransactionSummary {
        metadata: HashMap::from([("edge".to_string(), "from-metadata".to_string())]),
        ..grpc_summary()
    };
    let projected = project(&with_backend, derived_flatten);
    assert_eq!(text_at(&projected, "edge"), Some("backend.internal"));
}

// ── Published cookbook blocks must actually compile ─────────────────

const LOG_SCHEMA_DOC: &str = include_str!("../../../docs/log_schema.md");

/// Every fenced YAML block under the operator cookbook heading.
fn cookbook_yaml_blocks() -> Vec<String> {
    let cookbook = LOG_SCHEMA_DOC
        .split("## Operator Cookbook")
        .nth(1)
        .expect("operator cookbook section")
        .split("\n## ")
        .next()
        .expect("cookbook body");
    let mut blocks = Vec::new();
    let mut current: Option<String> = None;
    for line in cookbook.lines() {
        let trimmed = line.trim_end();
        if current.is_none() {
            if trimmed == "```yaml" {
                current = Some(String::new());
            }
            continue;
        }
        if trimmed == "```" {
            if let Some(block) = current.take() {
                blocks.push(block);
            }
            continue;
        }
        if let Some(buffer) = current.as_mut() {
            buffer.push_str(line);
            buffer.push('\n');
        }
    }
    assert!(current.is_none(), "unterminated YAML cookbook block");
    assert!(!blocks.is_empty(), "no cookbook YAML blocks found");
    blocks
}

#[test]
fn test_every_published_cookbook_schema_passes_admission() {
    // Regression for issue #5167: two published cookbook blocks could not be
    // deployed as printed — a duplicate `time` output key under
    // `summary_type: both`, and a field named in both `rename` and `omit`.
    let mut compiled_any = false;
    for (index, block) in cookbook_yaml_blocks().iter().enumerate() {
        let doc: Value = serde_yaml::from_str(block)
            .unwrap_or_else(|e| panic!("cookbook block {index} is not valid YAML: {e}"));

        // Inline form: a bare `schema:` mapping.
        if let Some(schema) = doc.get("schema") {
            compile(schema.clone())
                .unwrap_or_else(|e| panic!("cookbook block {index} rejected: {e}"));
            compiled_any = true;
        }

        // Named form: a `transaction_log_schema` plugin config, validated
        // through the plugin's own shape-only path so the outer key set and
        // the non-empty `schemas` map are checked too.
        if doc.get("plugin_name") == Some(&json!("transaction_log_schema")) {
            let config = doc
                .get("config")
                .unwrap_or_else(|| panic!("cookbook block {index} has no config"));
            validate_plugin_config("transaction_log_schema", config)
                .unwrap_or_else(|e| panic!("cookbook block {index} rejected: {e}"));
            compiled_any = true;
        }

        // Referring form: `schema_ref` must name a schema the cookbook defines.
        if let Some(name) = doc
            .get("config")
            .and_then(|config| config.get("schema_ref"))
        {
            let name = name.as_str().expect("schema_ref is a string");
            assert!(
                LOG_SCHEMA_DOC.contains(&format!("    {name}:")),
                "cookbook block {index} references undefined schema '{name}'"
            );
        }
    }
    assert!(
        compiled_any,
        "no cookbook block carried a schema definition"
    );
}
