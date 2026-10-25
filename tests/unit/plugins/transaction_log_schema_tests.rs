//! Tests for the `transaction_log_schema` plugin — the config-only plugin
//! that registers named [`SummarySchema`] definitions for other logging
//! plugins to resolve via `schema_ref:`.
//!
//! These tests exercise the construction-time validation path. Tests that
//! touch the process-global named-schemas registry hold the reload-bracket
//! serializer for their entire scope so parallel sibling tests booting
//! gateways don't stomp the registry between the test's writes and its
//! assertions.

use std::collections::BTreeSet;

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
        TransactionLogSchema::new(&json!({})).expect_err("missing `schemas` must be rejected");
    assert!(err.contains("`schemas` is required"), "got: {err}");
}

#[test]
fn test_empty_schemas_object_rejected() {
    let _g = registry_lock();
    registry::reset_for_tests();
    let err = TransactionLogSchema::new(&json!({ "schemas": {} }))
        .expect_err("empty `schemas` object must be rejected");
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
        .expect_err("array-typed `schemas` must be rejected");
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
    assert!(err.contains("unknown config key \"strict\""), "got: {err}");
    assert!(err.contains("`config`"), "got: {err}");
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
    assert!(err.contains("entry \"bad\""), "got: {err}");
    assert!(
        err.contains("unknown field \"not_a_real_field\""),
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
    assert!(err.contains("entry \"typo\""), "got: {err}");
    assert!(err.contains("unknown schema key \"renaime\""), "got: {err}");
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
    assert!(err.contains("entry \"audit\""), "got: {err}");
    assert!(
        err.contains("\"from\" at `derived_fields[0]`"),
        "got: {err}"
    );
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
    assert!(err.contains("entry \"audit\""), "got: {err}");
    assert!(err.contains("\"on_collison\" at `metadata`"), "got: {err}");
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
        err.contains("`summary_type` must be `http`, `stream`, or `both`"),
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
    assert!(err.contains("entry \"bad\""), "got: {err}");
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
        assert_contains(&err, "`metadata.prefix` must be a string");

        let err = validate_schema(json!({
            "metadata": { "mode": mode, "prefix": "bad\u{1}" }
        }))
        .expect_err("a control character in metadata.prefix must be rejected");
        assert_contains(&err, "must not contain control characters");

        let err = validate_schema(json!({
            "metadata": { "mode": mode, "on_collision": "bad" }
        }))
        .expect_err("an unknown metadata.on_collision must be rejected");
        assert_contains(&err, "must be `skip` or `overwrite`");

        let err = validate_schema(json!({
            "metadata": { "mode": mode, "on_collision": 7 }
        }))
        .expect_err("a non-string metadata.on_collision must be rejected");
        assert_contains(&err, "`metadata.on_collision` must be a string");
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
    assert_contains(
        &err,
        "must be `nested`, `omit`, or `flatten` (got \"nope\")",
    );
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
        metadata: ferrum_edge::plugins::MetadataMap::from_iter([(
            "grpc_status".to_string(),
            "0".to_string(),
        )]),
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
        metadata: ferrum_edge::plugins::MetadataMap::from_iter([
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

    // `overwrite`: the metadata value replaces the native value in place
    // (see `test_flatten_overwrite_replaces_in_place_without_duplicate_keys`
    // for the single-key guarantee on the serialized line).
    let overwritten = project(
        &summary,
        json!({
            "summary_type": "http",
            "metadata": { "mode": "flatten", "on_collision": "overwrite" }
        }),
    );
    // The overwriting value is the redaction marker: `client_ip` is not an
    // allowlisted metadata name (fail closed, issue #6619).
    assert_eq!(text_at(&overwritten, "client_ip"), Some("[REDACTED]"));

    // A derived value that was NOT emitted does not reserve its key, so a
    // metadata entry of the same name still lands.
    let derived_flatten = json!({
        "summary_type": "http",
        "derived_fields": [{ "name": "edge", "kind": "backend_host" }],
        "metadata": { "mode": "flatten", "on_collision": "skip" }
    });
    let no_backend = TransactionSummary {
        backend_target: None,
        metadata: ferrum_edge::plugins::MetadataMap::from_iter([(
            "edge".to_string(),
            "from-metadata".to_string(),
        )]),
        ..grpc_summary()
    };
    let projected = project(&no_backend, derived_flatten.clone());
    assert_eq!(text_at(&projected, "edge"), Some("[REDACTED]"));

    // ...and when it IS emitted, it wins.
    let with_backend = TransactionSummary {
        metadata: ferrum_edge::plugins::MetadataMap::from_iter([(
            "edge".to_string(),
            "from-metadata".to_string(),
        )]),
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

#[test]
fn startup_diagnostics_withhold_schema_names_keys_and_output_fields() {
    let secret = "'diagnostic-marker-5594`\"\\\n";
    for (schema, context) in [
        (json!(false), "`schema` must be an object"),
        (json!({secret: true}), "unknown schema key"),
        (
            json!({"metadata": {"mode": secret}}),
            "`metadata.mode` must be `nested`, `omit`, or `flatten`",
        ),
        (
            json!({"static_fields": {secret: null}}),
            "`static_fields` value for",
        ),
        (
            json!({"derived_fields": [{"name": "safe", "kind": "outcome", secret: 1}]}),
            "`derived_fields[0]`",
        ),
        (
            json!({"rename": {"proxy_id": secret}, "order": []}),
            "`order` missing entries",
        ),
        (
            json!({"static_fields": {secret: "safe"}, "rename": {"proxy_id": secret}}),
            "duplicate output key",
        ),
        (
            json!({"order": [secret, "*"]}),
            "`order` references unknown output key",
        ),
    ] {
        let error = validate_plugin_config(
            "transaction_log_schema",
            &json!({"schemas": {secret: schema}}),
        )
        .expect_err("invalid named schema must still be rejected");
        let rendered = ferrum_edge::startup::render_startup_error(anyhow::Error::msg(error), &[]);
        assert!(rendered.contains("transaction_log_schema"), "{rendered}");
        assert!(rendered.contains(context), "{rendered}");
        assert!(!rendered.contains("diagnostic-marker-5594"), "{rendered}");
    }

    let error = validate_schema(json!({"omit": ["proxy_idd"]})).unwrap_err();
    let rendered = ferrum_edge::startup::render_startup_error(anyhow::Error::msg(error), &[]);
    assert!(rendered.contains("schema `omit`"), "{rendered}");
    assert!(rendered.contains("did you mean `proxy_id`"), "{rendered}");
    assert!(!rendered.contains("proxy_idd"), "{rendered}");
}

#[test]
fn startup_diagnostics_preserve_named_schema_enum_paths() {
    let schema_name = "'SchemaName5594`\"\\\n";
    let value = "'EnumValue5594`\"\\\n";
    for (schema, path, reason) in [
        (
            json!({"summary_type": value}),
            "`summary_type`",
            "must be `http`, `stream`, or `both`",
        ),
        (
            json!({"timestamp_format": value}),
            "`timestamp_format`",
            "must be `rfc3339`, `epoch_ms`, or `epoch_s`",
        ),
        (
            json!({"derived_fields": [
                {"name": "first", "kind": "outcome"},
                {"name": "'DerivedName5594`\"\\\n", "kind": value}
            ]}),
            "`derived_fields[1].kind`",
            "unknown derived kind",
        ),
    ] {
        let error = validate_plugin_config(
            "transaction_log_schema",
            &json!({"schemas": {schema_name: schema}}),
        )
        .expect_err("invalid enum must reject named-schema admission");
        let rendered = ferrum_edge::startup::render_startup_error(anyhow::Error::msg(error), &[]);
        for visible in ["transaction_log_schema", "`schemas` entry", path, reason] {
            assert!(rendered.contains(visible), "{rendered}");
        }
        for hidden in ["SchemaName5594", "EnumValue5594", "DerivedName5594"] {
            assert!(!rendered.contains(hidden), "{rendered}");
        }
    }
}

// ── `metadata` directives that contradict the metadata mode ─────────

#[test]
fn test_metadata_directives_contradicting_the_mode_are_rejected() {
    // `omit: [metadata]` under flatten would promote every metadata entry to
    // the top level — the opposite of what it says — and was silently
    // accepted; `rename` of `metadata` under flatten / omit was a silent
    // no-op. All three are rejected now.
    let error = compile(json!({
        "omit": ["metadata"],
        "metadata": { "mode": "flatten", "prefix": "meta_" }
    }))
    .unwrap_err();
    assert_contains(&error, "`omit` lists `metadata`");
    assert_contains(&error, "metadata.mode: omit");

    let error = compile(json!({
        "rename": { "metadata": "attrs" },
        "metadata": { "mode": "flatten" }
    }))
    .unwrap_err();
    assert_contains(&error, "`rename` of `metadata` has no effect");
    assert_contains(&error, "metadata.mode: flatten");

    let error = compile(json!({
        "rename": { "metadata": "attrs" },
        "metadata": { "mode": "omit" }
    }))
    .unwrap_err();
    assert_contains(&error, "`rename` of `metadata` has no effect");
    assert_contains(&error, "metadata.mode: omit");

    // The named-schema admission path refuses the same contradiction.
    assert!(
        validate_plugin_config(
            "transaction_log_schema",
            &json!({ "schemas": { "audit": {
                "omit": ["metadata"],
                "metadata": { "mode": "flatten" }
            } } }),
        )
        .is_err()
    );

    // Consistent combinations keep compiling: a redundant omit under
    // `mode: omit`, and nested-mode rename / omit.
    compile(json!({ "omit": ["metadata"], "metadata": { "mode": "omit" } }))
        .expect("omit + mode omit is redundant but consistent");
    compile(json!({ "rename": { "metadata": "attrs" } })).expect("nested rename still compiles");
    compile(json!({ "omit": ["metadata"], "metadata": { "mode": "nested" } }))
        .expect("nested omit still compiles");
}

// ── flatten + overwrite replaces in place ───────────────────────────

fn line(summary: &TransactionSummary, schema: Value) -> String {
    let compiled = compile(schema).expect("schema compiles");
    serde_json::to_string(&SchemaView {
        summary,
        schema: &compiled,
    })
    .expect("schema view serializes")
}

fn key_count(line: &str, key: &str) -> usize {
    line.matches(&format!("\"{key}\":")).count()
}

#[test]
fn test_flatten_overwrite_replaces_in_place_without_duplicate_keys() {
    // `on_collision: overwrite` used to append a second JSON key with the
    // same name, so the record meant different things to last-wins,
    // first-wins, and duplicate-rejecting parsers. The serialized line (not a
    // `serde_json::Value`, which hides duplicates) must carry each key once.
    let summary = TransactionSummary {
        metadata: ferrum_edge::plugins::MetadataMap::from_iter([
            ("client_ip".to_string(), "from-metadata".to_string()),
            ("trace_id".to_string(), "abc-123".to_string()),
            ("edge".to_string(), "from-metadata".to_string()),
            ("only_in_metadata".to_string(), "x".to_string()),
        ]),
        ..grpc_summary()
    };
    let schema = json!({
        "summary_type": "http",
        "static_fields": { "trace_id": "static-value" },
        "derived_fields": [{ "name": "edge", "kind": "backend_host" }],
        "metadata": { "mode": "flatten", "on_collision": "overwrite" }
    });
    let rendered = line(&summary, schema.clone());
    for key in ["client_ip", "trace_id", "edge", "only_in_metadata"] {
        assert_eq!(key_count(&rendered, key), 1, "{key} in {rendered}");
    }
    let parsed: Value = serde_json::from_str(&rendered).expect("line parses");
    // Native collision: the metadata value (redacted: `client_ip` is not an
    // allowlisted metadata key) replaces the native value...
    assert_eq!(text_at(&parsed, "client_ip"), Some("[REDACTED]"));
    // ...in the native field's position, ahead of later native fields.
    let client_ip_at = rendered.find("\"client_ip\":").expect("client_ip");
    let method_at = rendered.find("\"http_method\":").expect("http_method");
    assert!(client_ip_at < method_at, "{rendered}");
    // Static and derived collisions are replaced in place too.
    assert_eq!(text_at(&parsed, "trace_id"), Some("abc-123"));
    assert!(text_at(&parsed, "edge").is_some());
    assert_ne!(text_at(&parsed, "edge"), Some("backend.internal"));

    // `skip` is unchanged: the schema's own field keeps every key, once.
    let skipped = line(
        &summary,
        json!({
            "summary_type": "http",
            "static_fields": { "trace_id": "static-value" },
            "metadata": { "mode": "flatten", "on_collision": "skip" }
        }),
    );
    assert_eq!(key_count(&skipped, "client_ip"), 1);
    assert_eq!(key_count(&skipped, "trace_id"), 1);
    let parsed: Value = serde_json::from_str(&skipped).expect("line parses");
    assert_eq!(text_at(&parsed, "client_ip"), Some("10.0.0.1"));
    assert_eq!(text_at(&parsed, "trace_id"), Some("static-value"));
}

#[test]
fn test_flatten_overwrite_honors_the_prefix() {
    let summary = TransactionSummary {
        metadata: ferrum_edge::plugins::MetadataMap::from_iter([
            ("trace_id".to_string(), "abc-123".to_string()),
            ("_dedup_key".to_string(), "dedup-sentinel-7f3a".to_string()),
        ]),
        ..grpc_summary()
    };
    // `meta_trace_id` (static) collides with the promoted `trace_id`.
    let rendered = line(
        &summary,
        json!({
            "summary_type": "http",
            "static_fields": { "meta_trace_id": "static", "trace_id": "unprefixed" },
            "metadata": { "mode": "flatten", "prefix": "meta_", "on_collision": "overwrite" }
        }),
    );
    assert_eq!(key_count(&rendered, "meta_trace_id"), 1, "{rendered}");
    assert_eq!(key_count(&rendered, "trace_id"), 1, "{rendered}");
    let parsed: Value = serde_json::from_str(&rendered).expect("line parses");
    assert_eq!(text_at(&parsed, "meta_trace_id"), Some("abc-123"));
    // The unprefixed static key is not the promoted key, so it is untouched.
    assert_eq!(text_at(&parsed, "trace_id"), Some("unprefixed"));
    // Internal-only lifecycle metadata is never emitted.
    assert!(!rendered.contains("dedup-sentinel-7f3a"), "{rendered}");
    assert!(parsed.get("meta__dedup_key").is_none(), "{rendered}");
    assert!(parsed.get("_dedup_key").is_none(), "{rendered}");
}

// ── Compiler bounds ─────────────────────────────────────────────────

#[test]
fn test_schema_compiler_bounds_are_enforced() {
    use ferrum_edge::plugins::utils::log_schema::{
        MAX_DERIVED_FIELDS, MAX_METADATA_PREFIX_BYTES, MAX_OUTPUT_KEY_BYTES,
        MAX_SCHEMA_LIST_ENTRIES, MAX_STATIC_FIELD_DEPTH, MAX_STATIC_FIELDS,
        MAX_STATIC_FIELDS_BYTES,
    };

    // List lengths.
    let omit = vec![json!("proxy_id"); MAX_SCHEMA_LIST_ENTRIES + 1];
    assert_contains(&compile(json!({ "omit": omit })).unwrap_err(), "`omit` has");
    let order = vec![json!("*"); MAX_SCHEMA_LIST_ENTRIES + 1];
    assert_contains(
        &compile(json!({ "order": order })).unwrap_err(),
        "`order` has",
    );

    // Output-key lengths.
    let long_key = "k".repeat(MAX_OUTPUT_KEY_BYTES + 1);
    let max_key = "k".repeat(MAX_OUTPUT_KEY_BYTES);
    assert_contains(
        &compile(json!({ "rename": { "proxy_id": long_key } })).unwrap_err(),
        "at most",
    );
    compile(json!({ "rename": { "proxy_id": max_key } })).expect("128-byte rename target");
    assert_contains(
        &compile(json!({ "static_fields": { (long_key.clone()): "v" } })).unwrap_err(),
        "at most",
    );
    assert_contains(
        &compile(json!({ "derived_fields": [{ "name": long_key, "kind": "outcome" }] }))
            .unwrap_err(),
        "at most",
    );

    // Static field count, total bytes, and nesting depth.
    let many: serde_json::Map<String, Value> = (0..=MAX_STATIC_FIELDS)
        .map(|index| (format!("stamp_{index}"), json!("v")))
        .collect();
    assert_contains(
        &compile(json!({ "static_fields": many })).unwrap_err(),
        "`static_fields` has",
    );
    let at_cap: serde_json::Map<String, Value> = (0..MAX_STATIC_FIELDS)
        .map(|index| (format!("stamp_{index}"), json!("v")))
        .collect();
    compile(json!({ "static_fields": at_cap })).expect("64 static fields compile");
    assert_contains(
        &compile(json!({ "static_fields": { "blob": "x".repeat(MAX_STATIC_FIELDS_BYTES) } }))
            .unwrap_err(),
        "serialize to more than",
    );
    compile(json!({ "static_fields": { "blob": "x".repeat(MAX_STATIC_FIELDS_BYTES / 2) } }))
        .expect("a static payload under the byte cap compiles");
    // The cap is the exact serialized JSON of the whole object:
    // `{"blob":"<n>"}` is n + 11 bytes.
    compile(json!({ "static_fields": { "blob": "x".repeat(MAX_STATIC_FIELDS_BYTES - 11) } }))
        .expect("a static object of exactly the byte cap compiles");
    assert_contains(
        &compile(json!({ "static_fields": { "blob": "x".repeat(MAX_STATIC_FIELDS_BYTES - 10) } }))
            .unwrap_err(),
        "serialize to more than",
    );
    // Escaped key bytes count: 64 keys of 126 NULs (six bytes each once
    // JSON-escaped) plus a two-digit index used to fit under a raw-length
    // budget while serializing to over 55 KiB.
    let escaped: serde_json::Map<String, Value> = (0..MAX_STATIC_FIELDS)
        .map(|index| {
            (
                format!("{}{index:02}", "\u{0}".repeat(126)),
                json!("x".repeat(100)),
            )
        })
        .collect();
    assert_contains(
        &compile(json!({ "static_fields": escaped })).unwrap_err(),
        "serialize to more than",
    );
    let nested = |levels: usize| {
        let mut value = json!("leaf");
        for _ in 0..levels {
            value = json!([value]);
        }
        value
    };
    compile(json!({ "static_fields": { "deep": nested(MAX_STATIC_FIELD_DEPTH) } }))
        .expect("nesting at the cap compiles");
    assert_contains(
        &compile(json!({ "static_fields": { "deep": nested(MAX_STATIC_FIELD_DEPTH + 1) } }))
            .unwrap_err(),
        "nests deeper than",
    );

    // Derived field count.
    let derived: Vec<Value> = (0..=MAX_DERIVED_FIELDS)
        .map(|index| json!({ "name": format!("derived_{index}"), "kind": "outcome" }))
        .collect();
    assert_contains(
        &compile(json!({ "derived_fields": derived })).unwrap_err(),
        "`derived_fields` has",
    );

    // Metadata prefix length.
    assert_contains(
        &compile(json!({
            "metadata": { "mode": "flatten", "prefix": "p".repeat(MAX_METADATA_PREFIX_BYTES + 1) }
        }))
        .unwrap_err(),
        "`metadata.prefix` must be at most",
    );
}

#[test]
fn test_named_schema_count_and_name_length_are_bounded() {
    use ferrum_edge::plugins::transaction_log_schema::{MAX_NAMED_SCHEMAS, MAX_SCHEMA_NAME_BYTES};

    let schemas = |count: usize| -> serde_json::Map<String, Value> {
        (0..count)
            .map(|index| (format!("schema_{index}"), json!({})))
            .collect()
    };
    let error = validate_plugin_config(
        "transaction_log_schema",
        &json!({ "schemas": schemas(MAX_NAMED_SCHEMAS + 1) }),
    )
    .unwrap_err();
    assert_contains(&error, "named schemas (maximum");
    validate_plugin_config(
        "transaction_log_schema",
        &json!({ "schemas": schemas(MAX_NAMED_SCHEMAS) }),
    )
    .expect("the maximum number of named schemas is admitted");

    let long_name = "n".repeat(MAX_SCHEMA_NAME_BYTES + 1);
    let error = validate_plugin_config(
        "transaction_log_schema",
        &json!({ "schemas": { (long_name): {} } }),
    )
    .unwrap_err();
    assert_contains(&error, "schema names must be at most");
    validate_plugin_config(
        "transaction_log_schema",
        &json!({ "schemas": { ("n".repeat(MAX_SCHEMA_NAME_BYTES)): {} } }),
    )
    .expect("a maximum-length name is admitted");
}

// ── Reload bracket unwind safety ────────────────────────────────────

#[test]
fn test_a_panicking_reload_does_not_wedge_the_registry() {
    let _g = registry_lock();
    registry::reset_for_tests();

    // A constructor panicking mid-reload used to skip commit/abort, leaving
    // this thread's bracket marked open (and the serializer held), so every
    // later reload on the thread failed as "nested".
    let outcome: std::thread::Result<()> = std::panic::catch_unwind(|| {
        let _bracket = registry::begin_reload_guarded().expect("bracket opens");
        TransactionLogSchema::new(&json!({ "schemas": { "staged": {} } }))
            .expect("definition stages");
        assert!(registry::lookup_named("staged").is_some());
        panic!("simulated plugin constructor panic during a reload");
    });
    assert!(outcome.is_err(), "the closure panicked");

    // The staged definition was discarded rather than promoted...
    assert!(registry::lookup_named("staged").is_none());
    // ...and a fresh reload opens, stages, and commits on the same thread.
    registry::begin_reload().expect("a later reload is not refused as nested");
    TransactionLogSchema::new(&json!({ "schemas": { "after": {} } })).expect("stages");
    registry::commit_reload().expect("commits");
    assert!(registry::lookup_named("after").is_some());

    // A guard whose bracket was closed normally is inert on drop.
    let bracket = registry::begin_reload_guarded().expect("bracket opens");
    TransactionLogSchema::new(&json!({ "schemas": { "committed": {} } })).expect("stages");
    registry::commit_reload().expect("commits");
    assert!(!bracket.is_open());
    drop(bracket);
    assert!(registry::lookup_named("committed").is_some());
}

// ── Value transforms ────────────────────────────────────────────────

const HASH_SECRET_ENV: &str = "FERRUM_PLUGIN_SECRET_LOG_SCHEMA_TEST_KEY";
const HASH_SECRET: &str = "0123456789abcdef0123456789abcdef-log-schema";

fn expected_hmac_hex(secret: &str, value: &str) -> String {
    let mut mac = ferrum_edge::fips::approved::HmacSha256::new_from_slice(secret.as_bytes())
        .expect("hmac key");
    mac.update(value.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

#[test]
fn test_truncate_transform_cuts_on_a_character_boundary() {
    let summary = TransactionSummary {
        request_path: "/caf\u{e9}/menu".into(),
        request_user_agent: Some("Mozilla/5.0 (X11; Linux x86_64)".into()),
        ..grpc_summary()
    };
    let projected = project(
        &summary,
        json!({
            "summary_type": "http",
            "transforms": {
                // "/caf" is 4 bytes and "é" spans bytes 4..6, so a 5-byte
                // cut must back off to the boundary at 4.
                "request_path": { "type": "truncate", "max_bytes": 5 },
                "request_user_agent": { "type": "truncate", "max_bytes": 7 }
            }
        }),
    );
    assert_eq!(text_at(&projected, "request_path"), Some("/caf"));
    assert_eq!(text_at(&projected, "request_user_agent"), Some("Mozilla"));
    // Shorter values pass through unchanged.
    let projected = project(
        &summary,
        json!({
            "summary_type": "http",
            "transforms": { "request_path": { "type": "truncate", "max_bytes": 4096 } }
        }),
    );
    assert_eq!(text_at(&projected, "request_path"), Some("/caf\u{e9}/menu"));
}

#[test]
fn test_ip_prefix_transform_zeroes_host_bits() {
    let with_ip = |ip: &str| TransactionSummary {
        client_ip: ip.into(),
        backend_resolved_ip: Some("192.0.2.200".into()),
        ..grpc_summary()
    };
    let schema = json!({
        "summary_type": "http",
        "rename": { "client_ip": "ip" },
        "transforms": {
            "client_ip": { "type": "ip_prefix", "ipv4_bits": 24, "ipv6_bits": 48 },
            "backend_resolved_ip": { "type": "ip_prefix" }
        }
    });
    let projected = project(&with_ip("203.0.113.77"), schema.clone());
    assert_eq!(text_at(&projected, "ip"), Some("203.0.113.0"));
    assert!(projected.get("client_ip").is_none(), "rename still applies");
    // Defaults are /24 and /48.
    assert_eq!(
        text_at(&projected, "backend_resolved_ip"),
        Some("192.0.2.0")
    );

    let projected = project(&with_ip("2001:db8:1234:5678::1"), schema.clone());
    assert_eq!(text_at(&projected, "ip"), Some("2001:db8:1234::"));

    // IPv4-mapped IPv6 is masked as IPv4.
    let projected = project(&with_ip("::ffff:198.51.100.9"), schema.clone());
    assert_eq!(text_at(&projected, "ip"), Some("198.51.100.0"));

    // A value that is not an address is never emitted raw.
    let projected = project(&with_ip("not-an-address"), schema);
    assert_eq!(projected.get("ip"), Some(&Value::Null));
    assert!(!projected.to_string().contains("not-an-address"));
}

#[test]
fn test_hash_transform_is_keyed_stable_and_never_raw() {
    crate::unit::env_lock::with_env_vars(&[(HASH_SECRET_ENV, HASH_SECRET)], || {
        let summary = TransactionSummary {
            consumer_username: Some("alice@example.com".into()),
            ..grpc_summary()
        };
        let schema = json!({
            "summary_type": "http",
            "transforms": {
                "consumer_username": {
                    "type": "hash",
                    "secret_ref": format!("${{{HASH_SECRET_ENV}}}")
                }
            }
        });
        let first = project(&summary, schema.clone());
        let second = project(&summary, schema.clone());
        let digest = text_at(&first, "consumer_username").expect("hashed value");
        assert_eq!(digest, expected_hmac_hex(HASH_SECRET, "alice@example.com"));
        assert_eq!(digest.len(), 64);
        assert_eq!(text_at(&second, "consumer_username"), Some(digest));
        assert!(!first.to_string().contains("alice"));

        // An absent value keeps native serialization (`null`), not a hash of
        // the empty string.
        let anonymous = TransactionSummary {
            consumer_username: None,
            ..grpc_summary()
        };
        let projected = project(&anonymous, schema.clone());
        assert_eq!(projected.get("consumer_username"), Some(&Value::Null));

        // The compiled schema never prints the key.
        let compiled = compile(schema).expect("schema compiles");
        let debug = format!("{compiled:?}");
        assert!(!debug.contains(HASH_SECRET), "{debug}");
    });
}

#[test]
fn test_hash_transform_requires_a_plugin_secret_reference() {
    let hash = |secret_ref: Value| json!({ "transforms": { "client_ip": { "type": "hash", "secret_ref": secret_ref } } });
    // Literal secrets are refused outright.
    let error = compile(hash(json!(HASH_SECRET))).unwrap_err();
    assert_contains(&error, "literal secrets are not accepted");
    assert!(!error.contains(HASH_SECRET), "{error}");
    // Only the plugin-secret namespace may be referenced.
    let error = compile(hash(json!("${FERRUM_ADMIN_JWT_SECRET}"))).unwrap_err();
    assert_contains(&error, "FERRUM_PLUGIN_SECRET_");
    // Missing `secret_ref`.
    assert_contains(
        &compile(json!({ "transforms": { "client_ip": { "type": "hash" } } })).unwrap_err(),
        "secret_ref",
    );
    // Unset and too-short values fail construction.
    crate::unit::env_lock::without_env_vars(&[HASH_SECRET_ENV], || {
        let error = compile(hash(json!(format!("${{{HASH_SECRET_ENV}}}")))).unwrap_err();
        assert_contains(&error, "is not set");
    });
    crate::unit::env_lock::with_env_vars(&[(HASH_SECRET_ENV, "too-short")], || {
        let error = compile(hash(json!(format!("${{{HASH_SECRET_ENV}}}")))).unwrap_err();
        assert_contains(&error, "shorter than 32 bytes");
        assert!(!error.contains("too-short"), "{error}");
    });
}

#[test]
fn test_transform_admission_is_fail_closed() {
    for (schema, needle) in [
        (
            json!({ "transforms": { "clientip": { "type": "truncate", "max_bytes": 4 } } }),
            "`transforms` references unknown field",
        ),
        (
            json!({ "transforms": { "http_method": { "type": "truncate", "max_bytes": 4 } } }),
            "cannot transform field",
        ),
        (
            json!({ "transforms": { "request_path": { "type": "ip_prefix" } } }),
            "applies only to IP address fields",
        ),
        (
            json!({
                "omit": ["client_ip"],
                "transforms": { "client_ip": { "type": "ip_prefix" } }
            }),
            "both omitted and transformed",
        ),
        (
            json!({ "transforms": { "client_ip": { "type": "mask" } } }),
            "must be `truncate`, `ip_prefix`, or `hash`",
        ),
        (
            json!({ "transforms": { "client_ip": { "max_bytes": 4 } } }),
            "missing `type`",
        ),
        (
            json!({ "transforms": { "client_ip": { "type": "truncate", "max_bytes": 4, "x": 1 } } }),
            "unknown schema key",
        ),
        (
            json!({ "transforms": { "client_ip": { "type": "truncate", "max_bytes": 0 } } }),
            "max_bytes must be an integer between 1 and",
        ),
        (
            json!({ "transforms": { "client_ip": { "type": "truncate", "max_bytes": 65537 } } }),
            "max_bytes must be an integer between 1 and",
        ),
        (
            json!({ "transforms": { "client_ip": { "type": "ip_prefix", "ipv4_bits": 33 } } }),
            "ipv4_bits must be an integer between 0 and 32",
        ),
        (
            json!({ "transforms": { "client_ip": { "type": "ip_prefix", "ipv6_bits": 129 } } }),
            "ipv6_bits must be an integer between 0 and 128",
        ),
        (
            json!({ "summary_type": "stream",
                    "transforms": { "request_path": { "type": "truncate", "max_bytes": 4 } } }),
            "`transforms` references unknown field",
        ),
        (
            json!({ "transforms": [] }),
            "`transforms` must be an object",
        ),
    ] {
        let error = match compile(schema.clone()) {
            Ok(_) => panic!("must reject {schema}"),
            Err(error) => error,
        };
        assert_contains(&error, needle);
    }

    // Families that cannot honor a transform reject the key.
    for caps in [
        SchemaCapabilities::API_CHARGEBACK,
        SchemaCapabilities::API_CHARGEBACK_SINK,
        SchemaCapabilities::TRANSACTION_DEBUGGER,
    ] {
        let error = SummarySchema::compile(
            &json!({ "transforms": { "proxy_id": { "type": "truncate", "max_bytes": 4 } } }),
            "test",
            caps,
        )
        .unwrap_err();
        assert_contains(&error, "`transforms` is not supported for this plugin");
    }

    // Named definitions admit transforms like inline schemas do.
    validate_plugin_config(
        "transaction_log_schema",
        &json!({ "schemas": { "minimized": {
            "transforms": {
                "client_ip": { "type": "ip_prefix" },
                "request_user_agent": { "type": "truncate", "max_bytes": 64 }
            }
        } } }),
    )
    .expect("named schema with transforms is admitted");
}
