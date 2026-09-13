//! Integration tests for the customizable transaction-log schema feature.
//!
//! Drift detection between the registry and the structs lives in
//! `log_schema_registry_tests.rs`. This file covers the cross-plugin /
//! cross-loader interactions:
//!
//! * `transaction_log_schema` + a logging plugin referencing it via
//!   `schema_ref:` resolves correctly through the named-schemas registry.
//! * The loader's `begin_reload` / `commit_reload` bracket actually
//!   publishes schemas so dependents can find them.
//! * `prometheus_metrics` still rejects `schema` / `schema_ref` (its label
//!   names are baked into the time-series store), while `api_chargeback`,
//!   `api_chargeback_sink`, and `transaction_debugger` project their own
//!   record families and fail closed on shapes those families cannot express.
//! * `transaction_log_schema` rejects non-global scopes via
//!   `GatewayConfig::validate_plugin_references`.

use chrono::Utc;
use ferrum_edge::config::types::{GatewayConfig, PluginConfig, PluginScope};
use ferrum_edge::plugins::create_plugin;
use ferrum_edge::plugins::utils::log_schema::registry;
use serde_json::{Value, json};
use std::time::Duration;

/// `Option<Arc<dyn Plugin>>` is not `Debug`, so `Result::expect_err` won't
/// compile against it. Wrap the bare `create_plugin` to discard the Ok
/// payload and return either the error string or a panic.
fn create_err(name: &str, config: Value) -> String {
    match create_plugin(name, &config) {
        Ok(_) => panic!("expected {name} construction to fail with config: {config}"),
        Err(e) => e,
    }
}

fn create_ok(name: &str, config: Value) {
    match create_plugin(name, &config) {
        Ok(Some(_)) => {}
        Ok(None) => panic!("{name} returned no plugin"),
        Err(e) => panic!("expected {name} to construct: {e}"),
    }
}

/// Tests that touch the process-global named-schemas registry hold the
/// reload-bracket serializer for their entire scope (writes AND
/// assertions). This protects against parallel sibling tests booting
/// gateways whose plugin-cache reloads would otherwise stomp the
/// registry's `schemas` map between commit and lookup. The serializer is
/// reentrant for this test guard plus one inner reload bracket.
fn registry_lock() -> registry::ReloadBracketTestGuard {
    registry::lock_for_tests()
}

fn graph_plugin(id: &str, namespace: &str, plugin_name: &str, config: Value) -> PluginConfig {
    PluginConfig {
        labels: Default::default(),
        id: id.to_string(),
        plugin_name: plugin_name.to_string(),
        namespace: namespace.to_string(),
        config,
        scope: PluginScope::Global,
        proxy_id: None,
        enabled: true,
        priority_override: None,
        trigger: None,
        api_spec_id: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

fn validate_graph(plugin_configs: Vec<PluginConfig>) -> Result<(), Vec<String>> {
    ferrum_edge::_test_support::validate_transaction_log_schema_graph_for_test(&GatewayConfig {
        plugin_configs,
        ..GatewayConfig::default()
    })
}

#[test]
fn prospective_graph_is_definition_first_and_does_not_mutate_live_registry() {
    let _g = registry_lock();
    registry::reset_for_tests();
    registry::begin_reload().expect("reload bracket opens");
    create_ok(
        "transaction_log_schema",
        json!({"schemas": {"live_baseline": {}}}),
    );
    registry::commit_reload().expect("reload bracket commits");

    validate_graph(vec![
        graph_plugin(
            "logger",
            "ferrum",
            "stdout_logging",
            json!({"schema_ref": "prospective"}),
        ),
        graph_plugin(
            "schemas",
            "ferrum",
            "transaction_log_schema",
            json!({"schemas": {"prospective": {"summary_type": "both"}}}),
        ),
    ])
    .expect("referrers may precede their definition in a prospective config");

    assert!(registry::lookup_named("live_baseline").is_some());
    assert!(
        registry::lookup_named("prospective").is_none(),
        "validation staging must never publish into the live registry"
    );
}

#[test]
fn nested_reload_is_rejected_without_clobbering_outer_staging() {
    let _g = registry_lock();
    registry::reset_for_tests();
    registry::begin_reload().expect("outer reload bracket opens");
    create_ok("transaction_log_schema", json!({"schemas": {"outer": {}}}));

    let error = registry::begin_reload().expect_err("nested reload must be rejected");
    assert!(error.contains("nested begin_reload"), "got: {error}");

    create_ok(
        "transaction_log_schema",
        json!({"schemas": {"after_rejection": {}}}),
    );
    registry::commit_reload().expect("outer reload bracket commits");
    assert!(registry::lookup_named("outer").is_some());
    assert!(registry::lookup_named("after_rejection").is_some());
}

#[tokio::test]
async fn namespace_config_admission_serializes_same_namespace_mutations() {
    let first = ferrum_edge::_test_support::lock_namespace_config_admission_for_test(
        "schema-lock-serialization",
    )
    .await;
    let (attempting_tx, attempting_rx) = tokio::sync::oneshot::channel();
    let mut waiter = tokio::spawn(async move {
        let _ = attempting_tx.send(());
        let _second = ferrum_edge::_test_support::lock_namespace_config_admission_for_test(
            "schema-lock-serialization",
        )
        .await;
    });

    attempting_rx
        .await
        .expect("waiter reaches lock acquisition");
    assert!(
        tokio::time::timeout(Duration::from_millis(50), &mut waiter)
            .await
            .is_err(),
        "same-namespace mutation must wait while admission through persistence is guarded"
    );

    drop(first);
    tokio::time::timeout(Duration::from_secs(1), waiter)
        .await
        .expect("waiter acquires promptly after release")
        .expect("waiter task completes");
}

#[test]
fn prospective_graph_rejects_duplicate_names_and_dangling_renames_or_deletes() {
    let duplicate = validate_graph(vec![
        graph_plugin(
            "schemas-a",
            "ferrum",
            "transaction_log_schema",
            json!({"schemas": {"audit": {}}}),
        ),
        graph_plugin(
            "schemas-b",
            "ferrum",
            "transaction_log_schema",
            json!({"schemas": {"audit": {}}}),
        ),
    ])
    .expect_err("duplicate names across schema instances must be rejected");
    assert!(
        duplicate
            .iter()
            .any(|error| error.contains("registered more than once")),
        "unexpected duplicate errors: {duplicate:?}"
    );

    for plugins in [
        vec![
            graph_plugin(
                "schemas",
                "ferrum",
                "transaction_log_schema",
                json!({"schemas": {"renamed": {}}}),
            ),
            graph_plugin(
                "logger",
                "ferrum",
                "stdout_logging",
                json!({"schema_ref": "removed"}),
            ),
        ],
        vec![graph_plugin(
            "logger",
            "ferrum",
            "stdout_logging",
            json!({"schema_ref": "deleted"}),
        )],
    ] {
        let errors = validate_graph(plugins)
            .expect_err("renamed or deleted definitions must leave no dangling referrers");
        assert!(
            errors.iter().any(|error| error.contains("unknown schema")),
            "unexpected dangling-ref errors: {errors:?}"
        );
    }
}

#[test]
fn stray_schema_ref_participates_only_when_the_plugin_is_enabled() {
    let mut plugin = graph_plugin(
        "stray-ref",
        "ferrum",
        "cors",
        json!({"origins": ["*"], "schema_ref": "missing"}),
    );
    plugin.enabled = false;
    validate_graph(vec![plugin.clone()]).expect("disabled config is inert");

    plugin.enabled = true;
    let errors = validate_graph(vec![plugin])
        .expect_err("enabled top-level schema_ref must participate fail-closed");
    assert!(
        errors
            .iter()
            .any(|error| error.contains("unknown schema 'missing'")),
        "unexpected errors: {errors:?}"
    );
}

#[test]
fn prospective_graph_is_namespace_scoped_across_multiple_instances() {
    validate_graph(vec![
        graph_plugin(
            "schemas-a",
            "tenant-a",
            "transaction_log_schema",
            json!({"schemas": {"audit": {}}}),
        ),
        graph_plugin(
            "logger-a",
            "tenant-a",
            "stdout_logging",
            json!({"schema_ref": "audit"}),
        ),
        graph_plugin(
            "schemas-b",
            "tenant-b",
            "transaction_log_schema",
            json!({"schemas": {"audit": {}}}),
        ),
        graph_plugin(
            "logger-b",
            "tenant-b",
            "stdout_logging",
            json!({"schema_ref": "audit"}),
        ),
    ])
    .expect("the same schema name is independent in separate namespaces");

    let errors = validate_graph(vec![
        graph_plugin(
            "schemas-a",
            "tenant-a",
            "transaction_log_schema",
            json!({"schemas": {"audit": {}}}),
        ),
        graph_plugin(
            "logger-b",
            "tenant-b",
            "stdout_logging",
            json!({"schema_ref": "audit"}),
        ),
    ])
    .expect_err("a referrer must not resolve a definition from another namespace");
    assert!(
        errors
            .iter()
            .any(|error| error.contains("namespace=tenant-b") && error.contains("unknown schema")),
        "unexpected cross-namespace errors: {errors:?}"
    );
}

#[test]
fn runtime_load_preserves_optional_logger_fail_open_but_not_dangling_refs() {
    let _g = registry_lock();
    registry::reset_for_tests();
    let policy = ferrum_edge::config::BackendEgressPolicy::unrestricted();

    let mut malformed_optional_sink = GatewayConfig {
        plugin_configs: vec![
            graph_plugin(
                "schemas",
                "ferrum",
                "transaction_log_schema",
                json!({"schemas": {"audit": {}}}),
            ),
            graph_plugin(
                "logger",
                "ferrum",
                "stdout_logging",
                json!({"schema_ref": "audit", "filter": "not-an-object"}),
            ),
        ],
        ..GatewayConfig::default()
    };
    ferrum_edge::_test_support::validate_plugin_configs_fatal_for_test(
        &mut malformed_optional_sink,
        &policy,
    )
    .expect("optional logger constructor failures remain fail-open on runtime load");

    let mut dangling_ref = GatewayConfig {
        plugin_configs: vec![graph_plugin(
            "logger",
            "ferrum",
            "stdout_logging",
            json!({"schema_ref": "missing"}),
        )],
        ..GatewayConfig::default()
    };
    let error = ferrum_edge::_test_support::validate_plugin_configs_fatal_for_test(
        &mut dangling_ref,
        &policy,
    )
    .expect_err("reference-integrity failures remain fatal");
    assert!(error.contains("1 errors"), "unexpected error: {error}");
}

#[test]
fn shared_runtime_rejecting_contract_rejects_dangling_graphs_only() {
    let _g = registry_lock();
    registry::reset_for_tests();

    let dangling_ref = GatewayConfig {
        plugin_configs: vec![graph_plugin(
            "logger",
            "ferrum",
            "stdout_logging",
            json!({"schema_ref": "missing"}),
        )],
        ..GatewayConfig::default()
    };
    let errors =
        ferrum_edge::_test_support::collect_rejecting_runtime_config_errors_for_test(&dangling_ref);
    assert!(
        errors
            .iter()
            .any(|error| error.contains("unknown schema 'missing'")),
        "database, MongoDB, and CP snapshots must reject dangling graph refs: {errors:?}"
    );

    let malformed_optional_sink = GatewayConfig {
        plugin_configs: vec![
            graph_plugin(
                "schemas",
                "ferrum",
                "transaction_log_schema",
                json!({"schemas": {"audit": {}}}),
            ),
            graph_plugin(
                "logger",
                "ferrum",
                "stdout_logging",
                json!({"schema_ref": "audit", "filter": "not-an-object"}),
            ),
        ],
        ..GatewayConfig::default()
    };
    let errors = ferrum_edge::_test_support::collect_rejecting_runtime_config_errors_for_test(
        &malformed_optional_sink,
    );
    assert!(
        errors.is_empty(),
        "optional sink constructor failures must remain outside the rejecting graph contract: {errors:?}"
    );
}

#[test]
fn schema_ref_opt_in_cannot_bypass_policy_only_egress_validation() {
    let _g = registry_lock();
    registry::reset_for_tests();
    let policy = ferrum_edge::config::BackendEgressPolicy::from_env(
        ferrum_edge::config::BackendAllowIps::Both,
        "",
        "",
        true,
    )
    .expect("default egress policy is valid");
    let mut config = GatewayConfig {
        plugin_configs: vec![
            graph_plugin(
                "schemas",
                "ferrum",
                "transaction_log_schema",
                json!({"schemas": {"audit": {}}}),
            ),
            graph_plugin(
                "rate-limit",
                "ferrum",
                "rate_limiting",
                json!({
                    "window_seconds": 60,
                    "max_requests": 10,
                    "sync_mode": "redis",
                    "redis_url": "redis://169.254.169.254:6379/0",
                    "schema_ref": "audit"
                }),
            ),
        ],
        ..GatewayConfig::default()
    };

    let errors =
        ferrum_edge::_test_support::collect_plugin_config_errors_for_test(&mut config, &policy)
            .expect("collect validation should return policy errors");
    assert!(
        errors
            .iter()
            .any(|error| error.contains("redis_url IP 169.254.169.254 denied")),
        "schema_ref must not bypass policy-only checks: {errors:?}"
    );
}

#[test]
fn schema_ref_resolves_when_schema_registered_first() {
    let _g = registry_lock();
    registry::reset_for_tests();

    // Loader runs `begin_reload`, processes transaction_log_schema first,
    // then `commit_reload`, then the rest.
    registry::begin_reload().expect("reload bracket opens");
    create_ok(
        "transaction_log_schema",
        json!({
            "schemas": {
                "splunk_cim": {
                    "summary_type": "both",
                    "rename": { "proxy_id": "route_id" }
                }
            }
        }),
    );
    registry::commit_reload().expect("reload bracket commits");

    create_ok("stdout_logging", json!({ "schema_ref": "splunk_cim" }));
}

#[test]
fn schema_ref_unknown_rejected_after_commit() {
    let _g = registry_lock();
    registry::reset_for_tests();
    registry::begin_reload().expect("reload bracket opens");
    registry::commit_reload().expect("empty reload bracket commits");

    let err = create_err("stdout_logging", json!({ "schema_ref": "missing" }));
    assert!(err.contains("unknown schema 'missing'"), "got: {err}");
}

#[test]
fn inline_and_schema_ref_mutually_exclusive() {
    let _g = registry_lock();
    registry::reset_for_tests();
    registry::begin_reload().expect("reload bracket opens");
    create_ok("transaction_log_schema", json!({ "schemas": { "x": {} } }));
    registry::commit_reload().expect("reload bracket commits");

    let err = create_err(
        "stdout_logging",
        json!({
            "schema": { "summary_type": "http" },
            "schema_ref": "x"
        }),
    );
    assert!(err.contains("mutually exclusive"), "got: {err}");
}

#[test]
fn transaction_debugger_accepts_inline_schema() {
    create_ok(
        "transaction_debugger",
        json!({
            "schema": {
                "summary_type": "http",
                "rename": { "proxy_id": "route_id" },
                "omit": ["latency_gw_overhead_ms"],
                "static_fields": { "env": "prod" },
                "derived_fields": [{ "name": "status_group", "kind": "status_class" }],
                "metadata": { "mode": "flatten", "prefix": "meta_" },
                "timestamp_format": "epoch_ms"
            }
        }),
    );
}

#[test]
fn transaction_debugger_schema_rejects_unknown_field_with_diagnostic() {
    // The diagnostic inventory is the plugin's own: a transaction-summary-only
    // name is unknown here and must fail closed rather than be ignored.
    let err = create_err(
        "transaction_debugger",
        json!({ "schema": { "summary_type": "http", "omit": ["request_user_agent"] } }),
    );
    assert!(
        err.contains(
            "transaction_debugger: schema omit references unknown field 'request_user_agent'"
        ),
        "got: {err}"
    );
}

#[test]
fn transaction_debugger_rejects_dangling_schema_ref() {
    let _g = registry_lock();
    registry::reset_for_tests();
    let err = create_err(
        "transaction_debugger",
        json!({ "schema_ref": "definitely-not-defined" }),
    );
    assert!(
        err.contains("references unknown schema 'definitely-not-defined'"),
        "got: {err}"
    );
}

#[test]
fn prometheus_metrics_rejects_schema() {
    let err = create_err(
        "prometheus_metrics",
        json!({ "schema": { "summary_type": "http" } }),
    );
    assert!(err.contains("not supported"), "got: {err}");
}

#[test]
fn api_chargeback_accepts_inline_schema() {
    create_ok(
        "api_chargeback",
        json!({
            "bandwidth_pricing": { "price_per_byte_sent": 0.000001 },
            "schema": {
                "rename": { "proxy_id": "route_id" },
                "omit": ["by_status"],
                "static_fields": { "ledger": "prod" },
                "derived_fields": [{ "name": "record_kind", "kind": "summary_kind" }]
            }
        }),
    );
}

#[test]
fn api_chargeback_schema_rejects_summary_type_metadata_and_order() {
    // A billing row is neither an HTTP nor a stream summary, carries no
    // metadata map, and is emitted as a member of a sorted JSON document.
    // Each unsupported shape fails closed with its own diagnostic.
    for (schema, needle) in [
        (
            json!({ "summary_type": "http" }),
            "'summary_type' is not supported",
        ),
        (
            json!({ "metadata": { "mode": "omit" } }),
            "'metadata' policy is not supported",
        ),
        (
            json!({ "order": ["proxy_id", "*"] }),
            "'order' is not supported",
        ),
        (
            json!({ "derived_fields": [{ "name": "host", "kind": "backend_host" }] }),
            "not representable from a chargeback billing row",
        ),
    ] {
        let err = create_err(
            "api_chargeback",
            json!({
                "bandwidth_pricing": { "price_per_byte_sent": 0.000001 },
                "schema": schema
            }),
        );
        assert!(err.contains(needle), "needle={needle}, got: {err}");
    }
}

#[test]
fn schema_loaded_after_commit_visible_to_subsequent_constructions() {
    let _g = registry_lock();
    registry::reset_for_tests();
    registry::begin_reload().expect("reload bracket opens");
    create_ok(
        "transaction_log_schema",
        json!({
            "schemas": {
                "a": { "summary_type": "http" },
                "b": { "summary_type": "stream" }
            }
        }),
    );
    registry::commit_reload().expect("reload bracket commits");

    // Both schemas should be resolvable.
    create_ok("stdout_logging", json!({ "schema_ref": "a" }));
    create_ok("stdout_logging", json!({ "schema_ref": "b" }));
}

#[test]
fn reload_replaces_previous_schemas() {
    let _g = registry_lock();
    registry::reset_for_tests();

    // First reload: schemas "a" and "b".
    registry::begin_reload().expect("reload bracket opens");
    create_ok(
        "transaction_log_schema",
        json!({
            "schemas": {
                "a": { "summary_type": "http" },
                "b": { "summary_type": "stream" }
            }
        }),
    );
    registry::commit_reload().expect("reload bracket commits");
    assert!(registry::lookup_named("a").is_some());
    assert!(registry::lookup_named("b").is_some());

    // Second reload: only schema "a" plus a new "c". "b" should vanish.
    registry::begin_reload().expect("reload bracket opens");
    create_ok(
        "transaction_log_schema",
        json!({
            "schemas": {
                "a": { "summary_type": "http" },
                "c": { "summary_type": "both" }
            }
        }),
    );
    registry::commit_reload().expect("reload bracket commits");
    assert!(registry::lookup_named("a").is_some(), "a survived");
    assert!(registry::lookup_named("b").is_none(), "b removed");
    assert!(registry::lookup_named("c").is_some(), "c added");
}

#[test]
fn schema_ref_succeeds_with_inline_validation_path() {
    // Even outside a reload bracket (validation-mode register_named is a
    // no-op), inline schemas still compile and apply. Verifies that
    // validation doesn't require the registry to be populated.
    let _g = registry_lock();
    registry::reset_for_tests();
    create_ok(
        "stdout_logging",
        json!({
            "schema": {
                "summary_type": "http",
                "rename": { "proxy_id": "route_id" }
            }
        }),
    );
}

#[tokio::test]
async fn ws_logging_accepts_schema() {
    let _g = registry_lock();
    registry::reset_for_tests();
    create_ok(
        "ws_logging",
        json!({
            "endpoint_url": "ws://logs.example.com/ingest",
            "schema": { "summary_type": "http", "omit": ["request_user_agent"] }
        }),
    );
}

#[tokio::test]
async fn statsd_logging_accepts_schema_with_tag_rename() {
    let _g = registry_lock();
    registry::reset_for_tests();
    create_ok(
        "statsd_logging",
        json!({
            "host": "127.0.0.1",
            "port": 8125,
            "schema": {
                "summary_type": "http",
                "rename": { "proxy_id": "route_id", "http_method": "verb" }
            }
        }),
    );
}

#[tokio::test]
async fn loki_logging_accepts_schema() {
    let _g = registry_lock();
    registry::reset_for_tests();
    create_ok(
        "loki_logging",
        json!({
            "endpoint_url": "http://loki.example.com:3100/loki/api/v1/push",
            "schema": {
                "summary_type": "both",
                "metadata": { "mode": "flatten", "prefix": "meta_" }
            }
        }),
    );
}

#[test]
fn static_fields_literal_bearer_token_rejected_via_create_plugin() {
    // End-to-end: the bearer-detection guard fires through the full
    // create_plugin construction path, not just SummarySchema::compile.
    let _g = registry_lock();
    registry::reset_for_tests();
    let err = create_err(
        "stdout_logging",
        json!({
            "schema": {
                "static_fields": { "audit_note": "Bearer leaked.jwt.token" }
            }
        }),
    );
    assert!(
        err.contains("looks like an HTTP Bearer credential"),
        "got: {err}"
    );
}

#[test]
fn static_fields_aws_sigv4_value_rejected_via_create_plugin() {
    let _g = registry_lock();
    registry::reset_for_tests();
    let err = create_err(
        "stdout_logging",
        json!({
            "schema": {
                "static_fields": {
                    "operator_note": "AWS4-HMAC-SHA256 Credential=AKIA.../...,SignedHeaders=...,Signature=..."
                }
            }
        }),
    );
    assert!(err.contains("AWS4-HMAC-SHA256"), "got: {err}");
}

#[test]
fn failed_cache_build_does_not_leak_registry_changes() {
    // Atomicity guarantee: when PluginCache::new rejects a config because
    // a downstream plugin fails to construct, the named-schema registry
    // must still reflect the LAST successfully-applied config — not the
    // staging that was being built for the rejected reload.
    use chrono::Utc;
    use ferrum_edge::config::types::{GatewayConfig, PluginConfig, PluginScope};
    use ferrum_edge::plugin_cache::PluginCache;

    fn schema_plugin(id: &str, schema_name: &str) -> PluginConfig {
        PluginConfig {
            labels: Default::default(),
            id: id.into(),
            plugin_name: "transaction_log_schema".into(),
            namespace: "ferrum".into(),
            config: json!({
                "schemas": { schema_name: { "summary_type": "http" } }
            }),
            scope: PluginScope::Global,
            proxy_id: None,
            enabled: true,
            priority_override: None,
            trigger: None,
            api_spec_id: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    fn broken_keyauth() -> PluginConfig {
        PluginConfig {
            labels: Default::default(),
            id: "broken-keyauth".into(),
            plugin_name: "key_auth".into(),
            namespace: "ferrum".into(),
            // Empty key_location triggers "must not be empty" from
            // KeyAuth::new() — security_errors path in build_cache.
            config: json!({ "key_location": "" }),
            scope: PluginScope::Global,
            proxy_id: None,
            enabled: true,
            priority_override: None,
            trigger: None,
            api_spec_id: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    let _g = registry_lock();
    registry::reset_for_tests();

    // 1. Seed a successful baseline registry containing schema "baseline".
    let baseline_cfg = GatewayConfig {
        plugin_configs: vec![schema_plugin("tls-baseline", "baseline")],
        ..GatewayConfig::default()
    };
    PluginCache::new(&baseline_cfg).expect("baseline build succeeds");
    assert!(
        registry::lookup_named("baseline").is_some(),
        "baseline schema is live after first build"
    );

    // 2. Attempt a second build that defines schema "rejected" alongside
    //    an invalid plugin, so the build fails at security validation.
    let bad_cfg = GatewayConfig {
        plugin_configs: vec![schema_plugin("tls-rejected", "rejected"), broken_keyauth()],
        ..GatewayConfig::default()
    };
    let result = PluginCache::new(&bad_cfg);
    assert!(result.is_err(), "build must fail when a plugin is invalid");

    // 3. Atomicity: registry matches the BASELINE, not the rejected reload.
    assert!(
        registry::lookup_named("baseline").is_some(),
        "baseline schema survives a rejected reload (pre-fix this was wiped)"
    );
    assert!(
        registry::lookup_named("rejected").is_none(),
        "rejected reload's staged schema must NOT leak into the live registry"
    );
}

#[test]
fn non_summary_families_resolve_schema_ref_and_survive_reload() {
    let _g = registry_lock();
    registry::reset_for_tests();
    registry::begin_reload().expect("reload bracket opens");
    create_ok(
        "transaction_log_schema",
        json!({
            "schemas": {
                "portable": { "rename": { "proxy_id": "route_id" } }
            }
        }),
    );
    registry::commit_reload().expect("reload bracket commits");

    // Both non-summary families recompile the named definition under their own
    // record family — the shared `proxy_id` name resolves in each.
    create_ok("transaction_debugger", json!({ "schema_ref": "portable" }));
    create_ok(
        "api_chargeback",
        json!({
            "bandwidth_pricing": { "price_per_byte_sent": 0.000001 },
            "schema_ref": "portable"
        }),
    );

    // A reload that drops the definition leaves the referrers dangling, and
    // they fail closed on the next construction.
    registry::begin_reload().expect("second reload bracket opens");
    create_ok(
        "transaction_log_schema",
        json!({ "schemas": { "other": {} } }),
    );
    registry::commit_reload().expect("second reload bracket commits");

    for (plugin, config) in [
        ("transaction_debugger", json!({ "schema_ref": "portable" })),
        (
            "api_chargeback",
            json!({
                "bandwidth_pricing": { "price_per_byte_sent": 0.000001 },
                "schema_ref": "portable"
            }),
        ),
    ] {
        let err = create_err(plugin, config);
        assert!(
            err.contains("references unknown schema 'portable'"),
            "{plugin}: {err}"
        );
    }
}

#[test]
fn non_summary_families_reject_a_named_schema_they_cannot_represent() {
    // A portable definition is authored against the transaction-summary
    // registry. Recompiling it under another family fails closed on any name
    // that family does not have, rather than silently dropping the field.
    let _g = registry_lock();
    registry::reset_for_tests();
    registry::begin_reload().expect("reload bracket opens");
    create_ok(
        "transaction_log_schema",
        json!({
            "schemas": {
                "summary_only": { "omit": ["request_user_agent"] }
            }
        }),
    );
    registry::commit_reload().expect("reload bracket commits");

    let err = create_err(
        "transaction_debugger",
        json!({ "schema_ref": "summary_only" }),
    );
    assert!(
        err.contains("schema omit references unknown field 'request_user_agent'"),
        "got: {err}"
    );
}

#[test]
fn non_summary_families_participate_in_the_prospective_graph() {
    let _g = registry_lock();
    registry::reset_for_tests();
    registry::begin_reload().expect("reload bracket opens");
    registry::commit_reload().expect("reload bracket commits");

    validate_graph(vec![
        graph_plugin(
            "debugger",
            "ferrum",
            "transaction_debugger",
            json!({"schema_ref": "prospective"}),
        ),
        graph_plugin(
            "schemas",
            "ferrum",
            "transaction_log_schema",
            json!({"schemas": {"prospective": {}}}),
        ),
    ])
    .expect("a debugger referrer resolves against a prospective definition");

    let errors = validate_graph(vec![graph_plugin(
        "debugger",
        "ferrum",
        "transaction_debugger",
        json!({"schema_ref": "missing"}),
    )])
    .expect_err("a dangling debugger reference is graph-fatal");
    assert!(
        errors.iter().any(|error| error.contains("missing")),
        "{errors:?}"
    );
}

/// Minimal `api_chargeback_sink` config the constructor admits: spool disabled
/// so no on-disk tree is created, one pricing dimension, and a hostname
/// ClickHouse endpoint that the literal-IP egress screen leaves alone.
fn sink_config(extra: Value) -> Value {
    let mut config = json!({
        "mode": "per_event",
        "clickhouse": { "url": "https://clickhouse.example:8443" },
        "spool": { "enabled": false },
        "pricing_tiers": [{ "status_codes": [200], "price_per_call": 0.01 }],
        "pricing_version": "test-v1",
        "currency": "USD"
    });
    if let Some(object) = extra.as_object() {
        for (key, value) in object {
            config[key.as_str()] = value.clone();
        }
    }
    config
}

/// The charge-event family is the only one whose projected keys are remote
/// ClickHouse column names, so its `schema_ref` lifecycle is asserted end to
/// end: a shared definition recompiles under the family, a definition whose
/// rename target collides with a real charge-event column is rejected instead
/// of quietly redirecting a value into another column, and a reload that drops
/// the definition leaves the referrer failing closed.
///
/// `summary_only_target` is the collision case: `route_id` is not a
/// transaction-summary field, so the definition is perfectly valid where it is
/// authored, but it IS a `ChargeEvent` member (and a ClickHouse column).
#[test]
fn charge_event_family_resolves_schema_ref_and_rejects_a_colliding_definition() {
    let _g = registry_lock();
    registry::reset_for_tests();
    registry::begin_reload().expect("reload bracket opens");
    create_ok(
        "transaction_log_schema",
        json!({
            "schemas": {
                "sink_portable": { "rename": { "proxy_id": "gateway_route" } },
                "summary_only_target": { "rename": { "proxy_id": "route_id" } }
            }
        }),
    );
    registry::commit_reload().expect("reload bracket commits");

    create_ok(
        "api_chargeback_sink",
        sink_config(json!({ "schema_ref": "sink_portable" })),
    );

    let err = create_err(
        "api_chargeback_sink",
        sink_config(json!({ "schema_ref": "summary_only_target" })),
    );
    assert!(
        err.contains("duplicate output key 'route_id' produced by native and native"),
        "got: {err}"
    );

    registry::begin_reload().expect("second reload bracket opens");
    create_ok(
        "transaction_log_schema",
        json!({ "schemas": { "other": {} } }),
    );
    registry::commit_reload().expect("second reload bracket commits");

    let err = create_err(
        "api_chargeback_sink",
        sink_config(json!({ "schema_ref": "sink_portable" })),
    );
    assert!(
        err.contains("references unknown schema 'sink_portable'"),
        "got: {err}"
    );
}
