use chrono::Utc;
use ferrum_edge::config::db_backend::FullConfigLoadPurpose;
use ferrum_edge::config::types::{
    Consumer, GatewayConfig, PluginConfig, PluginScope, anchor_regex_pattern, hosts_overlap,
    redact_consumer_credentials, validate_host_entry,
};
use serde_json::json;
use std::collections::HashMap;

// ---------------------------------------------------------------------------
// Helper
// ---------------------------------------------------------------------------

fn make_consumer(id: &str, username: &str) -> Consumer {
    Consumer {
        id: id.into(),
        namespace: ferrum_edge::config::types::default_namespace(),
        username: username.into(),
        custom_id: None,
        credentials: HashMap::new(),
        acl_groups: Vec::new(),
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

// ===========================================================================
// validate_host_entry — additional coverage
// ===========================================================================

#[test]
fn test_validate_host_entry_whitespace_only_rejected() {
    let err = validate_host_entry("   ").unwrap_err();
    assert!(
        err.contains("whitespace"),
        "whitespace-only host should be rejected: {err}"
    );
}

#[test]
fn test_validate_host_entry_ipv4_address() {
    // The HOST_REGEX allows digits and dots, so a valid IPv4 like 127.0.0.1
    // passes the regex (it looks syntactically like a hostname with numeric
    // labels). This test documents the current behaviour.
    assert!(
        validate_host_entry("127.0.0.1").is_ok(),
        "numeric IPv4-like hostname is accepted by the current regex"
    );
}

#[test]
fn test_validate_host_entry_ipv6_rejected() {
    // IPv6 literal contains colons — rejected by the "must not contain a port"
    // check (or by the host regex if bare).
    assert!(
        validate_host_entry("::1").is_err(),
        "IPv6 literal should be rejected"
    );
}

#[test]
fn test_validate_host_entry_double_dots_rejected() {
    let err = validate_host_entry("example..com").unwrap_err();
    assert!(
        err.contains("empty labels"),
        "double-dot hostname should be rejected: {err}"
    );
}

#[test]
fn test_validate_host_entry_trailing_dot_rejected() {
    // DNS FQDNs end with a dot, but the HOST_REGEX requires the last char to
    // be alphanumeric, so trailing dots are rejected.
    let err = validate_host_entry("example.com.").unwrap_err();
    assert!(
        err.contains("invalid"),
        "trailing-dot hostname should be rejected: {err}"
    );
}

#[test]
fn test_validate_host_entry_very_long_hostname_rejected() {
    let long = format!("{}.example.com", "a".repeat(240));
    let err = validate_host_entry(&long).unwrap_err();
    assert!(err.contains("label longer than 63"), "got {err}");
}

#[test]
fn test_validate_host_entry_single_label() {
    assert!(
        validate_host_entry("localhost").is_ok(),
        "single-label hostname should pass"
    );
    assert!(
        validate_host_entry("a").is_ok(),
        "single-char hostname should pass"
    );
}

#[test]
fn test_validate_host_entry_leading_hyphen_rejected() {
    let err = validate_host_entry("-example.com").unwrap_err();
    assert!(
        err.contains("invalid"),
        "leading-hyphen hostname should be rejected: {err}"
    );
}

#[test]
fn test_validate_host_entry_label_trailing_hyphen_rejected() {
    let err = validate_host_entry("example-.com").unwrap_err();
    assert!(
        err.contains("start and end"),
        "label ending in hyphen should be rejected: {err}"
    );
}

#[test]
fn test_validate_host_entry_underscore_rejected() {
    let err = validate_host_entry("my_host.example.com").unwrap_err();
    assert!(
        err.contains("invalid"),
        "underscore in hostname should be rejected: {err}"
    );
}

#[test]
fn test_validate_host_entry_space_rejected() {
    let err = validate_host_entry("my host.com").unwrap_err();
    assert!(
        err.contains("invalid"),
        "space in hostname should be rejected: {err}"
    );
}

#[test]
fn test_validate_host_entry_wildcard_bare_star_rejected() {
    let err = validate_host_entry("*").unwrap_err();
    assert!(
        err.contains("wildcard"),
        "bare '*' should be rejected: {err}"
    );
}

#[test]
fn test_validate_host_entry_wildcard_mid_position_rejected() {
    let err = validate_host_entry("api.*.com").unwrap_err();
    assert!(
        err.contains("wildcard"),
        "mid-position wildcard should be rejected: {err}"
    );
}

#[test]
fn test_validate_host_entry_wildcard_without_dot_rejected() {
    let err = validate_host_entry("*example.com").unwrap_err();
    assert!(
        err.contains("wildcard"),
        "'*example.com' (no dot after star) should be rejected: {err}"
    );
}

#[test]
fn test_validate_host_entry_scheme_https_rejected() {
    let err = validate_host_entry("https://example.com").unwrap_err();
    assert!(
        err.contains("scheme"),
        "HTTPS scheme should be rejected: {err}"
    );
}

// ===========================================================================
// hosts_overlap — additional coverage
// ===========================================================================

#[test]
fn test_hosts_overlap_case_sensitivity() {
    // The function operates on raw strings. Hosts are normalised (lowercased)
    // before reaching this function in production, so exact-case comparison
    // is correct. Verify that mixed-case entries do NOT overlap by default.
    let a = vec!["API.example.com".to_string()];
    let b = vec!["api.example.com".to_string()];
    assert!(
        !hosts_overlap(&a, &b),
        "hosts_overlap is case-sensitive; mixed case should NOT overlap"
    );
}

#[test]
fn test_hosts_overlap_wildcard_vs_wildcard_same_domain() {
    let a = vec!["*.example.com".to_string()];
    let b = vec!["*.example.com".to_string()];
    assert!(
        hosts_overlap(&a, &b),
        "identical wildcard hosts should overlap"
    );
}

#[test]
fn test_hosts_overlap_wildcard_vs_wildcard_different_domain() {
    let a = vec!["*.example.com".to_string()];
    let b = vec!["*.other.org".to_string()];
    assert!(
        !hosts_overlap(&a, &b),
        "wildcards on different domains should not overlap"
    );
}

#[test]
fn test_hosts_overlap_multiple_hosts_partial_overlap() {
    let a = vec!["x.example.com".to_string(), "y.example.com".to_string()];
    let b = vec!["y.example.com".to_string(), "z.example.com".to_string()];
    assert!(
        hosts_overlap(&a, &b),
        "partial overlap (y.example.com) should be detected"
    );
}

#[test]
fn test_hosts_overlap_wildcard_does_not_match_base_domain() {
    let a = vec!["*.example.com".to_string()];
    let b = vec!["example.com".to_string()];
    assert!(
        !hosts_overlap(&a, &b),
        "*.example.com should NOT match the bare base domain"
    );
}

#[test]
fn test_hosts_overlap_wildcard_matches_multi_level() {
    let a = vec!["*.example.com".to_string()];
    let b = vec!["a.b.example.com".to_string()];
    assert!(
        hosts_overlap(&a, &b),
        "*.example.com should match multi-level subdomains"
    );
}

// ===========================================================================
// anchor_regex_pattern — additional coverage
// ===========================================================================

#[test]
fn test_anchor_regex_pattern_empty_string() {
    assert_eq!(anchor_regex_pattern(""), "^(?:)$");
}

#[test]
fn test_anchor_regex_pattern_special_regex_chars() {
    // Pattern with groups, quantifiers, alternation should be grouped, not altered.
    assert_eq!(
        anchor_regex_pattern("/api/(v1|v2)/users"),
        "^(?:/api/(v1|v2)/users)$"
    );
}

#[test]
fn test_anchor_regex_pattern_dot_star_at_end() {
    // Operators use .* to opt out of strict end-anchoring
    assert_eq!(anchor_regex_pattern("/api/.*"), "^(?:/api/.*)$");
}

#[test]
fn test_anchor_regex_pattern_only_caret() {
    // Pattern that starts with ^ but doesn't end with $
    assert_eq!(anchor_regex_pattern("^/foo"), "^(?:/foo)$");
}

#[test]
fn test_anchor_regex_pattern_only_dollar() {
    // Pattern that ends with $ but doesn't start with ^
    assert_eq!(anchor_regex_pattern("/foo$"), "^(?:/foo)$");
}

#[test]
fn test_anchor_regex_pattern_dollar_inside_not_at_end() {
    // A $ in a character class is NOT an end anchor
    assert_eq!(anchor_regex_pattern("/price/[$]"), "^(?:/price/[$])$");
}

#[test]
fn test_anchor_regex_pattern_caret_inside_not_at_start() {
    // A ^ that isn't the first character is NOT a start anchor
    assert_eq!(anchor_regex_pattern("/path/[^a]"), "^(?:/path/[^a])$");
}

// ===========================================================================
// redact_consumer_credentials
// ===========================================================================

#[test]
fn test_redact_consumer_no_credentials() {
    let consumer = make_consumer("c1", "alice");
    let redacted = redact_consumer_credentials(&consumer);
    assert!(redacted.credentials.is_empty());
    assert_eq!(redacted.username, "alice");
}

#[test]
fn test_redact_consumer_keyauth_key_redacted() {
    let mut consumer = make_consumer("c1", "alice");
    consumer.credentials.insert(
        "keyauth".into(),
        serde_json::json!([{"key": "my-api-key-123"}]),
    );
    let redacted = redact_consumer_credentials(&consumer);
    let keyauth = redacted.credentials.get("keyauth").unwrap();
    assert_eq!(keyauth[0]["key"].as_str().unwrap(), "[REDACTED]");
}

#[test]
fn test_redact_consumer_basicauth_password_hash_omitted() {
    let mut consumer = make_consumer("c1", "alice");
    consumer.credentials.insert(
        "basicauth".into(),
        serde_json::json!([{"password_hash": "hmac_sha256:abc123def456"}]),
    );
    let redacted = redact_consumer_credentials(&consumer);
    assert!(!redacted.credentials.contains_key("basicauth"));
}

#[test]
fn test_redact_consumer_basicauth_plaintext_and_unknown_fields_omitted() {
    let mut consumer = make_consumer("c1", "alice");
    consumer.credentials.insert(
        "basicauth".into(),
        serde_json::json!([{"password": "plaintext", "unexpected": "also-sensitive"}]),
    );
    let redacted = redact_consumer_credentials(&consumer);
    assert!(!redacted.credentials.contains_key("basicauth"));
}

#[test]
fn test_redact_consumer_basicauth_malformed_values_omitted() {
    let mut consumer = make_consumer("c1", "alice");
    consumer.credentials.insert(
        "basicauth".into(),
        serde_json::json!(["must-not-escape", 42, null]),
    );
    let redacted = redact_consumer_credentials(&consumer);
    assert!(!redacted.credentials.contains_key("basicauth"));

    consumer
        .credentials
        .insert("basicauth".into(), serde_json::json!("must-not-escape"));
    let redacted = redact_consumer_credentials(&consumer);
    assert!(!redacted.credentials.contains_key("basicauth"));
}

#[test]
fn test_redact_consumer_jwt_secret_redacted() {
    let mut consumer = make_consumer("c1", "alice");
    consumer.credentials.insert(
        "jwt".into(),
        serde_json::json!([{"secret": "super-secret-jwt-key-that-is-long-enough-32ch"}]),
    );
    let redacted = redact_consumer_credentials(&consumer);
    let jwt = redacted.credentials.get("jwt").unwrap();
    assert_eq!(jwt[0]["secret"].as_str().unwrap(), "[REDACTED]");
}

#[test]
fn test_redact_consumer_hmac_secret_redacted() {
    let mut consumer = make_consumer("c1", "alice");
    consumer.credentials.insert(
        "hmac_auth".into(),
        serde_json::json!([{"secret": "hmac-secret-value-here"}]),
    );
    let redacted = redact_consumer_credentials(&consumer);
    let hmac = redacted.credentials.get("hmac_auth").unwrap();
    assert_eq!(hmac[0]["secret"].as_str().unwrap(), "[REDACTED]");
}

#[test]
fn test_redact_consumer_mtls_identity_unchanged() {
    // mtls_auth has no secret field — identity is not sensitive
    let mut consumer = make_consumer("c1", "alice");
    consumer.credentials.insert(
        "mtls_auth".into(),
        serde_json::json!([{"identity": "CN=client1,O=Acme"}]),
    );
    let redacted = redact_consumer_credentials(&consumer);
    let mtls = redacted.credentials.get("mtls_auth").unwrap();
    assert_eq!(
        mtls[0]["identity"].as_str().unwrap(),
        "CN=client1,O=Acme",
        "mtls identity should NOT be redacted"
    );
}

#[test]
fn test_redact_consumer_multiple_credential_types_all_redacted() {
    let mut consumer = make_consumer("c1", "alice");
    consumer.credentials.insert(
        "basicauth".into(),
        serde_json::json!([{"password_hash": "hmac_sha256:secret1"}]),
    );
    consumer.credentials.insert(
        "jwt".into(),
        serde_json::json!([{"secret": "jwt-secret-value-long-enough-32chars!!"}]),
    );
    consumer.credentials.insert(
        "hmac_auth".into(),
        serde_json::json!([{"secret": "hmac-secret"}]),
    );
    consumer
        .credentials
        .insert("keyauth".into(), serde_json::json!([{"key": "my-key"}]));

    let redacted = redact_consumer_credentials(&consumer);

    // basicauth is redacted by omitting the credential type.
    assert!(!redacted.credentials.contains_key("basicauth"));
    // jwt secret redacted
    assert_eq!(
        redacted.credentials["jwt"][0]["secret"].as_str().unwrap(),
        "[REDACTED]"
    );
    // hmac_auth secret redacted
    assert_eq!(
        redacted.credentials["hmac_auth"][0]["secret"]
            .as_str()
            .unwrap(),
        "[REDACTED]"
    );
    // keyauth key redacted
    assert_eq!(
        redacted.credentials["keyauth"][0]["key"].as_str().unwrap(),
        "[REDACTED]"
    );
}

#[test]
fn test_redact_consumer_multi_entry_array_all_entries_redacted() {
    let mut consumer = make_consumer("c1", "alice");
    consumer.credentials.insert(
        "jwt".into(),
        serde_json::json!([
            {"secret": "first-secret-value-long-enough-32characters"},
            {"secret": "second-secret-value-long-enough-32characters"}
        ]),
    );
    let redacted = redact_consumer_credentials(&consumer);
    let jwt = redacted.credentials.get("jwt").unwrap();
    let arr = jwt.as_array().unwrap();
    assert_eq!(arr.len(), 2);
    assert_eq!(arr[0]["secret"].as_str().unwrap(), "[REDACTED]");
    assert_eq!(arr[1]["secret"].as_str().unwrap(), "[REDACTED]");
}

#[test]
fn test_redact_consumer_does_not_mutate_original() {
    let mut consumer = make_consumer("c1", "alice");
    consumer.credentials.insert(
        "jwt".into(),
        serde_json::json!([{"secret": "original-secret-must-survive-32chars!!!"}]),
    );
    let _ = redact_consumer_credentials(&consumer);
    // Original consumer must be untouched
    assert_eq!(
        consumer.credentials["jwt"][0]["secret"].as_str().unwrap(),
        "original-secret-must-survive-32chars!!!"
    );
}

#[test]
fn test_redact_consumer_preserves_non_credential_fields() {
    let mut consumer = make_consumer("c1", "alice");
    consumer.custom_id = Some("custom-123".into());
    consumer.acl_groups = vec!["admin".to_string(), "users".to_string()];
    consumer.credentials.insert(
        "jwt".into(),
        serde_json::json!([{"secret": "jwt-secret-value-long-enough-32chars!!"}]),
    );

    let redacted = redact_consumer_credentials(&consumer);
    assert_eq!(redacted.id, "c1");
    assert_eq!(redacted.username, "alice");
    assert_eq!(redacted.custom_id, Some("custom-123".to_string()));
    assert_eq!(redacted.acl_groups, vec!["admin", "users"]);
}

#[test]
fn test_redact_consumer_object_format_basicauth_omitted() {
    // The old single-object format is omitted just like the canonical array.
    let mut consumer = make_consumer("c1", "alice");
    consumer.credentials.insert(
        "basicauth".into(),
        serde_json::json!({"password_hash": "hmac_sha256:oldhash"}),
    );
    let redacted = redact_consumer_credentials(&consumer);
    assert!(!redacted.credentials.contains_key("basicauth"));
}

#[test]
fn test_redact_consumer_legacy_jwt_entry_is_canonicalized() {
    // Legacy JWT fields are never echoed into the closed ordinary-response
    // projection, even when the old entry has no secret field.
    let mut consumer = make_consumer("c1", "alice");
    consumer.credentials.insert(
        "jwt".into(),
        serde_json::json!([{"algorithm": "HS256", "issuer": "example.com"}]),
    );
    let redacted = redact_consumer_credentials(&consumer);
    let jwt = redacted.credentials.get("jwt").unwrap();
    let entry = jwt[0].as_object().unwrap();
    assert_eq!(entry.len(), 1);
    assert_eq!(entry.get("secret"), Some(&serde_json::json!("[REDACTED]")));
    assert!(!entry.contains_key("algorithm"));
    assert!(!entry.contains_key("issuer"));
}

#[test]
fn test_redact_consumer_omits_unknown_credential_values() {
    let mut consumer = make_consumer("c1", "alice");
    consumer.credentials.insert(
        "custom_auth".into(),
        serde_json::json!([{
            "api_token": "must-not-cross-the-ordinary-response-boundary",
            "metadata": {"nested_secret": "also-must-not-cross"}
        }]),
    );

    let redacted = redact_consumer_credentials(&consumer);
    assert!(!redacted.credentials.contains_key("custom_auth"));
    assert!(consumer.credentials.contains_key("custom_auth"));
}

#[test]
fn cp_full_and_incremental_rejection_share_plugin_security_composition_validation() {
    let shared = include_str!("../../../src/config/validation_pipeline.rs");
    assert!(
        shared.contains("validate_plugin_security_composition_candidate("),
        "the shared rejecting contract must include plugin security composition"
    );
    let rejecting_fn = shared
        .find("pub(crate) fn collect_rejecting_runtime_config_errors(")
        .expect("shared rejecting contract function");
    let rejecting_body = &shared[rejecting_fn..];
    assert!(
        rejecting_body.contains("config.validate_resource_ids()"),
        "shared rejecting contract must fail closed on malformed IDs/namespaces"
    );

    let control_plane = include_str!("../../../src/modes/control_plane.rs");
    let full_start = control_plane
        .find("fn reject_invalid_cp_full_snapshot(")
        .expect("CP full rejection function");
    let incremental_start = control_plane
        .find("fn collect_rejecting_cp_incremental_errors(")
        .expect("CP incremental rejection function");
    let tracker_start = control_plane[incremental_start..]
        .find("struct CpRejectedDeltaTracker")
        .map(|offset| incremental_start + offset)
        .expect("CP rejected-delta tracker after incremental validation");
    assert!(
        control_plane[full_start..incremental_start]
            .contains("collect_rejecting_runtime_config_errors(config)"),
        "CP full snapshots must use the shared rejecting contract"
    );
    assert!(
        control_plane[incremental_start..tracker_start]
            .contains("collect_rejecting_runtime_config_errors"),
        "CP incremental snapshots must use the shared rejecting contract"
    );
}

#[test]
fn non_runtime_full_loads_skip_node_local_plugin_files() {
    assert!(FullConfigLoadPurpose::Runtime.loads_node_local_plugin_files());
    assert!(!FullConfigLoadPurpose::ControlPlane.loads_node_local_plugin_files());
    assert!(!FullConfigLoadPurpose::BackupExport.loads_node_local_plugin_files());

    let control_plane = include_str!("../../../src/modes/control_plane.rs");
    // Two call sites: the single-namespace fast path and the per-namespace
    // isolation loop that also covers the multi-namespace seed (#2983 folded
    // the former "first namespace" seed into that loop).
    assert_eq!(
        control_plane
            .matches("FullConfigLoadPurpose::ControlPlane")
            .count(),
        2,
        "single- and multi-namespace CP full loads must use the non-serving purpose"
    );
    assert!(!control_plane.contains("CountryMmdbLoadSession"));

    let admin = include_str!("../../../src/admin/mod.rs");
    let backup_start = admin
        .find("async fn handle_backup(")
        .expect("backup handler");
    let restore_start = admin[backup_start..]
        .find("async fn handle_restore(")
        .map(|offset| backup_start + offset)
        .expect("restore handler after backup");
    assert!(
        admin[backup_start..restore_start].contains("FullConfigLoadPurpose::BackupExport"),
        "backup export must not create a runtime MMDB validation handoff"
    );

    for source in [
        include_str!("../../../src/config/db_loader.rs"),
        include_str!("../../../src/config/mongo_store.rs"),
    ] {
        assert!(source.contains("if purpose.loads_node_local_plugin_files() {"));
    }
}

#[test]
fn runtime_plugin_file_dependency_validation_runs_off_async_workers() {
    let validation = include_str!("../../../src/config/validation_pipeline.rs");
    assert!(validation.contains("validate_plugin_file_dependencies_off_thread"));
    assert!(validation.contains("tokio::task::spawn_blocking"));
    assert!(validation.contains("GeoRestriction::validate_config"));

    for source in [
        include_str!("../../../src/config/db_loader.rs"),
        include_str!("../../../src/config/mongo_store.rs"),
    ] {
        assert!(source.contains("validate_plugin_file_dependencies_off_thread("));
        assert!(source.contains("ValidationAction::Warn"));
        assert!(source.contains(".await?"));
    }

    let dp_client = include_str!("../../../src/grpc/dp_client.rs");
    assert!(dp_client.contains("update_config_off_thread(config).await"));

    let proxy = include_str!("../../../src/proxy/mod.rs");
    let plugin_cache = include_str!("../../../src/plugin_cache.rs");
    assert!(proxy.contains("country_mmdb_preload_required("));
    assert!(proxy.contains("body_validator_descriptor_preload_required("));
    assert!(proxy.contains("ai_response_guard_descriptor_preload_required("));
    assert!(proxy.contains("validate_plugin_file_dependencies_off_thread("));
    assert!(plugin_cache.contains("pub(crate) fn country_mmdb_preload_required("));
    assert!(plugin_cache.contains("pub(crate) fn body_validator_descriptor_preload_required("));
    assert!(plugin_cache.contains("pub(crate) fn ai_response_guard_descriptor_preload_required("));
    assert_eq!(
        plugin_cache
            .matches("self.expanded_file_dependency_rebuild_scope(")
            .count(),
        3,
        "MMDB and protobuf descriptor preloads must use the exact expanded delta-build scope"
    );

    let file_loader = include_str!("../../../src/config/file_loader.rs");
    let file_mode = include_str!("../../../src/modes/file.rs");
    assert!(file_loader.contains("load_config_from_file_off_thread"));
    assert!(file_loader.contains("reload_config_from_file_off_thread"));
    assert!(file_mode.contains("load_config_from_file_off_thread("));
    assert!(file_mode.contains("reload_config_from_file_off_thread("));
}

#[test]
fn runtime_plugin_composition_validation_treats_globals_as_gateway_wide() {
    let global_correlation = |id: &str, namespace: &str| PluginConfig {
        id: id.to_string(),
        plugin_name: "correlation_id".to_string(),
        namespace: namespace.to_string(),
        config: json!({}),
        scope: PluginScope::Global,
        proxy_id: None,
        enabled: true,
        priority_override: None,
        api_spec_id: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };
    let config = GatewayConfig {
        plugin_configs: vec![
            global_correlation("tenant-a-correlation", "tenant-a"),
            global_correlation("tenant-b-correlation", "tenant-b"),
        ],
        ..GatewayConfig::default()
    };

    let errors =
        ferrum_edge::_test_support::collect_rejecting_runtime_config_errors_for_test(&config);
    assert!(
        errors
            .iter()
            .any(|error| error.contains("duplicate effective header_name")),
        "global correlation owners are installed gateway-wide and must conflict: {errors:?}"
    );
}

#[test]
fn runtime_config_rejection_includes_tcp_throttle_attachment_validation() {
    let shared = include_str!("../../../src/config/validation_pipeline.rs");
    assert!(
        shared.contains("validate_tcp_connection_throttle_attachments(config)"),
        "database and CP snapshots must reject unsupported TCP-throttle attachments"
    );
}
