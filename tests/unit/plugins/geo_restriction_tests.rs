use chrono::Utc;
use ferrum_edge::config::types::{
    GatewayConfig, PluginConfig, PluginScope, default_namespace, validate_mmdb_file,
};
use ferrum_edge::plugins::Plugin;
use ferrum_edge::plugins::geo_restriction::GeoRestriction;
use serde_json::json;

// Note: geo_restriction tests that require actual .mmdb files are limited to
// config validation tests. Full lookup tests would require a MaxMind test database.

fn make_geo_plugin(id: &str, enabled: bool, config: serde_json::Value) -> PluginConfig {
    PluginConfig {
        id: id.into(),
        namespace: default_namespace(),
        plugin_name: "geo_restriction".into(),
        config,
        scope: PluginScope::Global,
        proxy_id: None,
        enabled,
        priority_override: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

#[test]
fn test_new_missing_db_path_fails() {
    let config = json!({
        "allow_countries": ["US"]
    });
    let result = GeoRestriction::new(&config);
    assert!(result.is_err());
    assert!(result.err().unwrap().contains("db_path"));
}

#[test]
fn test_new_invalid_db_path_succeeds_with_none_reader() {
    // Constructor no longer fails on missing .mmdb file — it stores reader: None
    // and degrades gracefully at request time using on_lookup_failure policy.
    let config = json!({
        "db_path": "/nonexistent/path/to/GeoLite2-Country.mmdb",
        "allow_countries": ["US"]
    });
    let result = GeoRestriction::new(&config);
    assert!(
        result.is_ok(),
        "Constructor should succeed with missing file"
    );
}

#[test]
fn test_new_no_countries_fails() {
    // With reader now optional, this properly tests the no-countries validation.
    let config = json!({
        "db_path": "/nonexistent/path/to/test.mmdb"
    });
    let result = GeoRestriction::new(&config);
    assert!(result.is_err());
    assert!(
        result.err().unwrap().contains("allow_countries"),
        "Should fail due to missing country lists"
    );
}

#[test]
fn test_new_both_allow_and_deny_fails() {
    let config = json!({
        "db_path": "/nonexistent/path/to/test.mmdb",
        "allow_countries": ["US"],
        "deny_countries": ["CN"]
    });
    let result = GeoRestriction::new(&config);
    assert!(result.is_err());
    assert!(
        result.err().unwrap().contains("mutually exclusive"),
        "Should fail due to both allow and deny lists"
    );
}

// --- validate_mmdb_file tests ---

#[test]
fn test_validate_mmdb_file_nonexistent() {
    let result = validate_mmdb_file("geo_restriction.db_path", "/nonexistent/path/test.mmdb");
    assert!(result.is_err());
    assert!(result.err().unwrap().contains("not accessible"));
}

#[test]
fn test_validate_mmdb_file_is_directory() {
    let result = validate_mmdb_file("geo_restriction.db_path", "/tmp");
    assert!(result.is_err());
    assert!(result.err().unwrap().contains("not a regular file"));
}

// --- validate_plugin_file_dependencies tests ---

#[test]
fn test_validate_plugin_file_deps_catches_missing_mmdb() {
    let config = GatewayConfig {
        plugin_configs: vec![make_geo_plugin(
            "pc1",
            true,
            json!({
                "db_path": "/nonexistent/path/GeoLite2-Country.mmdb",
                "allow_countries": ["US"]
            }),
        )],
        ..Default::default()
    };
    let errors = config.validate_plugin_file_dependencies();
    assert!(!errors.is_empty(), "Should report missing .mmdb file");
    assert!(
        errors[0].contains("MaxMind database file"),
        "Error should mention MaxMind: {}",
        errors[0]
    );
}

#[test]
fn test_validate_plugin_file_deps_skips_disabled_plugin() {
    let config = GatewayConfig {
        plugin_configs: vec![make_geo_plugin(
            "pc1",
            false,
            json!({
                "db_path": "/nonexistent/path/GeoLite2-Country.mmdb",
                "allow_countries": ["US"]
            }),
        )],
        ..Default::default()
    };
    let errors = config.validate_plugin_file_dependencies();
    assert!(errors.is_empty(), "Disabled plugin should not be validated");
}

#[test]
fn test_validate_plugin_file_deps_deduplicates_paths() {
    // Two plugins referencing the same missing file should only produce one error.
    let config = GatewayConfig {
        plugin_configs: vec![
            make_geo_plugin(
                "pc1",
                true,
                json!({
                    "db_path": "/nonexistent/path/GeoLite2-Country.mmdb",
                    "allow_countries": ["US"]
                }),
            ),
            make_geo_plugin(
                "pc2",
                true,
                json!({
                    "db_path": "/nonexistent/path/GeoLite2-Country.mmdb",
                    "deny_countries": ["CN"]
                }),
            ),
        ],
        ..Default::default()
    };
    let errors = config.validate_plugin_file_dependencies();
    let mmdb_errors: Vec<_> = errors
        .iter()
        .filter(|e| e.contains("MaxMind database file"))
        .collect();
    assert_eq!(
        mmdb_errors.len(),
        1,
        "Same path should only be validated once: {:?}",
        errors
    );
}

// --- modifies_request_headers capability ---

#[test]
fn test_modifies_request_headers_true_when_inject_enabled() {
    // The proxy uses this hint to take the explicit-clone code path; without
    // it `before_proxy` modifications happen on a soon-to-be-restored buffer
    // and the resulting behavior is fragile.
    let config = json!({
        "db_path": "/nonexistent/path/test.mmdb",
        "allow_countries": ["US"],
        "inject_headers": true
    });
    let plugin = GeoRestriction::new(&config).unwrap();
    assert!(plugin.modifies_request_headers());
}

#[test]
fn test_modifies_request_headers_false_when_inject_disabled() {
    let config = json!({
        "db_path": "/nonexistent/path/test.mmdb",
        "allow_countries": ["US"]
    });
    let plugin = GeoRestriction::new(&config).unwrap();
    assert!(!plugin.modifies_request_headers());
}

#[test]
fn test_validate_all_fields_does_not_check_mmdb() {
    // validate_all_fields should NOT catch missing .mmdb files — that's
    // handled by validate_plugin_file_dependencies() so each mode can
    // treat it independently (fatal vs warn vs skip).
    let config = GatewayConfig {
        plugin_configs: vec![make_geo_plugin(
            "pc1",
            true,
            json!({
                "db_path": "/nonexistent/path/GeoLite2-Country.mmdb",
                "allow_countries": ["US"]
            }),
        )],
        ..Default::default()
    };
    let result = config.validate_all_fields(30);
    // Should pass — .mmdb validation is NOT in validate_all_fields
    assert!(
        result.is_ok(),
        "validate_all_fields should not check .mmdb files: {:?}",
        result.err()
    );
}
