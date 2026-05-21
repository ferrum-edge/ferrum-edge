use chrono::Utc;
use ferrum_edge::config::types::{
    GatewayConfig, PluginConfig, PluginScope, default_namespace, validate_mmdb_file,
};
use ferrum_edge::plugins::geo_restriction::GeoRestriction;
use ferrum_edge::plugins::{ALL_PROTOCOLS, Plugin, PluginResult, RequestContext, priority};
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
        api_spec_id: None,
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
fn test_plugin_metadata_and_protocol_flags() {
    let config = json!({
        "db_path": "/nonexistent/path/to/GeoLite2-Country.mmdb",
        "allow_countries": ["US"]
    });
    let plugin = GeoRestriction::new(&config).unwrap();
    assert_eq!(plugin.name(), "geo_restriction");
    assert_eq!(plugin.priority(), priority::GEO_RESTRICTION);
    assert_eq!(plugin.priority(), 175);
    assert_eq!(plugin.supported_protocols(), ALL_PROTOCOLS);
    assert!(!plugin.modifies_request_headers());
    assert!(!plugin.applies_after_proxy_on_reject());
    assert!(!plugin.is_auth_plugin());
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

#[test]
fn test_new_rejects_invalid_country_code() {
    let config = json!({
        "db_path": "/nonexistent/path/to/test.mmdb",
        "allow_countries": ["USA"]
    });
    let result = GeoRestriction::new(&config);
    assert!(result.is_err());
    assert!(result.err().unwrap().contains("country code"));
}

#[test]
fn test_new_rejects_non_string_country_code() {
    let config = json!({
        "db_path": "/nonexistent/path/to/test.mmdb",
        "deny_countries": [42]
    });
    let result = GeoRestriction::new(&config);
    assert!(result.is_err());
    assert!(result.err().unwrap().contains("entries must be strings"));
}

#[test]
fn test_new_rejects_non_array_country_list() {
    let config = json!({
        "db_path": "/nonexistent/path/to/test.mmdb",
        "allow_countries": "US"
    });
    let result = GeoRestriction::new(&config);
    assert!(result.is_err());
    assert!(result.err().unwrap().contains("allow_countries"));
}

#[test]
fn test_new_rejects_invalid_on_lookup_failure() {
    let config = json!({
        "db_path": "/nonexistent/path/to/test.mmdb",
        "allow_countries": ["US"],
        "on_lookup_failure": "block"
    });
    let result = GeoRestriction::new(&config);
    assert!(result.is_err());
    assert!(result.err().unwrap().contains("on_lookup_failure"));
}

#[test]
fn test_new_rejects_non_bool_inject_headers() {
    let config = json!({
        "db_path": "/nonexistent/path/to/test.mmdb",
        "allow_countries": ["US"],
        "inject_headers": "yes"
    });
    let result = GeoRestriction::new(&config);
    assert!(result.is_err());
    assert!(result.err().unwrap().contains("inject_headers"));
}

#[tokio::test]
async fn test_missing_reader_uses_deny_lookup_failure_policy() {
    let config = json!({
        "db_path": "/nonexistent/path/to/test.mmdb",
        "allow_countries": ["US"],
        "on_lookup_failure": "deny"
    });
    let plugin = GeoRestriction::new(&config).unwrap();
    let mut ctx = RequestContext::new(
        "203.0.113.1".to_string(),
        "GET".to_string(),
        "/test".to_string(),
    );

    let result = plugin.on_request_received(&mut ctx).await;
    assert!(matches!(
        result,
        PluginResult::Reject {
            status_code: 403,
            ..
        }
    ));
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

#[test]
fn test_validate_mmdb_file_rejects_invalid_mmdb_contents() {
    let temp_path = std::env::temp_dir().join(format!(
        "ferrum-edge-invalid-geo-{}.mmdb",
        std::process::id()
    ));
    std::fs::write(&temp_path, b"not a maxmind database").unwrap();

    let result = validate_mmdb_file(
        "geo_restriction.db_path",
        temp_path.to_str().expect("temp path utf-8"),
    );

    let _ = std::fs::remove_file(&temp_path);

    assert!(result.is_err());
    assert!(result.err().unwrap().contains("not a valid readable .mmdb"));
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
