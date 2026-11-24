//! Cross-module admission coverage for the registered `spec_expose` plugin.

use ferrum_edge::plugins::validate_plugin_config;
use serde_json::json;

#[test]
fn registered_spec_expose_validation_accepts_documented_null_defaults() {
    let config = json!({
        "spec_url": "https://specs.example/openapi.yaml",
        "content_type": null,
        "tls_no_verify": null,
        "cache_ttl_seconds": null,
        "max_response_body_bytes": null
    });

    validate_plugin_config("spec_expose", &config)
        .expect("registered plugin validation should accept documented null defaults");
}

#[test]
fn registered_spec_expose_validation_reports_every_unknown_key() {
    let error = validate_plugin_config(
        "spec_expose",
        &json!({
            "spec_url": "https://specs.example/openapi.yaml",
            "cache_ttl_second": 30,
            "tls_no_verfy": true
        }),
    )
    .expect_err("registered plugin validation must reject unknown keys");

    assert!(error.contains("\"config.cache_ttl_second\""), "{error}");
    assert!(error.contains("\"config.tls_no_verfy\""), "{error}");
}

#[test]
fn registered_spec_expose_validation_rejects_userinfo_without_echoing_it() {
    let error = validate_plugin_config(
        "spec_expose",
        &json!({
            "spec_url": "https://operator:never-echo-this@specs.example/openapi.yaml"
        }),
    )
    .expect_err("registered plugin validation must reject URL userinfo");

    assert!(error.contains("must not contain URL userinfo"), "{error}");
    assert!(!error.contains("operator"), "{error}");
    assert!(!error.contains("never-echo-this"), "{error}");
}
