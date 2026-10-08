//! Plugin-config environment references are confined to the dedicated
//! `FERRUM_PLUGIN_SECRET_<NAME>` namespace.
//!
//! A plugin config is written by principals that do not own the gateway
//! process environment, and several plugins send the referenced value as a
//! credential to an endpoint the same config chooses. These tests pin the
//! shared resolver and enumerate every plugin field that names an environment
//! variable, so a new sibling field that skips the boundary has a table to
//! join.

use ferrum_edge::plugins::utils::plugin_secret_env::{
    PLUGIN_SECRET_ENV_PREFIX, is_plugin_secret_env_name, resolve_plugin_secret_env,
    validate_plugin_secret_env_name,
};
use ferrum_edge::plugins::validate_plugin_config;
use serde_json::{Value, json};

use crate::unit::env_lock::EnvGuard;

/// A value that must never surface in any diagnostic.
const GATEWAY_SECRET_SENTINEL: &str = "gateway-owned-secret-sentinel-0123456789abcdef";

/// Names that every plugin env reference must refuse, including gateway-owned
/// secrets that ARE set in this process.
const REFUSED_NAMES: &[&str] = &[
    "FERRUM_ADMIN_JWT_SECRET",
    "FERRUM_DB_URL",
    "FERRUM_CP_DP_GRPC_JWT_SECRET",
    "FERRUM_METRICS_BEARER_TOKEN",
    "AWS_SECRET_ACCESS_KEY",
    "PATH",
    "FERRUM_PLUGIN_SECRET_",
    "FERRUM_PLUGIN_SECRET_lowercase",
    "FERRUM_PLUGIN_SECRET_HAS SPACE",
    "FERRUM_PLUGIN_SECRET_TRAILING-DASH",
    // External secret-source suffixes are consumed by startup resolution to
    // materialize the base variable; a config must reference the base, never
    // the `_FILE` / `_VAULT` / `_AWS` / `_AZURE` / `_GCP` locator.
    "FERRUM_PLUGIN_SECRET_DEMO_FILE",
    "FERRUM_PLUGIN_SECRET_DEMO_VAULT",
    "FERRUM_PLUGIN_SECRET_DEMO_AWS",
    "FERRUM_PLUGIN_SECRET_DEMO_AZURE",
    "FERRUM_PLUGIN_SECRET_DEMO_GCP",
];

#[test]
fn namespace_admits_only_uppercase_plugin_secret_names() {
    for name in [
        "FERRUM_PLUGIN_SECRET_A",
        "FERRUM_PLUGIN_SECRET__",
        "FERRUM_PLUGIN_SECRET_CLICKHOUSE_PASSWORD",
        "FERRUM_PLUGIN_SECRET_KEY_2",
    ] {
        assert!(is_plugin_secret_env_name(name), "{name} admitted");
        assert!(validate_plugin_secret_env_name("field", name).is_ok());
    }
    let also_refused = [
        "FERRUM_PLUGIN_SECRET_9LEADING_DIGIT",
        " FERRUM_PLUGIN_SECRET_PADDED",
        "",
        "ferrum_plugin_secret_x",
    ];
    for name in REFUSED_NAMES.iter().copied().chain(also_refused) {
        assert!(!is_plugin_secret_env_name(name), "{name:?} refused");
    }
    let oversized = format!("{PLUGIN_SECRET_ENV_PREFIX}{}", "A".repeat(256));
    assert!(!is_plugin_secret_env_name(&oversized));
}

/// The external secret-source suffixes the startup resolver consumes are not
/// themselves admissible references: naming `FERRUM_PLUGIN_SECRET_X_FILE`
/// would send the file path/locator, not the secret. The diagnostic must name
/// the field and namespace without echoing the reference.
#[test]
fn namespace_refuses_external_secret_source_suffixes_without_echoing_them() {
    for name in [
        "FERRUM_PLUGIN_SECRET_DEMO_FILE",
        "FERRUM_PLUGIN_SECRET_DEMO_VAULT",
        "FERRUM_PLUGIN_SECRET_DEMO_AWS",
        "FERRUM_PLUGIN_SECRET_DEMO_AZURE",
        "FERRUM_PLUGIN_SECRET_DEMO_GCP",
    ] {
        assert!(!is_plugin_secret_env_name(name), "{name} must be refused");
        let error = validate_plugin_secret_env_name("demo: `secret_ref`", name)
            .expect_err("a source-suffix reference must be refused");
        assert!(error.contains("demo: `secret_ref`"), "{error}");
        assert!(error.contains("FERRUM_PLUGIN_SECRET_<NAME>"), "{error}");
        assert!(!error.contains(name), "diagnostic echoed the reference: {error}");
    }
    // The materialized base name is the admitted reference.
    assert!(is_plugin_secret_env_name("FERRUM_PLUGIN_SECRET_DEMO"));
}

#[test]
fn refusal_names_the_field_and_namespace_without_echoing_the_reference() {
    let error = validate_plugin_secret_env_name("demo: `secret_ref`", "FERRUM_ADMIN_JWT_SECRET")
        .expect_err("gateway secret must be refused");
    assert!(error.contains("demo: `secret_ref`"), "{error}");
    assert!(error.contains("FERRUM_PLUGIN_SECRET_<NAME>"), "{error}");
    assert!(!error.contains("FERRUM_ADMIN_JWT_SECRET"), "{error}");
}

#[test]
fn resolver_never_reads_outside_the_namespace() {
    let env = EnvGuard::new(&[]);
    env.set("FERRUM_ADMIN_JWT_SECRET", GATEWAY_SECRET_SENTINEL);
    env.set("FERRUM_DB_URL", GATEWAY_SECRET_SENTINEL);
    for name in REFUSED_NAMES {
        let error = resolve_plugin_secret_env("demo: `secret_ref`", name)
            .expect_err("out-of-namespace reference must be refused");
        assert!(error.contains("FERRUM_PLUGIN_SECRET_<NAME>"), "{error}");
        assert!(!error.contains(GATEWAY_SECRET_SENTINEL), "{error}");
    }
}

#[test]
fn resolver_reads_set_values_and_refuses_unset_or_empty_ones() {
    let env = EnvGuard::new(&[]);
    env.set("FERRUM_PLUGIN_SECRET_DEMO_TOKEN", "demo-token");
    assert_eq!(
        resolve_plugin_secret_env("demo", "FERRUM_PLUGIN_SECRET_DEMO_TOKEN").as_deref(),
        Ok("demo-token")
    );

    env.set("FERRUM_PLUGIN_SECRET_DEMO_TOKEN", "");
    let empty = resolve_plugin_secret_env("demo", "FERRUM_PLUGIN_SECRET_DEMO_TOKEN")
        .expect_err("an empty secret must not be sent");
    assert!(empty.contains("set but empty"), "{empty}");

    env.unset("FERRUM_PLUGIN_SECRET_DEMO_TOKEN");
    let unset = resolve_plugin_secret_env("demo", "FERRUM_PLUGIN_SECRET_DEMO_TOKEN")
        .expect_err("an unset secret must fail");
    assert!(unset.contains("is not set"), "{unset}");
}

fn api_chargeback_sink_password_ref(name: &str) -> Value {
    json!({
        "clickhouse": {
            "url": "https://clickhouse.example:8443",
            "password_ref": name
        },
        "spool": { "enabled": false },
        "pricing_tiers": [{"status_codes": [200], "price_per_call": 0.01}]
    })
}

fn ai_semantic_firewall_api_key_env(name: &str) -> Value {
    json!({
        "inspect": {"request": true, "response": false},
        "provider": {
            "type": "openai_compatible_embeddings",
            "endpoint": "https://embeddings.example.com/v1/embeddings",
            "api_key_env": name
        },
        "builtins": {"prompt_injection": true}
    })
}

fn ai_stream_router_api_key_reference(name: &str) -> Value {
    json!({
        "providers": [{
            "name": "openai",
            "provider_type": "openai",
            "endpoint": "https://api.openai.com/v1/chat/completions",
            "api_key": format!("${{{name}}}"),
            "model_patterns": ["gpt-*"]
        }]
    })
}

fn workload_metrics_lightstep_token_env(name: &str) -> Value {
    json!({
        "span_reporting_disabled": true,
        "tracing_provider": {
            "kind": "lightstep",
            "config": {
                "collector_url": "https://ingest.lightstep.example:443",
                "access_token_env": name
            }
        }
    })
}

fn proxy_alerts_config(channels: Value) -> Value {
    let names: Vec<String> = channels
        .as_object()
        .expect("channel map")
        .keys()
        .cloned()
        .collect();
    json!({
        "channels": channels,
        "rules": [{
            "name": "errors",
            "type": "error_rate",
            "status_codes": [500],
            "window_seconds": 60,
            "threshold_percent": 5.0,
            "min_request_count": 10,
            "channels": names
        }]
    })
}

fn proxy_alerts_webhook_url_env(name: &str) -> Value {
    proxy_alerts_config(json!({
        "ops_slack": {"type": "slack", "webhook_url_env": name},
        "ops_teams": {"type": "teams", "webhook_url_env": name},
        "ops_discord": {"type": "discord", "webhook_url_env": name},
        "ops_webhook": {"type": "webhook", "url_env": name, "body_template": "{}"}
    }))
}

fn proxy_alerts_smtp_credential_env(name: &str) -> Value {
    proxy_alerts_config(json!({
        "ops_email": {
            "type": "email",
            "smtp_host": "smtp.example.com",
            "username_env": name,
            "password_env": name,
            "from": "ferrum@example.com",
            "to": ["oncall@example.com"]
        }
    }))
}

/// Every plugin config field that names a process environment variable, as
/// `(plugin, config builder)`. A new env-reference field belongs here.
const ENV_REFERENCE_FIELDS: [(&str, fn(&str) -> Value); 6] = [
    ("api_chargeback_sink", api_chargeback_sink_password_ref),
    ("ai_semantic_firewall", ai_semantic_firewall_api_key_env),
    ("ai_stream_router", ai_stream_router_api_key_reference),
    ("workload_metrics", workload_metrics_lightstep_token_env),
    ("proxy_alerts", proxy_alerts_webhook_url_env),
    ("proxy_alerts", proxy_alerts_smtp_credential_env),
];

/// Admission (the same validator the admin API answers 400 from) refuses a
/// plugin config that names a gateway-owned secret, even when that secret is
/// set in this process, and never echoes its value.
#[tokio::test]
async fn admission_refuses_env_references_outside_the_namespace_for_every_plugin() {
    let env = EnvGuard::new(&[]);
    env.set("FERRUM_ADMIN_JWT_SECRET", GATEWAY_SECRET_SENTINEL);
    env.set("FERRUM_DB_URL", GATEWAY_SECRET_SENTINEL);
    for name in REFUSED_NAMES {
        for (plugin, build) in ENV_REFERENCE_FIELDS {
            let config = build(name);
            let error = validate_plugin_config(plugin, &config)
                .expect_err("an out-of-namespace env reference must be refused at admission");
            assert!(
                error.contains("FERRUM_PLUGIN_SECRET_<NAME>"),
                "{plugin} with {name:?}: {error}"
            );
            assert!(
                !error.contains(GATEWAY_SECRET_SENTINEL),
                "{plugin} with {name:?} echoed a secret: {error}"
            );
        }
    }
}

/// A namespaced reference is admitted. Plugins that resolve at construction
/// read the value set here; shape-only plugins never need it.
#[tokio::test]
async fn admission_accepts_plugin_secret_namespace_references() {
    let env = EnvGuard::new(&[]);
    env.set(
        "FERRUM_PLUGIN_SECRET_ADMISSION_FIXTURE",
        "https://hooks.example.com/services/fixture",
    );
    for (plugin, build) in ENV_REFERENCE_FIELDS {
        let config = build("FERRUM_PLUGIN_SECRET_ADMISSION_FIXTURE");
        validate_plugin_config(plugin, &config)
            .unwrap_or_else(|error| panic!("{plugin} must admit a namespaced reference: {error}"));
    }
}
