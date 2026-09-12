//! Proxy `CircuitBreakerConfig` serde alias: `cooldown_seconds` → `timeout_seconds`.
//!
//! Issue #5459: operators who spelled the open-state duration as
//! `cooldown_seconds` previously had that field silently dropped, so the 30s
//! default applied. The alias is accepted on Admin API bodies, file config,
//! database rows, and batch/restore payloads. Serialization always emits
//! `timeout_seconds`.

use ferrum_edge::config::types::{CircuitBreakerConfig, Proxy};
use serde_json::json;

fn assert_serializes_timeout_only(config: &CircuitBreakerConfig, expected: u64) {
    assert_eq!(config.timeout_seconds, expected);
    let serialized = serde_json::to_value(config).expect("serialize CircuitBreakerConfig");
    assert_eq!(serialized["timeout_seconds"], expected);
    assert!(
        serialized.get("cooldown_seconds").is_none(),
        "serialization must emit timeout_seconds only: {serialized}"
    );
}

#[test]
fn cooldown_seconds_alias_parses_as_timeout_seconds() {
    let via_alias: CircuitBreakerConfig = serde_json::from_value(json!({
        "failure_threshold": 2,
        "cooldown_seconds": 99,
    }))
    .expect("cooldown_seconds alias");
    let via_canonical: CircuitBreakerConfig = serde_json::from_value(json!({
        "failure_threshold": 2,
        "timeout_seconds": 99,
    }))
    .expect("timeout_seconds");

    assert_eq!(via_alias, via_canonical);
    assert_serializes_timeout_only(&via_alias, 99);
    assert_serializes_timeout_only(&via_canonical, 99);
}

#[test]
fn yaml_cooldown_seconds_alias_parses_as_timeout_seconds() {
    let via_alias: CircuitBreakerConfig =
        serde_yaml::from_str("failure_threshold: 2\ncooldown_seconds: 99\n")
            .expect("yaml cooldown_seconds alias");
    let via_canonical: CircuitBreakerConfig =
        serde_yaml::from_str("failure_threshold: 2\ntimeout_seconds: 99\n")
            .expect("yaml timeout_seconds");
    assert_eq!(via_alias, via_canonical);
    assert_eq!(via_alias.timeout_seconds, 99);
    let yaml = serde_yaml::to_string(&via_alias).expect("yaml serialize");
    assert!(
        yaml.contains("timeout_seconds: 99"),
        "yaml serialization must emit timeout_seconds: {yaml}"
    );
    assert!(
        !yaml.contains("cooldown_seconds"),
        "yaml serialization must not emit cooldown_seconds: {yaml}"
    );
}

#[test]
fn both_timeout_and_cooldown_spellings_are_rejected() {
    let err = serde_json::from_str::<CircuitBreakerConfig>(
        r#"{"timeout_seconds":10,"cooldown_seconds":99}"#,
    )
    .expect_err("both spellings must be a duplicate field");
    let message = err.to_string();
    assert!(
        message.contains("duplicate field"),
        "serde duplicate-field error must be readable: {message}"
    );
    // Admin CRUD wraps serde errors as HTTP 400 `{"error": "Invalid body: ..."}`.
    let admin_error = format!("Invalid body: {message}");
    assert!(
        admin_error.contains("duplicate field"),
        "Admin 400 body must remain readable: {admin_error}"
    );
}

#[test]
fn yaml_both_timeout_and_cooldown_spellings_are_rejected() {
    let err =
        serde_yaml::from_str::<CircuitBreakerConfig>("timeout_seconds: 10\ncooldown_seconds: 99\n")
            .expect_err("yaml both spellings must be a duplicate field");
    let message = err.to_string();
    assert!(
        message.contains("duplicate field"),
        "serde yaml duplicate-field error must be readable: {message}"
    );
}

#[test]
fn proxy_circuit_breaker_accepts_cooldown_seconds_alias() {
    let proxy: Proxy = serde_json::from_value(json!({
        "id": "p1",
        "listen_path": "/api",
        "backend_host": "localhost",
        "backend_port": 3000,
        "backend_scheme": "http",
        "circuit_breaker": {
            "failure_threshold": 2,
            "cooldown_seconds": 99,
        },
    }))
    .expect("proxy with cooldown_seconds alias");
    let breaker = proxy.circuit_breaker.expect("breaker present");
    assert_eq!(breaker.timeout_seconds, 99);
    let serialized = serde_json::to_value(&proxy).expect("serialize proxy");
    let breaker_json = serialized
        .get("circuit_breaker")
        .expect("serialized circuit_breaker");
    assert_eq!(breaker_json["timeout_seconds"], 99);
    assert!(
        breaker_json.get("cooldown_seconds").is_none(),
        "proxy serialization must emit timeout_seconds only: {breaker_json}"
    );
}

#[test]
fn default_still_applies_when_neither_spelling_is_present() {
    let config: CircuitBreakerConfig = serde_json::from_value(json!({
        "failure_threshold": 2,
    }))
    .expect("defaults");
    assert_eq!(config.timeout_seconds, 30);
}
