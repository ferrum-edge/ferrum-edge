//! Tests for admin API validation improvements.
//!
//! Tests credential type whitelist, credential redaction coverage,
//! and validation constants.

use serde_json::json;

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
        username: "test-user".to_string(),
        custom_id: None,
        credentials,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    }
}

#[test]
fn test_redact_basicauth_password_hash() {
    let mut credentials = std::collections::HashMap::new();
    credentials.insert(
        "basicauth".to_string(),
        json!({"username": "alice", "password_hash": "$2b$12$realhashabcdef"}),
    );
    let consumer = make_consumer(credentials);

    let redacted = ferrum_edge::admin::redact_consumer_credentials(&consumer);
    let basic = redacted.credentials.get("basicauth").unwrap();
    assert_eq!(basic["password_hash"], "[REDACTED]");
    assert_eq!(basic["username"], "alice");
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

    assert_eq!(
        redacted.credentials["basicauth"]["password_hash"],
        "[REDACTED]"
    );
    assert_eq!(redacted.credentials["hmac_auth"]["secret"], "[REDACTED]");
    // keyauth key should NOT be redacted (it's the lookup key, not a secret)
    assert_eq!(redacted.credentials["keyauth"]["key"], "api-key-value");
}

#[test]
fn test_redact_no_secrets_present() {
    let mut credentials = std::collections::HashMap::new();
    credentials.insert("keyauth".to_string(), json!({"key": "my-api-key"}));
    credentials.insert(
        "mtls_auth".to_string(),
        json!({"identity": "CN=client.example.com"}),
    );
    let consumer = make_consumer(credentials);

    let redacted = ferrum_edge::admin::redact_consumer_credentials(&consumer);
    assert_eq!(redacted.credentials["keyauth"]["key"], "my-api-key");
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
