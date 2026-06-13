use chrono::Utc;
use ferrum_edge::config::types::{
    Consumer, anchor_regex_pattern, hosts_overlap, redact_consumer_credentials, validate_host_entry,
};
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
fn test_hosts_overlap_wildcard_does_not_match_multi_level() {
    let a = vec!["*.example.com".to_string()];
    let b = vec!["a.b.example.com".to_string()];
    assert!(
        !hosts_overlap(&a, &b),
        "*.example.com should NOT match multi-level subdomain"
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
fn test_redact_consumer_basicauth_password_hash_redacted() {
    let mut consumer = make_consumer("c1", "alice");
    consumer.credentials.insert(
        "basicauth".into(),
        serde_json::json!([{"password_hash": "hmac_sha256:abc123def456"}]),
    );
    let redacted = redact_consumer_credentials(&consumer);
    let basicauth = redacted.credentials.get("basicauth").unwrap();
    assert_eq!(
        basicauth[0]["password_hash"].as_str().unwrap(),
        "[REDACTED]"
    );
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

    // basicauth password_hash redacted
    assert_eq!(
        redacted.credentials["basicauth"][0]["password_hash"]
            .as_str()
            .unwrap(),
        "[REDACTED]"
    );
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
fn test_redact_consumer_object_format_basicauth_redacted() {
    // The old single-object format (not array) — redact_field handles both
    let mut consumer = make_consumer("c1", "alice");
    consumer.credentials.insert(
        "basicauth".into(),
        serde_json::json!({"password_hash": "hmac_sha256:oldhash"}),
    );
    let redacted = redact_consumer_credentials(&consumer);
    let basicauth = redacted.credentials.get("basicauth").unwrap();
    assert_eq!(basicauth["password_hash"].as_str().unwrap(), "[REDACTED]");
}

#[test]
fn test_redact_consumer_entry_without_target_field_unchanged() {
    // If a jwt entry doesn't have a "secret" key, it's left alone
    let mut consumer = make_consumer("c1", "alice");
    consumer.credentials.insert(
        "jwt".into(),
        serde_json::json!([{"algorithm": "HS256", "issuer": "example.com"}]),
    );
    let redacted = redact_consumer_credentials(&consumer);
    let jwt = redacted.credentials.get("jwt").unwrap();
    let entry = jwt[0].as_object().unwrap();
    assert_eq!(entry.get("algorithm").unwrap().as_str().unwrap(), "HS256");
    assert_eq!(
        entry.get("issuer").unwrap().as_str().unwrap(),
        "example.com"
    );
    assert!(entry.get("secret").is_none());
}
