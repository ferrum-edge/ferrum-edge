//! Tests for ldap_auth plugin — config validation and credential extraction.
//!
//! Note: These tests validate plugin construction (config validation) and
//! credential parsing from the Authorization header. Actual LDAP server
//! interaction is not tested here since it requires a real LDAP server;
//! those scenarios are covered by integration/functional tests.

use ferrum_edge::consumer_index::ConsumerIndex;
use ferrum_edge::plugins::{Plugin, PluginHttpClient, RequestContext, ldap_auth::LdapAuth};
use serde_json::json;

use super::plugin_utils::assert_reject;

fn http_client() -> PluginHttpClient {
    PluginHttpClient::default()
}

fn make_ctx() -> RequestContext {
    RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/test".to_string(),
    )
}

fn basic_header(user: &str, pass: &str) -> String {
    use base64::Engine;
    let encoded = base64::engine::general_purpose::STANDARD.encode(format!("{}:{}", user, pass));
    format!("Basic {}", encoded)
}

// ─── Config validation tests ─────────────────────────────────────────────

#[test]
fn test_missing_ldap_url_rejected() {
    let result = LdapAuth::new(&json!({}), http_client());
    assert!(result.is_err());
    assert!(result.err().unwrap().contains("ldap_url"));
}

#[test]
fn test_empty_ldap_url_rejected() {
    let result = LdapAuth::new(&json!({ "ldap_url": "" }), http_client());
    assert!(result.is_err());
    assert!(result.err().unwrap().contains("ldap_url"));
}

#[test]
fn test_invalid_ldap_url_scheme_rejected() {
    let result = LdapAuth::new(
        &json!({
            "ldap_url": "http://ldap.example.com",
            "bind_dn_template": "uid={username},ou=users,dc=example,dc=com"
        }),
        http_client(),
    );
    assert!(result.is_err());
    assert!(result.err().unwrap().contains("ldap://"));
}

#[test]
fn test_no_bind_mode_rejected() {
    let result = LdapAuth::new(
        &json!({
            "ldap_url": "ldap://ldap.example.com:389"
        }),
        http_client(),
    );
    assert!(result.is_err());
    assert!(result.err().unwrap().contains("bind_dn_template"));
}

#[test]
fn test_direct_bind_valid() {
    let result = LdapAuth::new(
        &json!({
            "ldap_url": "ldap://ldap.example.com:389",
            "bind_dn_template": "uid={username},ou=users,dc=example,dc=com"
        }),
        http_client(),
    );
    assert!(result.is_ok());
}

#[test]
fn test_ldaps_url_valid() {
    let result = LdapAuth::new(
        &json!({
            "ldap_url": "ldaps://ldap.example.com:636",
            "bind_dn_template": "uid={username},ou=users,dc=example,dc=com"
        }),
        http_client(),
    );
    assert!(result.is_ok());
}

#[test]
fn test_bind_dn_template_missing_placeholder_rejected() {
    let result = LdapAuth::new(
        &json!({
            "ldap_url": "ldap://ldap.example.com:389",
            "bind_dn_template": "uid=admin,ou=users,dc=example,dc=com"
        }),
        http_client(),
    );
    assert!(result.is_err());
    assert!(result.err().unwrap().contains("{username}"));
}

#[test]
fn test_search_then_bind_valid() {
    let result = LdapAuth::new(
        &json!({
            "ldap_url": "ldap://ldap.example.com:389",
            "search_base_dn": "ou=users,dc=example,dc=com",
            "search_filter": "(&(objectClass=person)(uid={username}))",
            "service_account_dn": "cn=admin,dc=example,dc=com",
            "service_account_password": "admin_password"
        }),
        http_client(),
    );
    assert!(result.is_ok());
}

#[test]
fn test_search_bind_without_service_account_rejected() {
    let result = LdapAuth::new(
        &json!({
            "ldap_url": "ldap://ldap.example.com:389",
            "search_base_dn": "ou=users,dc=example,dc=com",
            "search_filter": "(&(objectClass=person)(uid={username}))"
        }),
        http_client(),
    );
    assert!(result.is_err());
    assert!(result.err().unwrap().contains("service_account_dn"));
}

#[test]
fn test_search_filter_missing_placeholder_rejected() {
    let result = LdapAuth::new(
        &json!({
            "ldap_url": "ldap://ldap.example.com:389",
            "search_base_dn": "ou=users,dc=example,dc=com",
            "search_filter": "(&(objectClass=person)(uid=admin))",
            "service_account_dn": "cn=admin,dc=example,dc=com",
            "service_account_password": "admin_password"
        }),
        http_client(),
    );
    assert!(result.is_err());
    assert!(result.err().unwrap().contains("{username}"));
}

#[test]
fn test_starttls_with_ldaps_rejected() {
    let result = LdapAuth::new(
        &json!({
            "ldap_url": "ldaps://ldap.example.com:636",
            "bind_dn_template": "uid={username},ou=users,dc=example,dc=com",
            "starttls": true
        }),
        http_client(),
    );
    assert!(result.is_err());
    assert!(result.err().unwrap().contains("starttls"));
}

#[test]
fn test_starttls_with_ldap_valid() {
    let result = LdapAuth::new(
        &json!({
            "ldap_url": "ldap://ldap.example.com:389",
            "bind_dn_template": "uid={username},ou=users,dc=example,dc=com",
            "starttls": true
        }),
        http_client(),
    );
    assert!(result.is_ok());
}

#[test]
fn test_required_groups_without_group_base_dn_rejected() {
    let result = LdapAuth::new(
        &json!({
            "ldap_url": "ldap://ldap.example.com:389",
            "bind_dn_template": "uid={username},ou=users,dc=example,dc=com",
            "required_groups": ["admins"]
        }),
        http_client(),
    );
    assert!(result.is_err());
    assert!(result.err().unwrap().contains("group_base_dn"));
}

#[test]
fn test_required_groups_with_group_base_dn_valid() {
    let result = LdapAuth::new(
        &json!({
            "ldap_url": "ldap://ldap.example.com:389",
            "bind_dn_template": "uid={username},ou=users,dc=example,dc=com",
            "required_groups": ["admins", "developers"],
            "group_base_dn": "ou=groups,dc=example,dc=com"
        }),
        http_client(),
    );
    assert!(result.is_ok());
}

#[test]
fn test_custom_group_attribute() {
    let plugin = LdapAuth::new(
        &json!({
            "ldap_url": "ldap://ldap.example.com:389",
            "bind_dn_template": "uid={username},ou=users,dc=example,dc=com",
            "required_groups": ["admins"],
            "group_base_dn": "ou=groups,dc=example,dc=com",
            "group_attribute": "sAMAccountName"
        }),
        http_client(),
    );
    assert!(plugin.is_ok());
}

#[test]
fn test_cache_ttl_config() {
    let plugin = LdapAuth::new(
        &json!({
            "ldap_url": "ldap://ldap.example.com:389",
            "bind_dn_template": "uid={username},ou=users,dc=example,dc=com",
            "cache_ttl_seconds": 300
        }),
        http_client(),
    );
    assert!(plugin.is_ok());
}

#[test]
fn test_consumer_mapping_disabled() {
    let plugin = LdapAuth::new(
        &json!({
            "ldap_url": "ldap://ldap.example.com:389",
            "bind_dn_template": "uid={username},ou=users,dc=example,dc=com",
            "consumer_mapping": false
        }),
        http_client(),
    );
    assert!(plugin.is_ok());
}

// ─── Plugin trait tests ──────────────────────────────────────────────────

#[test]
fn test_plugin_name() {
    let plugin = LdapAuth::new(
        &json!({
            "ldap_url": "ldap://ldap.example.com:389",
            "bind_dn_template": "uid={username},ou=users,dc=example,dc=com"
        }),
        http_client(),
    )
    .unwrap();
    assert_eq!(plugin.name(), "ldap_auth");
}

#[test]
fn test_is_auth_plugin() {
    let plugin = LdapAuth::new(
        &json!({
            "ldap_url": "ldap://ldap.example.com:389",
            "bind_dn_template": "uid={username},ou=users,dc=example,dc=com"
        }),
        http_client(),
    )
    .unwrap();
    assert!(plugin.is_auth_plugin());
}

#[test]
fn test_priority() {
    let plugin = LdapAuth::new(
        &json!({
            "ldap_url": "ldap://ldap.example.com:389",
            "bind_dn_template": "uid={username},ou=users,dc=example,dc=com"
        }),
        http_client(),
    )
    .unwrap();
    assert_eq!(plugin.priority(), 1250);
}

// ─── Authenticate credential extraction tests ────────────────────────────
// These test the credential parsing path without requiring an LDAP server.
// The LDAP connection will fail, but we can verify header parsing rejects.

#[tokio::test]
async fn test_missing_authorization_header() {
    let plugin = LdapAuth::new(
        &json!({
            "ldap_url": "ldap://ldap.example.com:389",
            "bind_dn_template": "uid={username},ou=users,dc=example,dc=com"
        }),
        http_client(),
    )
    .unwrap();

    let mut ctx = make_ctx();
    let consumer_index = ConsumerIndex::new(&[]);

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_reject(result, Some(401));
}

#[tokio::test]
async fn test_non_basic_auth_scheme_rejected() {
    let plugin = LdapAuth::new(
        &json!({
            "ldap_url": "ldap://ldap.example.com:389",
            "bind_dn_template": "uid={username},ou=users,dc=example,dc=com"
        }),
        http_client(),
    )
    .unwrap();

    let mut ctx = make_ctx();
    ctx.headers
        .insert("authorization".to_string(), "Bearer some-token".to_string());
    let consumer_index = ConsumerIndex::new(&[]);

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_reject(result, Some(401));
}

#[tokio::test]
async fn test_invalid_base64_rejected() {
    let plugin = LdapAuth::new(
        &json!({
            "ldap_url": "ldap://ldap.example.com:389",
            "bind_dn_template": "uid={username},ou=users,dc=example,dc=com"
        }),
        http_client(),
    )
    .unwrap();

    let mut ctx = make_ctx();
    ctx.headers.insert(
        "authorization".to_string(),
        "Basic !!!invalid!!!".to_string(),
    );
    let consumer_index = ConsumerIndex::new(&[]);

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_reject(result, Some(401));
}

#[tokio::test]
async fn test_missing_colon_in_credentials_rejected() {
    let plugin = LdapAuth::new(
        &json!({
            "ldap_url": "ldap://ldap.example.com:389",
            "bind_dn_template": "uid={username},ou=users,dc=example,dc=com"
        }),
        http_client(),
    )
    .unwrap();

    let mut ctx = make_ctx();
    // Encode "nocolon" without a colon separator
    use base64::Engine;
    let encoded = base64::engine::general_purpose::STANDARD.encode("nocolon");
    ctx.headers
        .insert("authorization".to_string(), format!("Basic {}", encoded));
    let consumer_index = ConsumerIndex::new(&[]);

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_reject(result, Some(401));
}

#[tokio::test]
async fn test_empty_username_rejected() {
    let plugin = LdapAuth::new(
        &json!({
            "ldap_url": "ldap://ldap.example.com:389",
            "bind_dn_template": "uid={username},ou=users,dc=example,dc=com"
        }),
        http_client(),
    )
    .unwrap();

    let mut ctx = make_ctx();
    ctx.headers
        .insert("authorization".to_string(), basic_header("", "password"));
    let consumer_index = ConsumerIndex::new(&[]);

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_reject(result, Some(401));
}

#[tokio::test]
async fn test_ldap_connection_failure_returns_401() {
    // This test verifies that when LDAP is unreachable, we get a 401
    let plugin = LdapAuth::new(
        &json!({
            "ldap_url": "ldap://127.0.0.1:19",
            "bind_dn_template": "uid={username},ou=users,dc=example,dc=com",
            "connect_timeout_seconds": 1
        }),
        http_client(),
    )
    .unwrap();

    let mut ctx = make_ctx();
    ctx.headers.insert(
        "authorization".to_string(),
        basic_header("testuser", "password"),
    );
    let consumer_index = ConsumerIndex::new(&[]);

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_reject(result, Some(401));
}

// ─── AD config combination tests ─────────────────────────────────────────

#[test]
fn test_full_ad_config() {
    let result = LdapAuth::new(
        &json!({
            "ldap_url": "ldaps://dc.contoso.com:636",
            "search_base_dn": "OU=Users,DC=contoso,DC=com",
            "search_filter": "(&(objectClass=user)(sAMAccountName={username}))",
            "service_account_dn": "CN=svc-proxy,OU=ServiceAccounts,DC=contoso,DC=com",
            "service_account_password": "S3cret!",
            "group_base_dn": "OU=Groups,DC=contoso,DC=com",
            "group_filter": "(&(objectClass=group)(member={user_dn}))",
            "required_groups": ["Domain Admins", "Proxy Users"],
            "group_attribute": "cn",
            "cache_ttl_seconds": 300,
            "connect_timeout_seconds": 3,
            "consumer_mapping": true
        }),
        http_client(),
    );
    assert!(result.is_ok());
}

#[test]
fn test_both_bind_modes_accepted() {
    // Config is valid when both bind_dn_template and search config are provided.
    // At runtime, direct bind takes precedence (see authenticate_user logic).
    let result = LdapAuth::new(
        &json!({
            "ldap_url": "ldap://ldap.example.com:389",
            "bind_dn_template": "uid={username},ou=users,dc=example,dc=com",
            "search_base_dn": "ou=users,dc=example,dc=com",
            "search_filter": "(&(objectClass=person)(uid={username}))",
            "service_account_dn": "cn=admin,dc=example,dc=com",
            "service_account_password": "admin_password"
        }),
        http_client(),
    );
    assert!(result.is_ok());
}

// ─── Security plugin registration test ───────────────────────────────────

#[test]
fn test_ldap_auth_is_security_plugin() {
    assert!(ferrum_edge::plugins::is_security_plugin("ldap_auth"));
}

#[test]
fn test_ldap_auth_in_available_plugins() {
    let plugins = ferrum_edge::plugins::available_plugins();
    assert!(plugins.contains(&"ldap_auth"));
}

// ─── LDAP escaping tests ─────────────────────────────────────────────────

use ferrum_edge::plugins::ldap_auth::{escape_dn_value, escape_filter_value};

// ── DN escaping (RFC 4514) ──────────────────────────────────────────

#[test]
fn test_dn_escape_plain_username() {
    assert_eq!(escape_dn_value("alice"), "alice");
}

#[test]
fn test_dn_escape_special_chars() {
    assert_eq!(escape_dn_value("a,b+c\"d"), "a\\,b\\+c\\\"d");
}

#[test]
fn test_dn_escape_backslash_angle_semi() {
    assert_eq!(escape_dn_value("a\\b<c>d;e"), "a\\\\b\\<c\\>d\\;e");
}

#[test]
fn test_dn_escape_leading_space() {
    assert_eq!(escape_dn_value(" alice"), "\\ alice");
}

#[test]
fn test_dn_escape_trailing_space() {
    assert_eq!(escape_dn_value("alice "), "alice\\ ");
}

#[test]
fn test_dn_escape_leading_hash() {
    assert_eq!(escape_dn_value("#alice"), "\\#alice");
}

// ── Filter escaping (RFC 4515) ──────────────────────────────────────

#[test]
fn test_filter_escape_plain_username() {
    assert_eq!(escape_filter_value("alice"), "alice");
}

#[test]
fn test_filter_escape_special_chars() {
    assert_eq!(escape_filter_value("a*b(c)d\\e"), "a\\2ab\\28c\\29d\\5ce");
}

#[test]
fn test_filter_escape_nul() {
    assert_eq!(escape_filter_value("a\0b"), "a\\00b");
}

#[test]
fn test_filter_escape_injection_attempt() {
    // Attacker tries: username = "admin)(objectClass=*"
    let escaped = escape_filter_value("admin)(objectClass=*");
    assert_eq!(escaped, "admin\\29\\28objectClass=\\2a");
}
