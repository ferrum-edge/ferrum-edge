//! Tests for ldap_auth plugin — config validation and credential extraction.
//!
//! The protocol-mock tests below also exercise bind, search-then-bind, and
//! group-authorization behavior through the public plugin interface. Live
//! directory behavior is covered by the LDAP service-integration suite.

use ferrum_edge::config::{BackendAllowIps, BackendEgressPolicy, PoolConfig};
use ferrum_edge::consumer_index::ConsumerIndex;
use ferrum_edge::dns::{DnsCache, DnsConfig};
use ferrum_edge::plugins::{
    HTTP_FAMILY_PROTOCOLS, Plugin, PluginHttpClient, PluginResult, RequestContext,
    ldap_auth::{LDAP_AUTH_MAX_CACHE_TTL_SECONDS, LdapAuth},
    priority,
};
use hickory_resolver::proto::{
    op::Message,
    rr::{RData, Record, RecordType},
};
use serde_json::json;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{
    Arc, RwLock,
    atomic::{AtomicUsize, Ordering},
};
use std::time::Duration;

use super::plugin_utils::{
    assert_continue, assert_reject, assert_reject_body, context_with_materialized_raw_header,
};

fn http_client() -> PluginHttpClient {
    PluginHttpClient::default()
}

fn production_egress_policy() -> BackendEgressPolicy {
    BackendEgressPolicy::from_allow_ips(BackendAllowIps::Both)
}

fn http_client_with_dns(
    resolver_addr: SocketAddr,
    policy: BackendEgressPolicy,
    ca_bundle_path: Option<&str>,
) -> PluginHttpClient {
    http_client_with_dns_config(
        DnsConfig {
            resolver_addresses: Some(resolver_addr.to_string()),
            try_tcp_on_error: false,
            ..DnsConfig::default()
        },
        policy,
        ca_bundle_path,
    )
}

fn http_client_with_dns_config(
    mut config: DnsConfig,
    policy: BackendEgressPolicy,
    ca_bundle_path: Option<&str>,
) -> PluginHttpClient {
    config.backend_allow_ips = policy.clone();
    let dns_cache = DnsCache::new(config);
    PluginHttpClient::new(
        &PoolConfig::default(),
        dns_cache,
        1_000,
        0,
        100,
        false,
        ca_bundle_path,
        Arc::new(Vec::new()),
        "default",
        policy,
        Arc::new(Vec::new()),
        0,
    )
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
fn test_invalid_config_types_rejected() {
    let invalid_configs = [
        json!(null),
        json!(""),
        json!({
            "ldap_url": 123,
            "bind_dn_template": "uid={username},ou=users,dc=example,dc=com",
            "canonical_identity_attribute": "uid"
        }),
        json!({
            "ldap_url": "ldaps://ldap.example.com:636",
            "bind_dn_template": 123
        }),
        json!({
            "ldap_url": "ldaps://ldap.example.com:636",
            "bind_dn_template": "uid={username},ou=users,dc=example,dc=com",
            "canonical_identity_attribute": "uid",
            "starttls": "yes"
        }),
        json!({
            "ldap_url": "ldaps://ldap.example.com:636",
            "bind_dn_template": "uid={username},ou=users,dc=example,dc=com",
            "canonical_identity_attribute": "uid",
            "required_groups": "admins"
        }),
        json!({
            "ldap_url": "ldaps://ldap.example.com:636",
            "bind_dn_template": "uid={username},ou=users,dc=example,dc=com",
            "canonical_identity_attribute": "uid",
            "connect_timeout_seconds": 0
        }),
        json!({
            "ldap_url": "ldaps://ldap.example.com:636",
            "bind_dn_template": "uid={username},ou=users,dc=example,dc=com",
            "canonical_identity_attribute": "uid",
            "max_cache_entries": 0
        }),
    ];

    for config in invalid_configs {
        assert!(
            LdapAuth::new(&config, http_client()).is_err(),
            "config should be rejected: {config}"
        );
    }
}

#[test]
fn test_invalid_ldap_url_scheme_rejected() {
    let result = LdapAuth::new(
        &json!({
            "ldap_url": "http://ldap.example.com",
            "bind_dn_template": "uid={username},ou=users,dc=example,dc=com",
            "canonical_identity_attribute": "uid"
        }),
        http_client(),
    );
    assert!(result.is_err());
    assert!(result.err().unwrap().contains("ldap://"));
}

#[test]
fn test_malformed_ldap_url_rejected() {
    let result = LdapAuth::new(
        &json!({
            "ldap_url": "ldap://[not-ipv6",
            "bind_dn_template": "uid={username},ou=users,dc=example,dc=com",
            "canonical_identity_attribute": "uid"
        }),
        http_client(),
    );
    assert!(result.is_err());
    assert!(result.err().unwrap().contains("valid URL"));
}

#[test]
fn test_ldap_url_empty_authority_rejected() {
    let result = LdapAuth::new(
        &json!({
            "ldap_url": "ldap:///dc=example,dc=com",
            "bind_dn_template": "uid={username},ou=users,dc=example,dc=com",
            "canonical_identity_attribute": "uid"
        }),
        http_client(),
    );
    assert!(result.is_err());
    assert!(result.err().unwrap().contains("hostname"));
}

#[test]
fn test_no_bind_mode_rejected() {
    let result = LdapAuth::new(
        &json!({
            "ldap_url": "ldaps://ldap.example.com:636"
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
            "ldap_url": "ldaps://ldap.example.com:636",
            "bind_dn_template": "uid={username},ou=users,dc=example,dc=com",
            "canonical_identity_attribute": "uid"
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
            "bind_dn_template": "uid={username},ou=users,dc=example,dc=com",
            "canonical_identity_attribute": "uid"
        }),
        http_client(),
    );
    assert!(result.is_ok());
}

#[test]
fn test_bind_dn_template_missing_placeholder_rejected() {
    let result = LdapAuth::new(
        &json!({
            "ldap_url": "ldaps://ldap.example.com:636",
            "bind_dn_template": "uid=admin,ou=users,dc=example,dc=com",
            "canonical_identity_attribute": "uid"
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
            "ldap_url": "ldaps://ldap.example.com:636",
            "search_base_dn": "ou=users,dc=example,dc=com",
            "search_filter": "(&(objectClass=person)(uid={username}))",
            "canonical_identity_attribute": "uid",
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
            "ldap_url": "ldaps://ldap.example.com:636",
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
            "ldap_url": "ldaps://ldap.example.com:636",
            "search_base_dn": "ou=users,dc=example,dc=com",
            "search_filter": "(&(objectClass=person)(uid=admin))",
            "canonical_identity_attribute": "uid",
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
            "canonical_identity_attribute": "uid",
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
            "canonical_identity_attribute": "uid",
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
            "ldap_url": "ldaps://ldap.example.com:636",
            "bind_dn_template": "uid={username},ou=users,dc=example,dc=com",
            "canonical_identity_attribute": "uid",
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
            "ldap_url": "ldaps://ldap.example.com:636",
            "bind_dn_template": "uid={username},ou=users,dc=example,dc=com",
            "canonical_identity_attribute": "uid",
            "required_groups": ["admins", "developers"],
            "group_base_dn": "ou=groups,dc=example,dc=com"
        }),
        http_client(),
    );
    assert!(result.is_ok());
}

#[test]
fn test_required_groups_direct_bind_without_service_account_accepted() {
    // Finding #33: direct-bind + required_groups with no service account is a
    // footgun (the group search falls back to an ANONYMOUS bind, which many
    // directories restrict). The plugin emits a startup warning but does NOT
    // reject the config — anonymous group search is legitimate on directories
    // that permit it, so failing construction would break valid deployments.
    let result = LdapAuth::new(
        &json!({
            "ldap_url": "ldaps://ldap.example.com:636",
            "bind_dn_template": "uid={username},ou=users,dc=example,dc=com",
            "canonical_identity_attribute": "uid",
            "required_groups": ["admins"],
            "group_base_dn": "ou=groups,dc=example,dc=com"
        }),
        http_client(),
    );
    assert!(
        result.is_ok(),
        "direct-bind + required_groups without a service account must remain a \
         valid (warned) config, not a hard error"
    );
}

#[test]
fn test_required_groups_with_service_account_accepted() {
    // The recommended configuration: a service account is supplied for the
    // group-membership search, so no anonymous bind is used.
    let result = LdapAuth::new(
        &json!({
            "ldap_url": "ldaps://ldap.example.com:636",
            "bind_dn_template": "uid={username},ou=users,dc=example,dc=com",
            "canonical_identity_attribute": "uid",
            "required_groups": ["admins"],
            "group_base_dn": "ou=groups,dc=example,dc=com",
            "service_account_dn": "cn=admin,dc=example,dc=com",
            "service_account_password": "admin_password"
        }),
        http_client(),
    );
    assert!(result.is_ok());
}

#[test]
fn test_custom_group_attribute() {
    let plugin = LdapAuth::new(
        &json!({
            "ldap_url": "ldaps://ldap.example.com:636",
            "bind_dn_template": "uid={username},ou=users,dc=example,dc=com",
            "canonical_identity_attribute": "uid",
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
            "ldap_url": "ldaps://ldap.example.com:636",
            "bind_dn_template": "uid={username},ou=users,dc=example,dc=com",
            "canonical_identity_attribute": "uid",
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
            "ldap_url": "ldaps://ldap.example.com:636",
            "bind_dn_template": "uid={username},ou=users,dc=example,dc=com",
            "canonical_identity_attribute": "uid",
            "consumer_mapping": false
        }),
        http_client(),
    );
    assert!(plugin.is_ok());
}

#[test]
fn test_unknown_config_key_rejected() {
    let error = LdapAuth::new(
        &json!({
            "ldap_url": "ldaps://ldap.example.com:636",
            "bind_dn_template": "uid={username},ou=users,dc=example,dc=com",
            "canonical_identity_attribute": "uid",
            "required_group": ["admins"]
        }),
        http_client(),
    )
    .err()
    .expect("misspelled authorization key must fail closed");

    assert!(
        error.contains("unknown config key 'required_group'"),
        "{error}"
    );
}

#[test]
fn test_static_custom_group_filter_rejected() {
    let error = LdapAuth::new(
        &json!({
            "ldap_url": "ldaps://ldap.example.com:636",
            "bind_dn_template": "uid={username},ou=users,dc=example,dc=com",
            "canonical_identity_attribute": "uid",
            "group_base_dn": "ou=groups,dc=example,dc=com",
            "group_filter": "(cn=admins)",
            "required_groups": ["admins"]
        }),
        http_client(),
    )
    .err()
    .expect("static group filter must not authorize every bound user");

    assert!(
        error.contains("{user_dn}") && error.contains("{username}"),
        "{error}"
    );
}

#[test]
fn test_user_specific_custom_group_filters_accepted() {
    for group_filter in [
        "(&(objectClass=group)(member={user_dn}))",
        "(&(objectClass=posixGroup)(memberUid={username}))",
    ] {
        let result = LdapAuth::new(
            &json!({
                "ldap_url": "ldaps://ldap.example.com:636",
                "bind_dn_template": "uid={username},ou=users,dc=example,dc=com",
                "canonical_identity_attribute": "uid",
                "group_base_dn": "ou=groups,dc=example,dc=com",
                "group_filter": group_filter,
                "required_groups": ["admins"]
            }),
            http_client(),
        );
        assert!(
            result.is_ok(),
            "user-specific filter should be valid: {:?}",
            result.err()
        );
    }
}

#[test]
fn test_search_bind_requires_canonical_identity_attribute() {
    let error = LdapAuth::new(
        &json!({
            "ldap_url": "ldaps://ldap.example.com:636",
            "search_base_dn": "ou=users,dc=example,dc=com",
            "search_filter": "(uid={username})",
            "service_account_dn": "cn=admin,dc=example,dc=com",
            "service_account_password": "admin-password"
        }),
        http_client(),
    )
    .err()
    .expect("search bind without a canonical identity must fail closed");

    assert!(error.contains("canonical_identity_attribute"), "{error}");
}

#[test]
fn test_cache_ttl_maximum_boundary() {
    let at_max = LdapAuth::new(
        &json!({
            "ldap_url": "ldaps://ldap.example.com:636",
            "bind_dn_template": "uid={username},ou=users,dc=example,dc=com",
            "canonical_identity_attribute": "uid",
            "cache_ttl_seconds": LDAP_AUTH_MAX_CACHE_TTL_SECONDS
        }),
        http_client(),
    );
    assert!(
        at_max.is_ok(),
        "documented maximum should be accepted: {:?}",
        at_max.err()
    );

    let above_max = LdapAuth::new(
        &json!({
            "ldap_url": "ldaps://ldap.example.com:636",
            "bind_dn_template": "uid={username},ou=users,dc=example,dc=com",
            "canonical_identity_attribute": "uid",
            "cache_ttl_seconds": LDAP_AUTH_MAX_CACHE_TTL_SECONDS + 1
        }),
        http_client(),
    )
    .err()
    .expect("TTL above maximum must be rejected");
    assert!(above_max.contains("cache_ttl_seconds"), "{above_max}");

    let hostile = LdapAuth::new(
        &json!({
            "ldap_url": "ldaps://ldap.example.com:636",
            "bind_dn_template": "uid={username},ou=users,dc=example,dc=com",
            "canonical_identity_attribute": "uid",
            "cache_ttl_seconds": u64::MAX
        }),
        http_client(),
    )
    .err()
    .expect("unrepresentable cache expiry must be rejected at construction");
    assert!(hostile.contains("cache_ttl_seconds"), "{hostile}");
}

#[test]
fn test_ldap_resource_boundaries_rejected() {
    for (field, value) in [
        ("connect_timeout_seconds", json!(301)),
        ("request_timeout_seconds", json!(0)),
        ("request_timeout_seconds", json!(301)),
        ("max_concurrent_requests", json!(0)),
        ("max_concurrent_requests", json!(1025)),
    ] {
        let mut config = json!({
            "ldap_url": "ldaps://ldap.example.com:636",
            "bind_dn_template": "uid={username},ou=users,dc=example,dc=com",
            "canonical_identity_attribute": "uid"
        });
        config[field] = value;
        let error = LdapAuth::new(&config, http_client())
            .err()
            .expect("out-of-range resource bound must be rejected");
        assert!(error.contains(field), "{field}: {error}");
    }
}

#[test]
fn test_remote_plaintext_ldap_requires_explicit_opt_in() {
    let config = json!({
        "ldap_url": "ldap://directory.example.test:389",
        "bind_dn_template": "uid={username},ou=users,dc=example,dc=test",
        "canonical_identity_attribute": "uid"
    });
    let error = LdapAuth::new(&config, http_client())
        .err()
        .expect("remote plaintext LDAP must be rejected by default");
    assert!(
        error.contains("STARTTLS") && error.contains("allow_plaintext"),
        "{error}"
    );

    let mut opted_in = config;
    opted_in["allow_plaintext"] = json!(true);
    assert!(LdapAuth::new(&opted_in, http_client()).is_ok());
}

#[test]
fn test_loopback_plaintext_ldap_remains_available_for_local_testing() {
    for ldap_url in [
        "ldap://127.0.0.1:389",
        "ldap://[::1]:389",
        "ldap://localhost:389",
    ] {
        let result = LdapAuth::new(
            &json!({
                "ldap_url": ldap_url,
                "bind_dn_template": "uid={username},ou=users,dc=example,dc=com",
                "canonical_identity_attribute": "uid"
            }),
            http_client(),
        );
        assert!(
            result.is_ok(),
            "loopback URL should be accepted: {ldap_url}"
        );
    }
}

#[test]
fn test_embedded_ldap_url_credentials_rejected() {
    let error = LdapAuth::new(
        &json!({
            "ldap_url": "ldaps://admin:secret@ldap.example.com:636",
            "bind_dn_template": "uid={username},ou=users,dc=example,dc=com",
            "canonical_identity_attribute": "uid"
        }),
        http_client(),
    )
    .err()
    .expect("embedded URL credentials must be rejected");
    assert!(error.contains("embedded credentials"), "{error}");
    assert!(
        !error.contains("secret@"),
        "secret leaked in error: {error}"
    );
}

#[test]
fn test_malformed_service_account_password_errors_are_redacted() {
    for malformed in [
        json!({"value": "never-log-object-secret"}),
        json!(["never-log-array-secret"]),
        json!(123456789),
        json!(null),
    ] {
        let error = LdapAuth::new(
            &json!({
                "ldap_url": "ldaps://ldap.example.com:636",
                "bind_dn_template": "uid={username},ou=users,dc=example,dc=com",
                "canonical_identity_attribute": "uid",
                "service_account_password": malformed
            }),
            http_client(),
        )
        .err()
        .expect("non-string service account password must be rejected");

        assert!(error.contains("service_account_password"), "{error}");
        assert!(
            !error.contains("never-log"),
            "secret leaked in error: {error}"
        );
        assert!(
            !error.contains("123456789"),
            "secret-like value leaked in error: {error}"
        );
    }
}

// ─── Plugin trait tests ──────────────────────────────────────────────────

#[test]
fn test_plugin_name() {
    let plugin = LdapAuth::new(
        &json!({
            "ldap_url": "ldaps://ldap.example.com:636",
            "bind_dn_template": "uid={username},ou=users,dc=example,dc=com",
            "canonical_identity_attribute": "uid"
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
            "ldap_url": "ldaps://ldap.example.com:636",
            "bind_dn_template": "uid={username},ou=users,dc=example,dc=com",
            "canonical_identity_attribute": "uid"
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
            "ldap_url": "ldaps://ldap.example.com:636",
            "bind_dn_template": "uid={username},ou=users,dc=example,dc=com",
            "canonical_identity_attribute": "uid"
        }),
        http_client(),
    )
    .unwrap();
    assert_eq!(plugin.priority(), priority::LDAP_AUTH);
    assert_eq!(plugin.priority(), 1250);
}

#[test]
fn test_ldap_auth_plugin_contract() {
    let plugin = LdapAuth::new(
        &json!({
            "ldap_url": "ldaps://ldap.example.com:636",
            "bind_dn_template": "uid={username},ou=users,dc=example,dc=com",
            "canonical_identity_attribute": "uid"
        }),
        http_client(),
    )
    .unwrap();

    assert_eq!(plugin.supported_protocols(), HTTP_FAMILY_PROTOCOLS);
    assert!(plugin.is_auth_plugin());
    // `hide_credentials` defaults to true, so the Basic credential is removed
    // from the backend request in `before_proxy`.
    assert!(plugin.modifies_request_headers());
    assert!(!plugin.modifies_request_body());
    assert!(!plugin.requires_request_body_before_before_proxy());
    assert!(!plugin.requires_request_body_before_authenticate());
    assert!(!plugin.needs_request_body_bytes());
    assert!(!plugin.requires_request_body_buffering());
    assert!(!plugin.requires_response_body_buffering());
    assert!(!plugin.applies_after_proxy_on_reject());
}

#[test]
fn test_warmup_hostnames_ldap() {
    let plugin = LdapAuth::new(
        &json!({
            "ldap_url": "ldap://ldap.example.com:389",
            "bind_dn_template": "uid={username},ou=users,dc=example,dc=com",
            "canonical_identity_attribute": "uid",
            "allow_plaintext": true
        }),
        http_client(),
    )
    .unwrap();
    assert_eq!(plugin.warmup_hostnames(), vec!["ldap.example.com"]);
}

#[test]
fn test_warmup_hostnames_ldaps() {
    let plugin = LdapAuth::new(
        &json!({
            "ldap_url": "ldaps://secure-ldap.corp.internal:636",
            "bind_dn_template": "uid={username},ou=users,dc=corp,dc=internal",
            "canonical_identity_attribute": "uid"
        }),
        http_client(),
    )
    .unwrap();
    assert_eq!(plugin.warmup_hostnames(), vec!["secure-ldap.corp.internal"]);
}

#[test]
fn test_warmup_hostnames_unbrackets_ipv6_ldap_url() {
    let plugin = LdapAuth::new(
        &json!({
            "ldap_url": "ldaps://[2001:db8::50]:636",
            "bind_dn_template": "uid={username},ou=users,dc=example,dc=com",
            "canonical_identity_attribute": "uid"
        }),
        http_client(),
    )
    .unwrap();

    assert_eq!(plugin.warmup_hostnames(), vec!["2001:db8::50"]);
}

// ─── Authenticate credential extraction tests ────────────────────────────
// These test the credential parsing path without requiring an LDAP server.
// The LDAP connection will fail, but we can verify header parsing rejects.

#[tokio::test]
async fn test_missing_authorization_header() {
    let plugin = LdapAuth::new(
        &json!({
            "ldap_url": "ldaps://ldap.example.com:636",
            "bind_dn_template": "uid={username},ou=users,dc=example,dc=com",
            "canonical_identity_attribute": "uid"
        }),
        http_client(),
    )
    .unwrap();

    let mut ctx = make_ctx();
    let consumer_index = ConsumerIndex::new(&[]);

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_continue(result);
    assert!(ctx.identified_consumer.is_none());
    assert!(ctx.authenticated_identity.is_none());
    assert!(ctx.authenticated_identity_header.is_none());
}

#[tokio::test]
async fn test_non_basic_auth_scheme_rejected() {
    let plugin = LdapAuth::new(
        &json!({
            "ldap_url": "ldaps://ldap.example.com:636",
            "bind_dn_template": "uid={username},ou=users,dc=example,dc=com",
            "canonical_identity_attribute": "uid"
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
            "ldap_url": "ldaps://ldap.example.com:636",
            "bind_dn_template": "uid={username},ou=users,dc=example,dc=com",
            "canonical_identity_attribute": "uid"
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
            "ldap_url": "ldaps://ldap.example.com:636",
            "bind_dn_template": "uid={username},ou=users,dc=example,dc=com",
            "canonical_identity_attribute": "uid"
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
            "ldap_url": "ldaps://ldap.example.com:636",
            "bind_dn_template": "uid={username},ou=users,dc=example,dc=com",
            "canonical_identity_attribute": "uid"
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
async fn test_empty_password_rejected_without_contacting_ldap() {
    // RFC 4513 §5.1.2: simple bind with empty password is treated as an
    // unauthenticated bind by many directories (notably Active Directory),
    // and would silently succeed for any username. The plugin must reject
    // empty passwords up front, before they reach the server.
    //
    // Point at a guaranteed-closed loopback port rather than a public DNS
    // name — sandboxed CI runners may have no DNS, and a slow resolver
    // could make this test flaky even when the short-circuit works. A
    // closed loopback port gives immediate connection refusal if the
    // plugin ever regressed and actually attempted a bind.
    let plugin = LdapAuth::new(
        &json!({
            "ldap_url": "ldap://127.0.0.1:1",
            "bind_dn_template": "uid={username},ou=users,dc=example,dc=com",
            "canonical_identity_attribute": "uid"
        }),
        http_client(),
    )
    .unwrap();

    let mut ctx = make_ctx();
    ctx.headers
        .insert("authorization".to_string(), basic_header("alice", ""));
    let consumer_index = ConsumerIndex::new(&[]);

    // The test should complete quickly (no LDAP roundtrip).
    let start = std::time::Instant::now();
    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_reject(result, Some(401));
    assert!(
        start.elapsed() < std::time::Duration::from_millis(500),
        "Empty-password rejection must short-circuit before contacting LDAP"
    );
}

/// Canonical identity the direct-bind mock servers report for the bound entry.
/// Direct bind never exports the presented login, so successful mock flows land
/// on this value regardless of how the client spelled its username.
const DIRECT_BIND_CANONICAL_IDENTITY: &str = "canonical-alice";

/// Answer the base-scope search that direct bind issues on the bound DN to read
/// `canonical_identity_attribute`. ldap3 numbers it message ID 2 on a
/// connection whose bind was message ID 1.
async fn answer_canonical_identity_search<S>(stream: &mut S)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::AsyncWriteExt;

    if try_read_ldap_message_bytes(stream).await.is_err() {
        return;
    }
    let _ = stream
        .write_all(&search_result_entry(
            2,
            "uid=canonical-alice,ou=users,dc=example,dc=com",
            &[("uid", &[DIRECT_BIND_CANONICAL_IDENTITY])],
        ))
        .await;
    let _ = stream.write_all(&search_result_done(2, 0)).await;
    let _ = stream.flush().await;
}

/// Minimal mock LDAP server: accepts one TCP connection, reads the client's
/// first request (the simple bind), and replies with a `bindResponse` carrying
/// the provided `resultCode`. ldap3 assigns message ID 1 to the first operation
/// on a fresh connection, so the response is encoded at message ID 1.
///
/// LDAPMessage ::= SEQUENCE { messageID INTEGER (1), BindResponse }
/// BindResponse ::= [APPLICATION 1] SEQUENCE { resultCode ENUMERATED,
///                                             matchedDN "", diagnosticMessage "" }
async fn spawn_bind_response_ldap_server(result_code: u8) -> (u16, tokio::task::JoinHandle<()>) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind mock LDAP server");
    let port = listener.local_addr().expect("mock LDAP local addr").port();

    let task = tokio::spawn(async move {
        if let Ok((mut stream, _)) = listener.accept().await {
            // Drain the bind request so ldap3 doesn't see a half-open peer.
            let mut buf = [0u8; 1024];
            let _ = stream.read(&mut buf).await;

            // bindResponse, messageID 1, caller-provided resultCode.
            let response: [u8; 14] = [
                0x30,
                0x0c, // LDAPMessage SEQUENCE, len 12
                0x02,
                0x01,
                0x01, // messageID INTEGER 1
                0x61,
                0x07, // [APPLICATION 1] BindResponse, len 7
                0x0a,
                0x01,
                result_code, // resultCode ENUMERATED
                0x04,
                0x00, // matchedDN ""
                0x04,
                0x00, // diagnosticMessage ""
            ];
            let _ = stream.write_all(&response).await;
            let _ = stream.flush().await;
            if result_code == 0 {
                answer_canonical_identity_search(&mut stream).await;
            }
            // Hold the connection briefly so the client reads the response
            // before the socket is torn down.
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        }
    });

    (port, task)
}

#[derive(Clone)]
enum TestDnsAnswers {
    Addresses(Vec<IpAddr>),
    DropQueries,
}

struct TestDnsServer {
    addr: SocketAddr,
    answers: Arc<RwLock<TestDnsAnswers>>,
    query_count: Arc<AtomicUsize>,
    task: tokio::task::JoinHandle<()>,
}

impl TestDnsServer {
    async fn spawn(initial_answers: Vec<IpAddr>) -> Self {
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("bind test DNS server");
        let addr = socket.local_addr().expect("test DNS server address");
        let answers = Arc::new(RwLock::new(TestDnsAnswers::Addresses(initial_answers)));
        let query_count = Arc::new(AtomicUsize::new(0));
        let task_answers = Arc::clone(&answers);
        let task_query_count = Arc::clone(&query_count);
        let task = tokio::spawn(async move {
            let mut buffer = [0u8; 2_048];
            loop {
                let Ok((length, peer)) = socket.recv_from(&mut buffer).await else {
                    break;
                };
                let Ok(request) = Message::from_vec(&buffer[..length]) else {
                    continue;
                };
                let Some(query) = request.queries.first().cloned() else {
                    continue;
                };
                task_query_count.fetch_add(1, Ordering::Relaxed);
                let current_answers = task_answers.read().expect("read test DNS answers").clone();
                let TestDnsAnswers::Addresses(addresses) = current_answers else {
                    continue;
                };

                let mut response = request.into_response();
                for address in addresses {
                    let data = match (query.query_type(), address) {
                        (RecordType::A, IpAddr::V4(address)) => RData::A(address.into()),
                        (RecordType::AAAA, IpAddr::V6(address)) => RData::AAAA(address.into()),
                        _ => continue,
                    };
                    response.add_answer(Record::from_rdata(query.name().clone(), 1, data));
                }
                let Ok(encoded) = response.to_vec() else {
                    continue;
                };
                let _ = socket.send_to(&encoded, peer).await;
            }
        });

        Self {
            addr,
            answers,
            query_count,
            task,
        }
    }

    fn set_answers(&self, answers: TestDnsAnswers) {
        *self.answers.write().expect("write test DNS answers") = answers;
    }

    fn queries(&self) -> usize {
        self.query_count.load(Ordering::Relaxed)
    }
}

impl Drop for TestDnsServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn spawn_bind_response_ldap_server_at(
    bind_addr: SocketAddr,
    result_code: u8,
) -> (u16, tokio::task::JoinHandle<()>) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    let listener = TcpListener::bind(bind_addr)
        .await
        .expect("bind address-specific LDAP server");
    let port = listener
        .local_addr()
        .expect("address-specific LDAP local addr")
        .port();
    let task = tokio::spawn(async move {
        if let Ok((mut stream, _)) = listener.accept().await {
            let mut buffer = [0u8; 1_024];
            let _ = stream.read(&mut buffer).await;
            let _ = stream.write_all(&bind_response(1, result_code)).await;
            if result_code == 0 {
                answer_canonical_identity_search(&mut stream).await;
            }
        }
    });
    (port, task)
}

fn assert_backend_rejection_hides_credentials(result: PluginResult, credentials: &[&str]) {
    match result {
        PluginResult::Reject {
            status_code, body, ..
        } => {
            assert_eq!(status_code, 500);
            assert_eq!(
                body,
                r#"{"error":"LDAP authentication temporarily unavailable"}"#
            );
            for credential in credentials {
                assert!(
                    !body.contains(credential),
                    "LDAP backend response exposed a bind credential"
                );
            }
        }
        other => panic!("expected LDAP backend rejection, got {other:?}"),
    }
}

#[tokio::test]
async fn test_direct_bind_dials_fresh_screened_ipv4_answer() {
    let (port, ldap_task) = spawn_bind_response_ldap_server(0).await;
    let dns = TestDnsServer::spawn(vec![IpAddr::V4(Ipv4Addr::LOCALHOST)]).await;
    let plugin = LdapAuth::new(
        &json!({
            "ldap_url": format!("ldap://directory.test:{port}"),
            "bind_dn_template": "uid={username},ou=users,dc=example,dc=com",
            "canonical_identity_attribute": "uid",
            "allow_plaintext": true,
            "consumer_mapping": false
        }),
        http_client_with_dns(dns.addr, production_egress_policy(), None),
    )
    .expect("valid hostname direct-bind config");
    let mut ctx = make_ctx();
    ctx.headers.insert(
        "authorization".to_string(),
        basic_header("alice", "user-secret"),
    );

    let result = plugin
        .authenticate(&mut ctx, &ConsumerIndex::new(&[]))
        .await;
    assert_continue(result);
    assert!(dns.queries() >= 2, "dial lookup must query A and AAAA");
    ldap_task.await.expect("IPv4 LDAP bind server");
}

#[tokio::test]
async fn test_direct_bind_dials_fresh_screened_ipv6_answer() {
    let (port, ldap_task) =
        spawn_bind_response_ldap_server_at(SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 0), 0)
            .await;
    let dns = TestDnsServer::spawn(vec![IpAddr::V6(Ipv6Addr::LOCALHOST)]).await;
    let plugin = LdapAuth::new(
        &json!({
            "ldap_url": format!("ldap://directory.test:{port}"),
            "bind_dn_template": "uid={username},ou=users,dc=example,dc=com",
            "canonical_identity_attribute": "uid",
            "allow_plaintext": true,
            "consumer_mapping": false
        }),
        http_client_with_dns(dns.addr, production_egress_policy(), None),
    )
    .expect("valid IPv6 hostname direct-bind config");
    let mut ctx = make_ctx();
    ctx.headers.insert(
        "authorization".to_string(),
        basic_header("alice", "user-secret"),
    );

    let result = plugin
        .authenticate(&mut ctx, &ConsumerIndex::new(&[]))
        .await;
    assert_continue(result);
    ldap_task.await.expect("IPv6 LDAP bind server");
}

#[tokio::test]
async fn test_mixed_ipv4_ipv6_answer_fails_before_any_starttls_dial() {
    use tokio::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind mixed-answer LDAP sentinel");
    let port = listener
        .local_addr()
        .expect("mixed-answer LDAP addr")
        .port();
    let dns = TestDnsServer::spawn(vec![
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        "fe80::1".parse().expect("link-local IPv6"),
    ])
    .await;
    let plugin = LdapAuth::new(
        &json!({
            "ldap_url": format!("ldap://directory.test:{port}"),
            "bind_dn_template": "uid={username},ou=users,dc=example,dc=com",
            "canonical_identity_attribute": "uid",
            "starttls": true,
            "connect_timeout_seconds": 1
        }),
        http_client_with_dns(dns.addr, production_egress_policy(), None),
    )
    .expect("valid STARTTLS config");
    let mut ctx = make_ctx();
    ctx.headers.insert(
        "authorization".to_string(),
        basic_header("alice", "user-secret"),
    );

    let result = plugin
        .authenticate(&mut ctx, &ConsumerIndex::new(&[]))
        .await;
    assert_backend_rejection_hides_credentials(result, &["user-secret"]);
    assert!(
        tokio::time::timeout(Duration::from_millis(300), listener.accept())
            .await
            .is_err(),
        "an allowed decoy must not be dialed when any answer is denied"
    );
}

#[tokio::test]
async fn test_search_bind_re_resolves_and_blocks_denied_rebind() {
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind rebinding LDAP server");
    let port = listener.local_addr().expect("rebinding LDAP addr").port();
    let dns = TestDnsServer::spawn(vec![IpAddr::V4(Ipv4Addr::LOCALHOST)]).await;
    let answer_state = Arc::clone(&dns.answers);
    let ldap_task = tokio::spawn(async move {
        let (mut service_stream, _) = listener.accept().await.expect("accept service bind");
        read_ldap_message(&mut service_stream).await;
        service_stream
            .write_all(&bind_response(1, 0))
            .await
            .expect("write service bind response");
        read_ldap_message(&mut service_stream).await;
        service_stream
            .write_all(&search_result_entry(
                2,
                "uid=alice,ou=users,dc=example,dc=com",
                &[("uid", &["alice"])],
            ))
            .await
            .expect("write search entry");
        *answer_state.write().expect("write rebound DNS answer") =
            TestDnsAnswers::Addresses(vec!["169.254.169.254".parse().expect("metadata IP")]);
        service_stream
            .write_all(&search_result_done(2, 0))
            .await
            .expect("write search completion");
        drop(service_stream);

        assert!(
            tokio::time::timeout(Duration::from_millis(500), listener.accept())
                .await
                .is_err(),
            "the post-search user bind must not reach the original LDAP listener"
        );
    });
    let plugin = LdapAuth::new(
        &json!({
            "ldap_url": format!("ldap://directory.test:{port}"),
            "search_base_dn": "ou=users,dc=example,dc=com",
            "search_filter": "(uid={username})",
            "canonical_identity_attribute": "uid",
            "service_account_dn": "cn=admin,dc=example,dc=com",
            "service_account_password": "service-secret",
            "allow_plaintext": true,
            "connect_timeout_seconds": 1
        }),
        http_client_with_dns(dns.addr, production_egress_policy(), None),
    )
    .expect("valid rebinding search-bind config");
    let mut ctx = make_ctx();
    ctx.headers.insert(
        "authorization".to_string(),
        basic_header("alice", "user-secret"),
    );

    let result = plugin
        .authenticate(&mut ctx, &ConsumerIndex::new(&[]))
        .await;
    assert_backend_rejection_hides_credentials(result, &["service-secret", "user-secret"]);
    assert!(
        dns.queries() >= 4,
        "service and user connections must each issue fresh A/AAAA lookups"
    );
    ldap_task.await.expect("rebinding LDAP server");
}

#[tokio::test]
async fn test_literal_denial_is_enforced_at_dial_time() {
    let plugin = LdapAuth::new(
        &json!({
            "ldap_url": "ldap://169.254.169.254:389",
            "bind_dn_template": "uid={username},ou=users,dc=example,dc=com",
            "canonical_identity_attribute": "uid",
            "allow_plaintext": true,
            "connect_timeout_seconds": 1
        }),
        PluginHttpClient::default_with_backend_allow_ips(production_egress_policy()),
    )
    .expect("literal endpoint reaches runtime policy backstop");
    let mut ctx = make_ctx();
    ctx.headers.insert(
        "authorization".to_string(),
        basic_header("alice", "literal-secret"),
    );

    let result = plugin
        .authenticate(&mut ctx, &ConsumerIndex::new(&[]))
        .await;
    assert_backend_rejection_hides_credentials(result, &["literal-secret"]);
}

#[tokio::test]
async fn test_plaintext_localhost_exception_rejects_non_loopback_override() {
    use std::collections::HashMap;
    use tokio::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind plaintext-loopback sentinel");
    let port = listener
        .local_addr()
        .expect("plaintext-loopback sentinel addr")
        .port();
    let plugin = LdapAuth::new(
        &json!({
            "ldap_url": format!("ldap://localhost:{port}"),
            "bind_dn_template": "uid={username},ou=users,dc=example,dc=com",
            "canonical_identity_attribute": "uid",
            "connect_timeout_seconds": 1
        }),
        http_client_with_dns_config(
            DnsConfig {
                global_overrides: HashMap::from([("localhost".to_string(), "0.0.0.0".to_string())]),
                ..DnsConfig::default()
            },
            BackendEgressPolicy::unrestricted(),
            None,
        ),
    )
    .expect("localhost keeps the development loopback exception");
    let mut ctx = make_ctx();
    ctx.headers.insert(
        "authorization".to_string(),
        basic_header("alice", "loopback-secret"),
    );

    let result = plugin
        .authenticate(&mut ctx, &ConsumerIndex::new(&[]))
        .await;
    assert_backend_rejection_hides_credentials(result, &["loopback-secret"]);
    assert!(
        tokio::time::timeout(Duration::from_millis(300), listener.accept())
            .await
            .is_err(),
        "the plaintext localhost exception must not follow a non-loopback override"
    );
}

#[tokio::test]
async fn test_dial_resolution_timeout_is_bounded() {
    let dns = TestDnsServer::spawn(Vec::new()).await;
    dns.set_answers(TestDnsAnswers::DropQueries);
    let plugin = LdapAuth::new(
        &json!({
            "ldap_url": "ldap://directory.test:389",
            "bind_dn_template": "uid={username},ou=users,dc=example,dc=com",
            "canonical_identity_attribute": "uid",
            "allow_plaintext": true,
            "connect_timeout_seconds": 1
        }),
        http_client_with_dns(dns.addr, production_egress_policy(), None),
    )
    .expect("valid bounded resolver config");
    let mut ctx = make_ctx();
    ctx.headers.insert(
        "authorization".to_string(),
        basic_header("alice", "timeout-secret"),
    );
    let started = std::time::Instant::now();

    let result = plugin
        .authenticate(&mut ctx, &ConsumerIndex::new(&[]))
        .await;
    assert_backend_rejection_hides_credentials(result, &["timeout-secret"]);
    assert!(
        started.elapsed() < Duration::from_secs(3),
        "DNS and connection establishment must share the configured bound"
    );
    assert!(dns.queries() >= 1, "the test resolver was not queried");
}

#[tokio::test]
async fn test_dial_resolver_empty_response_fails_closed() {
    let dns = TestDnsServer::spawn(Vec::new()).await;
    let plugin = LdapAuth::new(
        &json!({
            "ldap_url": "ldap://missing.directory.test:389",
            "bind_dn_template": "uid={username},ou=users,dc=example,dc=com",
            "canonical_identity_attribute": "uid",
            "allow_plaintext": true,
            "connect_timeout_seconds": 1
        }),
        http_client_with_dns(dns.addr, production_egress_policy(), None),
    )
    .expect("valid resolver-error config");
    let mut ctx = make_ctx();
    ctx.headers.insert(
        "authorization".to_string(),
        basic_header("alice", "resolver-secret"),
    );

    let result = plugin
        .authenticate(&mut ctx, &ConsumerIndex::new(&[]))
        .await;
    assert_backend_rejection_hides_credentials(result, &["resolver-secret"]);
    assert!(dns.queries() >= 2, "both address families must be queried");
}

#[tokio::test]
async fn test_ldaps_keeps_configured_hostname_for_certificate_verification() {
    use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair, KeyUsagePurpose};
    use std::io::Write;
    use tempfile::NamedTempFile;
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;
    use tokio_rustls::TlsAcceptor;

    let ca_key =
        KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("generate LDAP test CA key");
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).expect("LDAP test CA params");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages.push(KeyUsagePurpose::KeyCertSign);
    let ca_cert = ca_params
        .self_signed(&ca_key)
        .expect("self-sign LDAP test CA");
    let issuer = Issuer::new(ca_params, ca_key);
    let leaf_key =
        KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("generate LDAP leaf key");
    let leaf_params =
        CertificateParams::new(vec!["directory.test".to_string()]).expect("LDAP leaf params");
    let leaf_cert = leaf_params
        .signed_by(&leaf_key, &issuer)
        .expect("sign LDAP leaf");

    let mut ca_file = NamedTempFile::new().expect("create LDAP CA bundle");
    ca_file
        .write_all(ca_cert.pem().as_bytes())
        .expect("write LDAP CA bundle");
    let certs = rustls_pemfile::certs(&mut leaf_cert.pem().as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .expect("parse LDAP leaf certificate");
    let key = rustls_pemfile::private_key(&mut leaf_key.serialize_pem().as_bytes())
        .expect("parse LDAP leaf key")
        .expect("LDAP leaf key present");
    let server_config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .expect("LDAP TLS protocol versions")
    .with_no_client_auth()
    .with_single_cert(certs, key)
    .expect("LDAP TLS server config");

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind LDAPS server");
    let port = listener.local_addr().expect("LDAPS server addr").port();
    let tls_task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("accept LDAPS connection");
        let mut stream = TlsAcceptor::from(Arc::new(server_config))
            .accept(stream)
            .await
            .expect("accept hostname-verified TLS");
        let _request = try_read_ldap_message_bytes(&mut stream)
            .await
            .expect("read LDAPS bind");
        stream
            .write_all(&bind_response(1, 0))
            .await
            .expect("write LDAPS bind response");
        answer_canonical_identity_search(&mut stream).await;
    });
    let dns = TestDnsServer::spawn(vec![IpAddr::V4(Ipv4Addr::LOCALHOST)]).await;
    let plugin = LdapAuth::new(
        &json!({
            "ldap_url": format!("ldaps://directory.test:{port}"),
            "bind_dn_template": "uid={username},ou=users,dc=example,dc=com",
            "canonical_identity_attribute": "uid",
            "consumer_mapping": false,
            "connect_timeout_seconds": 2
        }),
        http_client_with_dns(
            dns.addr,
            production_egress_policy(),
            ca_file.path().to_str(),
        ),
    )
    .expect("valid hostname-verified LDAPS config");
    let mut ctx = make_ctx();
    ctx.headers.insert(
        "authorization".to_string(),
        basic_header("alice", "tls-secret"),
    );

    let result = plugin
        .authenticate(&mut ctx, &ConsumerIndex::new(&[]))
        .await;
    assert_continue(result);
    tls_task.await.expect("LDAPS server");
}

fn ber_tlv(tag: u8, contents: &[u8]) -> Vec<u8> {
    let mut encoded = Vec::with_capacity(contents.len() + 4);
    encoded.push(tag);
    if contents.len() < 128 {
        encoded.push(contents.len() as u8);
    } else if contents.len() <= u8::MAX as usize {
        encoded.extend_from_slice(&[0x81, contents.len() as u8]);
    } else {
        encoded.push(0x82);
        encoded.extend_from_slice(&(contents.len() as u16).to_be_bytes());
    }
    encoded.extend_from_slice(contents);
    encoded
}

fn ldap_message(message_id: u8, protocol_op: &[u8]) -> Vec<u8> {
    let mut contents = ber_tlv(0x02, &[message_id]);
    contents.extend_from_slice(protocol_op);
    ber_tlv(0x30, &contents)
}

fn bind_response(message_id: u8, result_code: u8) -> Vec<u8> {
    ldap_message(
        message_id,
        &ber_tlv(0x61, &[0x0a, 0x01, result_code, 0x04, 0x00, 0x04, 0x00]),
    )
}

fn search_result_entry(message_id: u8, dn: &str, attributes: &[(&str, &[&str])]) -> Vec<u8> {
    let mut attribute_list = Vec::new();
    for (name, values) in attributes {
        let mut partial_attribute = ber_tlv(0x04, name.as_bytes());
        let mut encoded_values = Vec::new();
        for value in *values {
            encoded_values.extend_from_slice(&ber_tlv(0x04, value.as_bytes()));
        }
        partial_attribute.extend_from_slice(&ber_tlv(0x31, &encoded_values));
        attribute_list.extend_from_slice(&ber_tlv(0x30, &partial_attribute));
    }

    let mut entry = ber_tlv(0x04, dn.as_bytes());
    entry.extend_from_slice(&ber_tlv(0x30, &attribute_list));
    ldap_message(message_id, &ber_tlv(0x64, &entry))
}

fn search_result_done(message_id: u8, result_code: u8) -> Vec<u8> {
    ldap_message(
        message_id,
        &ber_tlv(0x65, &[0x0a, 0x01, result_code, 0x04, 0x00, 0x04, 0x00]),
    )
}

async fn try_read_ldap_message_bytes<S: tokio::io::AsyncRead + Unpin>(
    stream: &mut S,
) -> std::io::Result<Vec<u8>> {
    use tokio::io::AsyncReadExt;

    let mut header = [0u8; 2];
    stream.read_exact(&mut header).await?;
    assert_eq!(header[0], 0x30, "LDAP message must be a BER sequence");
    let body_len = if header[1] & 0x80 == 0 {
        usize::from(header[1])
    } else {
        let length_octets = usize::from(header[1] & 0x7f);
        let mut encoded_len = vec![0u8; length_octets];
        stream.read_exact(&mut encoded_len).await?;
        encoded_len
            .into_iter()
            .fold(0usize, |length, octet| (length << 8) | usize::from(octet))
    };
    let mut body = vec![0u8; body_len];
    stream.read_exact(&mut body).await?;
    Ok(body)
}

async fn read_ldap_message_bytes(stream: &mut tokio::net::TcpStream) -> Vec<u8> {
    try_read_ldap_message_bytes(stream)
        .await
        .expect("read LDAP message")
}

async fn read_ldap_message(stream: &mut tokio::net::TcpStream) {
    let _ = read_ldap_message_bytes(stream).await;
}

fn ldap_message_contains(message: &[u8], value: &str) -> bool {
    message
        .windows(value.len())
        .any(|window| window == value.as_bytes())
}

async fn spawn_search_bind_server(
    entries: Vec<(String, String, String)>,
    accept_user_bind: bool,
) -> (u16, tokio::task::JoinHandle<()>) {
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind search-bind LDAP server");
    let port = listener
        .local_addr()
        .expect("search-bind LDAP local addr")
        .port();
    let task = tokio::spawn(async move {
        let (mut service_stream, _) = listener.accept().await.expect("accept service bind");
        read_ldap_message(&mut service_stream).await;
        service_stream
            .write_all(&bind_response(1, 0))
            .await
            .expect("write service bind success");

        read_ldap_message(&mut service_stream).await;
        for (dn, attribute_name, attribute_value) in entries {
            service_stream
                .write_all(&search_result_entry(
                    2,
                    &dn,
                    &[(attribute_name.as_str(), &[attribute_value.as_str()])],
                ))
                .await
                .expect("write user search entry");
        }
        service_stream
            .write_all(&search_result_done(2, 0))
            .await
            .expect("write user search done");
        drop(service_stream);

        if accept_user_bind {
            let (mut user_stream, _) = listener.accept().await.expect("accept user bind");
            read_ldap_message(&mut user_stream).await;
            user_stream
                .write_all(&bind_response(1, 0))
                .await
                .expect("write user bind success");
        }
    });
    (port, task)
}

#[tokio::test]
async fn test_search_bind_uses_canonical_entry_identity() {
    let (port, task) = spawn_search_bind_server(
        vec![(
            "uid=canonical-alice,ou=users,dc=example,dc=com".to_string(),
            "UID".to_string(),
            "canonical-alice".to_string(),
        )],
        true,
    )
    .await;
    let plugin = LdapAuth::new(
        &json!({
            "ldap_url": format!("ldap://127.0.0.1:{port}"),
            "search_base_dn": "ou=users,dc=example,dc=com",
            "search_filter": "(uid={username})",
            "canonical_identity_attribute": "uid",
            "service_account_dn": "cn=admin,dc=example,dc=com",
            "service_account_password": "service-secret",
            "consumer_mapping": false
        }),
        http_client(),
    )
    .expect("valid search-bind config");
    let mut ctx = make_ctx();
    ctx.headers.insert(
        "authorization".to_string(),
        basic_header("presented-alias", "user-secret"),
    );

    let result = plugin
        .authenticate(&mut ctx, &ConsumerIndex::new(&[]))
        .await;
    assert_continue(result);
    assert_eq!(
        ctx.authenticated_identity.as_deref(),
        Some("canonical-alice")
    );
    assert_eq!(
        ctx.authenticated_identity_header.as_deref(),
        Some("canonical-alice")
    );
    task.abort();
}

/// Mock direct-bind directory that serves `connections` sequential
/// authentications. Every bind succeeds and every canonical-identity search
/// answers with the same entry, mirroring a real directory that matches the
/// login attribute case- and whitespace-insensitively.
async fn spawn_direct_bind_server(connections: usize) -> (u16, tokio::task::JoinHandle<()>) {
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind direct-bind LDAP server");
    let port = listener
        .local_addr()
        .expect("direct-bind LDAP local addr")
        .port();
    let task = tokio::spawn(async move {
        for _ in 0..connections {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            if try_read_ldap_message_bytes(&mut stream).await.is_err() {
                return;
            }
            if stream.write_all(&bind_response(1, 0)).await.is_err() {
                return;
            }
            answer_canonical_identity_search(&mut stream).await;
        }
    });
    (port, task)
}

/// Directories fold case and insignificant whitespace when matching a login
/// attribute, so `alice`, `ALICE`, and `alice ` all bind to one account. Direct
/// bind must therefore export the directory entry's canonical value, or one
/// account would mint an unbounded set of Ferrum principals — each with its own
/// per-consumer rate-limit budget and each missing an `access_control`
/// `disallowed_consumers` entry that names the real identity.
#[tokio::test]
async fn test_direct_bind_login_variants_share_one_canonical_identity() {
    use ferrum_edge::plugins::rate_limiting::RateLimiting;

    let logins = ["alice", "ALICE", "alice "];
    let (port, task) = spawn_direct_bind_server(logins.len()).await;
    let plugin = LdapAuth::new(
        &json!({
            "ldap_url": format!("ldap://127.0.0.1:{port}"),
            "bind_dn_template": "uid={username},ou=users,dc=example,dc=com",
            "canonical_identity_attribute": "uid",
            "consumer_mapping": false
        }),
        http_client(),
    )
    .expect("valid direct-bind config");

    // One request per window: a second admitted request proves the variants
    // were keyed as separate consumers.
    let limiter = RateLimiting::new(
        &json!({
            "limit_by": "consumer",
            "limits": [{ "scope": "default", "window_seconds": 60, "max_requests": 1 }]
        }),
        http_client(),
    )
    .expect("valid consumer rate limit");

    let mut admitted = 0usize;
    for login in logins {
        let mut ctx = make_ctx();
        ctx.headers.insert(
            "authorization".to_string(),
            basic_header(login, "user-secret"),
        );

        let result = plugin
            .authenticate(&mut ctx, &ConsumerIndex::new(&[]))
            .await;
        assert_continue(result);
        assert_eq!(
            ctx.authenticated_identity.as_deref(),
            Some(DIRECT_BIND_CANONICAL_IDENTITY),
            "login '{login}' must not become the Ferrum identity"
        );
        assert_eq!(
            ctx.effective_identity(),
            Some(DIRECT_BIND_CANONICAL_IDENTITY),
            "login '{login}' must resolve to the directory entry's identity"
        );

        if matches!(limiter.authorize(&mut ctx).await, PluginResult::Continue) {
            admitted += 1;
        }
    }

    assert_eq!(
        admitted, 1,
        "case and whitespace variants of one login must share a single rate-limiting key"
    );
    task.await.expect("direct-bind LDAP server");
}

/// A bind that succeeds but whose entry cannot yield exactly one canonical
/// value fails closed as a backend error rather than falling back to the
/// client-presented login.
#[tokio::test]
async fn test_direct_bind_without_a_canonical_value_fails_closed() {
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind canonical-less LDAP server");
    let port = listener
        .local_addr()
        .expect("canonical-less LDAP local addr")
        .port();
    let task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept direct bind");
        read_ldap_message(&mut stream).await;
        stream
            .write_all(&bind_response(1, 0))
            .await
            .expect("write bind success");
        read_ldap_message(&mut stream).await;
        stream
            .write_all(&search_result_entry(
                2,
                "uid=alice,ou=users,dc=example,dc=com",
                &[],
            ))
            .await
            .expect("write attribute-less entry");
        stream
            .write_all(&search_result_done(2, 0))
            .await
            .expect("write canonical search done");
    });
    let plugin = LdapAuth::new(
        &json!({
            "ldap_url": format!("ldap://127.0.0.1:{port}"),
            "bind_dn_template": "uid={username},ou=users,dc=example,dc=com",
            "canonical_identity_attribute": "uid",
            "consumer_mapping": false
        }),
        http_client(),
    )
    .expect("valid direct-bind config");
    let mut ctx = make_ctx();
    ctx.headers.insert(
        "authorization".to_string(),
        basic_header("alice", "user-secret"),
    );

    let result = plugin
        .authenticate(&mut ctx, &ConsumerIndex::new(&[]))
        .await;
    assert_reject(result, Some(500));
    assert!(ctx.authenticated_identity.is_none());
    task.abort();
}

#[tokio::test]
async fn test_search_bind_rejects_ambiguous_results() {
    let (port, task) = spawn_search_bind_server(
        vec![
            (
                "uid=victim,ou=users,dc=example,dc=com".to_string(),
                "uid".to_string(),
                "victim".to_string(),
            ),
            (
                "uid=attacker,ou=users,dc=example,dc=com".to_string(),
                "uid".to_string(),
                "attacker".to_string(),
            ),
        ],
        false,
    )
    .await;
    let plugin = LdapAuth::new(
        &json!({
            "ldap_url": format!("ldap://127.0.0.1:{port}"),
            "search_base_dn": "ou=users,dc=example,dc=com",
            "search_filter": "(uid={username})",
            "canonical_identity_attribute": "uid",
            "service_account_dn": "cn=admin,dc=example,dc=com",
            "service_account_password": "service-secret"
        }),
        http_client(),
    )
    .expect("valid search-bind config");
    let mut ctx = make_ctx();
    ctx.headers.insert(
        "authorization".to_string(),
        basic_header("victim", "attacker-secret"),
    );

    let result = plugin
        .authenticate(&mut ctx, &ConsumerIndex::new(&[]))
        .await;
    assert_reject(result, Some(401));
    assert!(ctx.authenticated_identity.is_none());
    task.abort();
}

async fn assert_search_bind_group_checks_use_canonical_identity(
    custom_group_filter: Option<&str>,
    canonical_identity_is_member: bool,
) {
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;

    const PRESENTED_ALIAS: &str = "alice@example.com";
    const CANONICAL_IDENTITY: &str = "immutable-alice-id";
    const USER_DN: &str = "uid=alice,ou=users,dc=example,dc=com";
    const GROUP_DN: &str = "cn=gateway-admins,ou=groups,dc=example,dc=com";

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind canonical group-check LDAP server");
    let port = listener
        .local_addr()
        .expect("canonical group-check LDAP local addr")
        .port();
    let expects_exact_group_proof = custom_group_filter.is_some();
    let task = tokio::spawn(async move {
        let (mut service_stream, _) = listener.accept().await.expect("accept service bind");
        read_ldap_message(&mut service_stream).await;
        service_stream
            .write_all(&bind_response(1, 0))
            .await
            .expect("write service bind success");

        let user_search = read_ldap_message_bytes(&mut service_stream).await;
        assert!(
            ldap_message_contains(&user_search, PRESENTED_ALIAS),
            "the presented login must remain the user-search input"
        );
        service_stream
            .write_all(&search_result_entry(
                2,
                USER_DN,
                &[("entryUUID", &[CANONICAL_IDENTITY])],
            ))
            .await
            .expect("write canonical user search entry");
        service_stream
            .write_all(&search_result_done(2, 0))
            .await
            .expect("write canonical user search done");
        drop(service_stream);

        let (mut user_stream, _) = listener.accept().await.expect("accept selected user bind");
        read_ldap_message(&mut user_stream).await;
        user_stream
            .write_all(&bind_response(1, 0))
            .await
            .expect("write selected user bind success");
        drop(user_stream);

        let (mut group_stream, _) = listener.accept().await.expect("accept group service bind");
        read_ldap_message(&mut group_stream).await;
        group_stream
            .write_all(&bind_response(1, 0))
            .await
            .expect("write group service bind success");

        let group_search = read_ldap_message_bytes(&mut group_stream).await;
        assert!(
            ldap_message_contains(&group_search, CANONICAL_IDENTITY),
            "group search did not use the authenticated canonical identity"
        );
        assert!(
            ldap_message_contains(&group_search, "memberUid"),
            "group search did not carry the username-based membership predicate"
        );
        assert!(
            !ldap_message_contains(&group_search, PRESENTED_ALIAS),
            "group search reused the client-presented alias"
        );
        if canonical_identity_is_member {
            group_stream
                .write_all(&search_result_entry(
                    2,
                    GROUP_DN,
                    &[("cn", &["gateway-admins"])],
                ))
                .await
                .expect("write required group search entry");
        }
        group_stream
            .write_all(&search_result_done(2, 0))
            .await
            .expect("write required group search done");

        if expects_exact_group_proof && canonical_identity_is_member {
            let exact_group_proof = read_ldap_message_bytes(&mut group_stream).await;
            assert!(
                ldap_message_contains(&exact_group_proof, CANONICAL_IDENTITY),
                "exact returned-group proof did not use the canonical identity"
            );
            assert!(
                ldap_message_contains(&exact_group_proof, "memberUid"),
                "exact returned-group proof did not carry the memberUid predicate"
            );
            assert!(
                !ldap_message_contains(&exact_group_proof, PRESENTED_ALIAS),
                "exact returned-group proof reused the client-presented alias"
            );
            group_stream
                .write_all(&search_result_entry(3, GROUP_DN, &[]))
                .await
                .expect("write exact returned-group proof");
            group_stream
                .write_all(&search_result_done(3, 0))
                .await
                .expect("write exact returned-group proof done");
        }

        if !canonical_identity_is_member {
            let trailing_request = tokio::time::timeout(
                std::time::Duration::from_secs(1),
                try_read_ldap_message_bytes(&mut group_stream),
            )
            .await;
            match trailing_request {
                Ok(Ok(request)) => assert!(
                    !ldap_message_contains(&request, PRESENTED_ALIAS),
                    "group denial triggered a fallback request using the presented alias"
                ),
                Ok(Err(error))
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::UnexpectedEof
                            | std::io::ErrorKind::ConnectionReset
                            | std::io::ErrorKind::ConnectionAborted
                    ) => {}
                Ok(Err(error)) => panic!("read trailing group-check request: {error}"),
                Err(_) => {}
            }
        }
    });

    let mut config = json!({
        "ldap_url": format!("ldap://127.0.0.1:{port}"),
        "search_base_dn": "ou=users,dc=example,dc=com",
        "search_filter": "(mail={username})",
        "canonical_identity_attribute": "entryUUID",
        "service_account_dn": "cn=admin,dc=example,dc=com",
        "service_account_password": "service-secret",
        "group_base_dn": "ou=groups,dc=example,dc=com",
        "required_groups": ["gateway-admins"],
        "consumer_mapping": false
    });
    if let Some(group_filter) = custom_group_filter {
        config["group_filter"] = json!(group_filter);
    }
    let plugin = LdapAuth::new(&config, http_client()).expect("valid canonical group-check config");
    let mut ctx = make_ctx();
    ctx.headers.insert(
        "authorization".to_string(),
        basic_header(PRESENTED_ALIAS, "user-secret"),
    );

    let result = plugin
        .authenticate(&mut ctx, &ConsumerIndex::new(&[]))
        .await;
    if canonical_identity_is_member {
        assert_continue(result);
        assert_eq!(
            ctx.authenticated_identity.as_deref(),
            Some(CANONICAL_IDENTITY)
        );
    } else {
        assert_reject(result, Some(403));
        assert!(ctx.authenticated_identity.is_none());
    }
    task.await.expect("canonical group-check LDAP server");
}

#[tokio::test]
async fn test_search_bind_default_member_uid_uses_canonical_identity() {
    assert_search_bind_group_checks_use_canonical_identity(None, true).await;
}

#[tokio::test]
async fn test_search_bind_custom_username_and_exact_proof_use_canonical_identity() {
    assert_search_bind_group_checks_use_canonical_identity(Some("(memberUid={username})"), true)
        .await;
}

#[tokio::test]
async fn test_search_bind_denies_alias_only_group_membership_without_fallback() {
    // Model the advisory shape: the presented alias is a memberUid value, but
    // the authenticated entry's immutable identity is not. The canonical query
    // therefore returns no groups, and any alias-bearing retry is a bypass.
    assert_search_bind_group_checks_use_canonical_identity(Some("(memberUid={username})"), false)
        .await;
}

async fn assert_group_search_result(
    result_code: u8,
    returned_group: &'static str,
    group_filter: &'static str,
    returned_user_is_member: bool,
    expected_rejection_status: Option<u16>,
) {
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind group LDAP server");
    let port = listener.local_addr().expect("group LDAP local addr").port();
    let task = tokio::spawn(async move {
        let (mut user_stream, _) = listener.accept().await.expect("accept direct bind");
        read_ldap_message(&mut user_stream).await;
        user_stream
            .write_all(&bind_response(1, 0))
            .await
            .expect("write direct bind success");
        // Direct bind reads the canonical identity off the bound entry before
        // any group lookup; answer it on the same connection.
        answer_canonical_identity_search(&mut user_stream).await;
        drop(user_stream);

        let (mut group_stream, _) = listener.accept().await.expect("accept group search");
        read_ldap_message(&mut group_stream).await;
        let group_dn = "CN=unrelated-cn,OU=Groups,DC=example,DC=com";
        group_stream
            .write_all(&search_result_entry(
                1,
                group_dn,
                &[("samaccountname", &[returned_group])],
            ))
            .await
            .expect("write group search entry");
        group_stream
            .write_all(&search_result_done(1, result_code))
            .await
            .expect("write group search done");

        // A custom-filter match against a required group must trigger a
        // base-scope membership proof on that exact returned entry. Simulate
        // the LDAP server evaluating the member/uniqueMember/memberUid filter.
        read_ldap_message(&mut group_stream).await;
        if returned_user_is_member {
            group_stream
                .write_all(&search_result_entry(2, group_dn, &[]))
                .await
                .expect("write returned-group membership proof");
        }
        group_stream
            .write_all(&search_result_done(2, 0))
            .await
            .expect("write returned-group membership proof done");
    });

    let plugin = LdapAuth::new(
        &json!({
            "ldap_url": format!("ldap://127.0.0.1:{port}"),
            "bind_dn_template": "uid={username},ou=users,dc=example,dc=com",
            "canonical_identity_attribute": "uid",
            "group_base_dn": "ou=groups,dc=example,dc=com",
            "group_filter": group_filter,
            "group_attribute": "sAMAccountName",
            "required_groups": ["gateway-admins"]
        }),
        http_client(),
    )
    .expect("valid direct-bind group config");
    let mut ctx = make_ctx();
    ctx.headers.insert(
        "authorization".to_string(),
        basic_header("alice", "user-secret"),
    );

    let result = plugin
        .authenticate(&mut ctx, &ConsumerIndex::new(&[]))
        .await;
    if let Some(status) = expected_rejection_status {
        assert_reject(result, Some(status));
    } else {
        assert_continue(result);
    }
    task.abort();
}

#[tokio::test]
async fn test_group_attribute_lookup_is_case_insensitive() {
    assert_group_search_result(0, "gateway-admins", "(member={user_dn})", true, None).await;
}

#[tokio::test]
async fn test_size_limited_group_search_accepts_a_proven_required_match() {
    assert_group_search_result(4, "gateway-admins", "(member={user_dn})", true, None).await;
}

#[tokio::test]
async fn test_size_limited_group_search_without_a_match_fails_closed() {
    assert_group_search_result(4, "unrelated-group", "(member={user_dn})", false, Some(500)).await;
}

#[tokio::test]
async fn test_static_allow_branch_does_not_authorize_non_member() {
    assert_group_search_result(
        0,
        "gateway-admins",
        "(|(member={user_dn})(cn=gateway-admins))",
        false,
        Some(403),
    )
    .await;
}

#[tokio::test]
async fn test_placeholder_only_group_filter_authorizes_real_member() {
    assert_group_search_result(0, "gateway-admins", "(member={user_dn})", true, None).await;
}

#[tokio::test]
async fn test_complete_flow_wall_clock_timeout() {
    use tokio::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind stalling LDAP server");
    let port = listener.local_addr().expect("stall LDAP local addr").port();
    let task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept stalled bind");
        read_ldap_message(&mut stream).await;
        tokio::time::sleep(std::time::Duration::from_secs(10)).await;
    });
    let plugin = LdapAuth::new(
        &json!({
            "ldap_url": format!("ldap://127.0.0.1:{port}"),
            "bind_dn_template": "uid={username},ou=users,dc=example,dc=com",
            "canonical_identity_attribute": "uid",
            "connect_timeout_seconds": 5,
            "request_timeout_seconds": 1
        }),
        http_client(),
    )
    .expect("valid bounded LDAP config");
    let mut ctx = make_ctx();
    ctx.headers.insert(
        "authorization".to_string(),
        basic_header("alice", "user-secret"),
    );
    let started = std::time::Instant::now();
    let result = plugin
        .authenticate(&mut ctx, &ConsumerIndex::new(&[]))
        .await;
    assert_reject(result, Some(500));
    assert!(
        started.elapsed() < std::time::Duration::from_secs(3),
        "overall authentication deadline was not enforced"
    );
    task.abort();
}

#[tokio::test]
async fn test_operation_timeout_is_reapplied_after_service_bind() {
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind post-bind stall server");
    let port = listener.local_addr().expect("stall LDAP local addr").port();
    let task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept service bind");
        read_ldap_message(&mut stream).await;
        stream
            .write_all(&bind_response(1, 0))
            .await
            .expect("write service bind success");
        read_ldap_message(&mut stream).await;
        tokio::time::sleep(std::time::Duration::from_secs(10)).await;
    });
    let plugin = LdapAuth::new(
        &json!({
            "ldap_url": format!("ldap://127.0.0.1:{port}"),
            "search_base_dn": "ou=users,dc=example,dc=com",
            "search_filter": "(uid={username})",
            "canonical_identity_attribute": "uid",
            "service_account_dn": "cn=admin,dc=example,dc=com",
            "service_account_password": "service-secret",
            "connect_timeout_seconds": 1,
            "request_timeout_seconds": 5
        }),
        http_client(),
    )
    .expect("valid bounded search-bind config");
    let mut ctx = make_ctx();
    ctx.headers.insert(
        "authorization".to_string(),
        basic_header("alice", "user-secret"),
    );
    let started = std::time::Instant::now();
    let result = plugin
        .authenticate(&mut ctx, &ConsumerIndex::new(&[]))
        .await;
    assert_reject(result, Some(500));
    assert!(
        started.elapsed() < std::time::Duration::from_secs(3),
        "search should use a fresh per-operation timeout after service bind"
    );
    task.abort();
}

#[tokio::test]
async fn test_concurrency_limit_rejects_excess_without_new_connection() {
    use std::sync::Arc;
    use tokio::net::TcpListener;
    use tokio::sync::oneshot;

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind concurrency LDAP server");
    let port = listener.local_addr().expect("concurrency LDAP addr").port();
    let (accepted_tx, accepted_rx) = oneshot::channel();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept first bind");
        read_ldap_message(&mut stream).await;
        let _ = accepted_tx.send(());
        tokio::time::sleep(std::time::Duration::from_secs(10)).await;
    });
    let plugin = Arc::new(
        LdapAuth::new(
            &json!({
                "ldap_url": format!("ldap://127.0.0.1:{port}"),
                "bind_dn_template": "uid={username},ou=users,dc=example,dc=com",
                "canonical_identity_attribute": "uid",
                "connect_timeout_seconds": 5,
                "request_timeout_seconds": 5,
                "max_concurrent_requests": 1
            }),
            http_client(),
        )
        .expect("valid concurrency-bounded LDAP config"),
    );
    let consumer_index = Arc::new(ConsumerIndex::new(&[]));
    let first_plugin = Arc::clone(&plugin);
    let first_consumers = Arc::clone(&consumer_index);
    let first = tokio::spawn(async move {
        let mut ctx = make_ctx();
        ctx.headers.insert(
            "authorization".to_string(),
            basic_header("first", "user-secret"),
        );
        first_plugin.authenticate(&mut ctx, &first_consumers).await
    });
    accepted_rx
        .await
        .expect("first request reached LDAP server");

    let mut second_ctx = make_ctx();
    second_ctx.headers.insert(
        "authorization".to_string(),
        basic_header("second", "user-secret"),
    );
    let started = std::time::Instant::now();
    let second = plugin.authenticate(&mut second_ctx, &consumer_index).await;
    assert_reject(second, Some(500));
    assert!(
        started.elapsed() < std::time::Duration::from_millis(500),
        "excess LDAP work should be rejected immediately"
    );

    first.abort();
    server.abort();
}

async fn spawn_invalid_credentials_ldap_server() -> (u16, tokio::task::JoinHandle<()>) {
    spawn_bind_response_ldap_server(49).await
}

#[tokio::test]
async fn test_ldap_invalid_credentials_returns_401() {
    // Finding #32: a directory that accepts the connection but REJECTS the bind
    // (resultCode 49, invalidCredentials) is the genuine wrong-password case and
    // must map to 401 — not the 500 reserved for backend/config failures.
    let (port, task) = spawn_invalid_credentials_ldap_server().await;

    let plugin = LdapAuth::new(
        &json!({
            "ldap_url": format!("ldap://127.0.0.1:{port}"),
            "bind_dn_template": "uid={username},ou=users,dc=example,dc=com",
            "canonical_identity_attribute": "uid",
            "connect_timeout_seconds": 5
        }),
        http_client(),
    )
    .unwrap();

    let mut ctx = make_ctx();
    ctx.headers.insert(
        "authorization".to_string(),
        basic_header("alice", "wrong-password"),
    );
    let consumer_index = ConsumerIndex::new(&[]);

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_reject(result, Some(401));

    task.abort();
}

#[tokio::test]
async fn test_ldap_busy_bind_result_returns_500() {
    // A directory can report operational failures as LDAP result codes after
    // accepting the TCP connection. Only rc=49 is a credential failure; rc=51
    // (`busy`) must surface as backend trouble.
    let (port, task) = spawn_bind_response_ldap_server(51).await;

    let plugin = LdapAuth::new(
        &json!({
            "ldap_url": format!("ldap://127.0.0.1:{port}"),
            "bind_dn_template": "uid={username},ou=users,dc=example,dc=com",
            "canonical_identity_attribute": "uid",
            "connect_timeout_seconds": 5
        }),
        http_client(),
    )
    .unwrap();

    let mut ctx = make_ctx();
    ctx.headers.insert(
        "authorization".to_string(),
        basic_header("alice", "password"),
    );
    let consumer_index = ConsumerIndex::new(&[]);

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_reject(result, Some(500));

    task.abort();
}

#[tokio::test]
async fn test_ldap_connection_failure_returns_500() {
    // Finding #32: an unreachable LDAP server is a backend/infrastructure
    // failure, not a credential failure. It must surface as a 500 so the client
    // is not falsely told its credentials are wrong (which would prompt useless
    // credential re-submission and mask the outage). Point at a closed loopback
    // port so the connection is refused immediately.
    let plugin = LdapAuth::new(
        &json!({
            "ldap_url": "ldap://127.0.0.1:19",
            "bind_dn_template": "uid={username},ou=users,dc=example,dc=com",
            "canonical_identity_attribute": "uid",
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
    assert_reject(result, Some(500));
}

#[tokio::test]
async fn test_ldap_connection_failure_search_bind_returns_500() {
    // Finding #32: the same backend-vs-credential distinction must hold in
    // search-then-bind mode. An unreachable directory (refused connection on a
    // closed loopback port) is a 500, not a 401 — the service-account bind never
    // even runs, so this is unambiguously infrastructure, not bad credentials.
    let plugin = LdapAuth::new(
        &json!({
            "ldap_url": "ldap://127.0.0.1:19",
            "search_base_dn": "ou=users,dc=example,dc=com",
            "search_filter": "(&(objectClass=person)(uid={username}))",
            "canonical_identity_attribute": "uid",
            "service_account_dn": "cn=admin,dc=example,dc=com",
            "service_account_password": "admin_password",
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
    assert_reject(result, Some(500));
}

// ─── AD config combination tests ─────────────────────────────────────────

#[test]
fn test_full_ad_config() {
    let result = LdapAuth::new(
        &json!({
            "ldap_url": "ldaps://dc.contoso.com:636",
            "search_base_dn": "OU=Users,DC=contoso,DC=com",
            "search_filter": "(&(objectClass=user)(sAMAccountName={username}))",
            "canonical_identity_attribute": "sAMAccountName",
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
fn test_both_bind_modes_rejected() {
    // Direct bind and search-then-bind are alternatives, not layers. Accepting
    // both and silently taking the direct-bind branch would leave the search
    // keys inert while an operator believes they are in force.
    for extra_key in ["search_base_dn", "search_filter"] {
        let mut config = json!({
            "ldap_url": "ldaps://ldap.example.com:636",
            "bind_dn_template": "uid={username},ou=users,dc=example,dc=com",
            "canonical_identity_attribute": "uid",
            "service_account_dn": "cn=admin,dc=example,dc=com",
            "service_account_password": "admin_password"
        });
        let value = if extra_key == "search_base_dn" {
            "ou=users,dc=example,dc=com"
        } else {
            "(&(objectClass=person)(uid={username}))"
        };
        config[extra_key] = json!(value);

        let error = LdapAuth::new(&config, http_client())
            .err()
            .unwrap_or_else(|| panic!("'{extra_key}' beside 'bind_dn_template' must be refused"));
        assert!(error.contains("bind_dn_template"), "{error}");
        assert!(error.contains(extra_key), "{error}");
    }
}

#[test]
fn test_direct_bind_requires_canonical_identity_attribute() {
    let error = LdapAuth::new(
        &json!({
            "ldap_url": "ldaps://ldap.example.com:636",
            "bind_dn_template": "uid={username},ou=users,dc=example,dc=com"
        }),
        http_client(),
    )
    .err()
    .expect("direct bind without a canonical identity must fail closed");

    assert!(error.contains("canonical_identity_attribute"), "{error}");
}

// ─── Cache bounding config tests ─────────────────────────────────────────

#[test]
fn test_ldap_auth_max_cache_entries_default() {
    // Create a valid config without max_cache_entries — default is 10000
    let config = json!({
        "ldap_url": "ldaps://ldap.example.com:636",
        "bind_dn_template": "uid={username},ou=users,dc=example,dc=com",
        "canonical_identity_attribute": "uid"
    });
    let plugin = LdapAuth::new(&config, http_client()).unwrap();
    assert_eq!(plugin.name(), "ldap_auth");
}

#[test]
fn test_ldap_auth_max_cache_entries_custom() {
    let config = json!({
        "ldap_url": "ldaps://ldap.example.com:636",
        "bind_dn_template": "uid={username},ou=users,dc=example,dc=com",
        "canonical_identity_attribute": "uid",
        "max_cache_entries": 500
    });
    let plugin = LdapAuth::new(&config, http_client()).unwrap();
    assert_eq!(plugin.name(), "ldap_auth");
}

// ─── Security plugin registration test ───────────────────────────────────

#[test]
fn test_ldap_auth_is_security_plugin() {
    assert_eq!(
        ferrum_edge::plugins::plugin_failure_policy("ldap_auth"),
        Some(ferrum_edge::plugins::PluginFailurePolicy::FailClosed)
    );
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
fn test_dn_escape_trailing_space_after_multibyte() {
    // `é` is 2 UTF-8 bytes — the old enumerate()-vs-input.len() comparison
    // would never flag the trailing space as the last character for any
    // input containing multi-byte UTF-8.
    assert_eq!(escape_dn_value("héllo "), "héllo\\ ");
}

#[test]
fn test_dn_escape_leading_space_with_multibyte() {
    assert_eq!(escape_dn_value(" héllo"), "\\ héllo");
}

#[test]
fn test_dn_escape_no_change_for_unicode_without_trailing_space() {
    assert_eq!(escape_dn_value("héllo"), "héllo");
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

#[test]
fn test_filter_escape_preserves_utf8() {
    // A non-ASCII filter value (e.g. an accented username/group) must keep its
    // real UTF-8 bytes — only the five RFC 4515 metacharacters are escaped.
    // Iterating bytes and doing `byte as char` re-encodes each UTF-8 byte as a
    // separate code point, corrupting the value so the directory search never
    // matches the entry (a non-ASCII user in search-then-bind / group lookup is
    // wrongly denied). `escape_dn_value` already handles this correctly; the
    // filter path must match.
    assert_eq!(escape_filter_value("café"), "café");
    assert_eq!(escape_filter_value("café").into_bytes(), "café".as_bytes());
    // Multi-byte characters and the metacharacter escaping must coexist.
    assert_eq!(escape_filter_value("café*"), "café\\2a");
    assert_eq!(escape_filter_value("naïve(user)"), "naïve\\28user\\29");
}

#[tokio::test]
async fn test_ldap_auth_non_ascii_authorization_returns_invalid_not_missing() {
    let plugin = LdapAuth::new(
        &json!({
            "ldap_url": "ldap://127.0.0.1:389",
            "bind_dn_template": "uid={username},dc=example,dc=com",
            "canonical_identity_attribute": "uid"
        }),
        http_client(),
    )
    .unwrap();
    let consumer_index = ConsumerIndex::new(&[]);
    let mut ctx =
        context_with_materialized_raw_header("Authorization", "Basic dXNlcjpwYXNz\u{3000}");

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_reject_body(result, r#"{"error":"Invalid Authorization header"}"#);
    assert!(ctx.identified_consumer.is_none());
}

// ─── Shared fixtures for the sections below ──────────────────────────────

fn direct_bind_config_with(extra: serde_json::Value) -> serde_json::Value {
    let mut config = json!({
        "ldap_url": "ldaps://ldap.example.com:636",
        "bind_dn_template": "uid={username},ou=users,dc=example,dc=com",
        "canonical_identity_attribute": "uid"
    });
    let object = config.as_object_mut().expect("config object");
    for (key, value) in extra.as_object().expect("extra object") {
        object.insert(key.clone(), value.clone());
    }
    config
}

fn direct_bind_plugin(extra: serde_json::Value) -> LdapAuth {
    let config = direct_bind_config_with(extra);
    LdapAuth::new(&config, http_client()).expect("valid direct-bind config")
}

fn search_bind_config_with(search_filter: &str) -> serde_json::Value {
    json!({
        "ldap_url": "ldaps://ldap.example.com:636",
        "search_base_dn": "ou=users,dc=example,dc=com",
        "search_filter": search_filter,
        "canonical_identity_attribute": "uid",
        "service_account_dn": "cn=admin,dc=example,dc=com",
        "service_account_password": "service-secret"
    })
}

// ─── Filter syntax admission (issue #5036) ───────────────────────────────

#[test]
fn test_unbalanced_search_filter_rejected_at_admission() {
    let config = search_bind_config_with("(uid={username}");
    let Err(error) = LdapAuth::new(&config, http_client()) else {
        panic!("unbalanced search_filter must be rejected");
    };
    assert!(
        error.contains("'search_filter'") && error.contains("RFC 4515"),
        "unexpected error: {error}"
    );
}

#[test]
fn test_empty_filter_branch_in_search_filter_rejected_at_admission() {
    let config = search_bind_config_with("(&(uid={username})())");
    let Err(error) = LdapAuth::new(&config, http_client()) else {
        panic!("an empty filter branch must be rejected");
    };
    assert!(error.contains("'search_filter'"), "unexpected: {error}");
}

#[test]
fn test_valid_search_filter_accepted_at_admission() {
    let config = search_bind_config_with("(&(objectClass=person)(uid={username}))");
    LdapAuth::new(&config, http_client()).expect("well-formed search_filter is admitted");
}

#[test]
fn test_unbalanced_group_filter_rejected_at_admission() {
    let config = direct_bind_config_with(json!({
        "group_base_dn": "ou=groups,dc=example,dc=com",
        "group_filter": "(member={user_dn}",
        "required_groups": ["admins"]
    }));
    let Err(error) = LdapAuth::new(&config, http_client()) else {
        panic!("unbalanced group_filter must be rejected");
    };
    assert!(
        error.contains("'group_filter'") && error.contains("RFC 4515"),
        "unexpected error: {error}"
    );
}

#[test]
fn test_valid_group_filter_accepted_at_admission() {
    let config = direct_bind_config_with(json!({
        "group_base_dn": "ou=groups,dc=example,dc=com",
        "group_filter": "(&(objectClass=group)(member={user_dn}))",
        "required_groups": ["admins"]
    }));
    LdapAuth::new(&config, http_client()).expect("well-formed group_filter is admitted");
}

// ─── Basic authentication challenge (issue #5037) ────────────────────────

#[test]
fn test_ldap_auth_advertises_the_basic_challenge() {
    let plugin = direct_bind_plugin(json!({}));
    assert_eq!(
        plugin.authentication_challenge(),
        Some(r#"Basic realm="ferrum-edge", charset="UTF-8""#)
    );
}

#[tokio::test]
async fn test_invalid_credential_rejection_carries_the_basic_challenge() {
    let plugin = direct_bind_plugin(json!({}));
    let mut ctx = make_ctx();
    ctx.headers.insert(
        "authorization".to_string(),
        "Basic !!!not-base64".to_string(),
    );

    let result = plugin
        .authenticate(&mut ctx, &ConsumerIndex::new(&[]))
        .await;
    let PluginResult::Reject {
        status_code,
        headers,
        ..
    } = result
    else {
        panic!("expected a rejection");
    };
    assert_eq!(status_code, 401);
    assert_eq!(
        headers.get("WWW-Authenticate").map(String::as_str),
        Some(r#"Basic realm="ferrum-edge", charset="UTF-8""#)
    );
}

// ─── max_cache_entries upper bound ───────────────────────────────────────

#[test]
fn test_max_cache_entries_upper_bound_enforced() {
    direct_bind_plugin(json!({"max_cache_entries": 1_000_000}));
    let config = direct_bind_config_with(json!({"max_cache_entries": 1_000_001}));
    let Err(error) = LdapAuth::new(&config, http_client()) else {
        panic!("above the documented maximum must be rejected");
    };
    assert!(error.contains("'max_cache_entries'"), "unexpected: {error}");
}

// ─── hide_credentials (advisory GHSA-wprm-pc37-r867) ─────────────────────

async fn backend_headers_after_before_proxy(
    extra: serde_json::Value,
    authorization: &str,
) -> std::collections::HashMap<String, String> {
    let plugin = direct_bind_plugin(extra);
    let mut ctx = make_ctx();
    let mut headers = std::collections::HashMap::new();
    headers.insert("authorization".to_string(), authorization.to_string());
    headers.insert("x-trace".to_string(), "keep-me".to_string());
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
    headers
}

#[tokio::test]
async fn test_basic_credentials_are_hidden_from_the_backend_by_default() {
    let authorization = basic_header("alice", "user-secret");
    let headers = backend_headers_after_before_proxy(json!({}), &authorization).await;
    assert!(
        !headers.contains_key("authorization"),
        "the Basic credential must not reach the backend: {headers:?}"
    );
    assert_eq!(headers.get("x-trace").map(String::as_str), Some("keep-me"));
}

#[tokio::test]
async fn test_mixed_case_authorization_field_name_is_also_hidden() {
    let plugin = direct_bind_plugin(json!({}));
    let mut ctx = make_ctx();
    let mut headers = std::collections::HashMap::new();
    headers.insert(
        "Authorization".to_string(),
        basic_header("alice", "user-secret"),
    );
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
    assert!(headers.is_empty(), "unexpected headers: {headers:?}");
}

#[tokio::test]
async fn test_hide_credentials_leaves_other_authorization_schemes_intact() {
    let headers = backend_headers_after_before_proxy(json!({}), "Bearer some.jwt.token").await;
    assert_eq!(
        headers.get("authorization").map(String::as_str),
        Some("Bearer some.jwt.token"),
        "another mechanism's credential must reach the backend unchanged"
    );
}

#[tokio::test]
async fn test_hide_credentials_can_be_disabled() {
    let authorization = basic_header("alice", "user-secret");
    let extra = json!({"hide_credentials": false});
    let headers = backend_headers_after_before_proxy(extra, &authorization).await;
    assert_eq!(
        headers.get("authorization").map(String::as_str),
        Some(authorization.as_str())
    );
}

#[test]
fn test_authorization_is_always_redacted_from_diagnostics() {
    for hide_credentials in [true, false] {
        let plugin = direct_bind_plugin(json!({"hide_credentials": hide_credentials}));
        let redacted: Vec<&str> = plugin
            .request_headers_to_redact()
            .iter()
            .map(String::as_str)
            .collect();
        assert_eq!(redacted, ["authorization"]);
        assert_eq!(plugin.modifies_request_headers(), hide_credentials);
    }
}

#[test]
fn test_hide_credentials_must_be_a_boolean() {
    let config = direct_bind_config_with(json!({"hide_credentials": "yes"}));
    let Err(error) = LdapAuth::new(&config, http_client()) else {
        panic!("non-boolean hide_credentials must be rejected");
    };
    assert!(error.contains("'hide_credentials'"), "unexpected: {error}");
}

// ─── Service-account password is never trimmed (issue #5039) ─────────────

/// Mock directory that records every request message it receives and then
/// rejects the bind, so a test can assert exactly what reached the wire.
async fn spawn_bind_recording_ldap_server(
    recorded: Arc<RwLock<Vec<Vec<u8>>>>,
) -> (u16, tokio::task::JoinHandle<()>) {
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind recording LDAP server");
    let port = listener
        .local_addr()
        .expect("recording LDAP local addr")
        .port();
    let task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept service bind");
        let bind = read_ldap_message_bytes(&mut stream).await;
        recorded.write().expect("record bind message").push(bind);
        let _ = stream.write_all(&bind_response(1, 49)).await;
    });
    (port, task)
}

#[test]
fn test_service_account_password_keeps_surrounding_whitespace() {
    let config = json!({
        "ldap_url": "ldaps://ldap.example.com:636",
        "search_base_dn": "ou=users,dc=example,dc=com",
        "search_filter": "(uid={username})",
        "canonical_identity_attribute": "uid",
        "service_account_dn": "cn=admin,dc=example,dc=com",
        "service_account_password": "  padded-secret  "
    });
    LdapAuth::new(&config, http_client()).expect("a padded password is a valid secret");
}

#[test]
fn test_empty_service_account_password_still_rejected() {
    let config = json!({
        "ldap_url": "ldaps://ldap.example.com:636",
        "search_base_dn": "ou=users,dc=example,dc=com",
        "search_filter": "(uid={username})",
        "canonical_identity_attribute": "uid",
        "service_account_dn": "cn=admin,dc=example,dc=com",
        "service_account_password": ""
    });
    let Err(error) = LdapAuth::new(&config, http_client()) else {
        panic!("an empty password must be rejected");
    };
    assert!(
        error.contains("'service_account_password'"),
        "unexpected: {error}"
    );
}

#[tokio::test]
async fn test_service_account_bind_carries_the_configured_password_verbatim() {
    let recorded = Arc::new(RwLock::new(Vec::new()));
    let (port, task) = spawn_bind_recording_ldap_server(Arc::clone(&recorded)).await;
    let config = json!({
        "ldap_url": format!("ldap://127.0.0.1:{port}"),
        "search_base_dn": "ou=users,dc=example,dc=com",
        "search_filter": "(uid={username})",
        "canonical_identity_attribute": "uid",
        "service_account_dn": "cn=admin,dc=example,dc=com",
        "service_account_password": "  padded-secret  ",
        "consumer_mapping": false
    });
    let plugin = LdapAuth::new(&config, http_client()).expect("valid search-bind config");
    let mut ctx = make_ctx();
    ctx.headers.insert(
        "authorization".to_string(),
        basic_header("alice", "user-secret"),
    );

    let result = plugin
        .authenticate(&mut ctx, &ConsumerIndex::new(&[]))
        .await;
    // A rejected service-account bind is an operator problem, not the client's.
    assert_reject(result, Some(500));

    let recorded = recorded.read().expect("read recorded messages");
    let bind = recorded.first().expect("service bind was recorded");
    assert!(
        ldap_message_contains(bind, "  padded-secret  "),
        "the service bind must carry the configured password verbatim"
    );
    task.abort();
}

// ─── Required-group DN matching (advisory GHSA-96v4-fqx6-rm3f) ───────────

/// Direct-bind authentication whose group search returns exactly one entry
/// carrying a NON-matching `sAMAccountName`, so only the entry's own DN can
/// decide the required-group gate. No custom `group_filter` is configured, so
/// the built-in membership filter is itself the membership proof.
async fn assert_dn_fallback_group_result(
    entry_dn: &'static str,
    required_group: &'static str,
    expect_authorized: bool,
) {
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind group LDAP server");
    let port = listener.local_addr().expect("group LDAP local addr").port();
    let task = tokio::spawn(async move {
        let (mut user_stream, _) = listener.accept().await.expect("accept direct bind");
        read_ldap_message(&mut user_stream).await;
        user_stream
            .write_all(&bind_response(1, 0))
            .await
            .expect("write direct bind success");
        answer_canonical_identity_search(&mut user_stream).await;
        drop(user_stream);

        let (mut group_stream, _) = listener.accept().await.expect("accept group search");
        read_ldap_message(&mut group_stream).await;
        group_stream
            .write_all(&search_result_entry(
                1,
                entry_dn,
                &[("samaccountname", &["unrelated-group"])],
            ))
            .await
            .expect("write group search entry");
        group_stream
            .write_all(&search_result_done(1, 0))
            .await
            .expect("write group search done");
    });

    let plugin = LdapAuth::new(
        &json!({
            "ldap_url": format!("ldap://127.0.0.1:{port}"),
            "bind_dn_template": "uid={username},ou=users,dc=example,dc=com",
            "canonical_identity_attribute": "uid",
            "group_base_dn": "ou=groups,dc=example,dc=com",
            "group_attribute": "sAMAccountName",
            "required_groups": [required_group],
            "consumer_mapping": false
        }),
        http_client(),
    )
    .expect("valid direct-bind group config");
    let mut ctx = make_ctx();
    ctx.headers.insert(
        "authorization".to_string(),
        basic_header("alice", "user-secret"),
    );

    let result = plugin
        .authenticate(&mut ctx, &ConsumerIndex::new(&[]))
        .await;
    if expect_authorized {
        assert_continue(result);
    } else {
        assert_reject(result, Some(403));
    }
    task.abort();
}

#[tokio::test]
async fn test_group_dn_fallback_matches_the_entry_own_cn_rdn() {
    assert_dn_fallback_group_result("cn=admins,ou=groups,dc=example,dc=com", "admins", true).await;
}

#[tokio::test]
async fn test_group_dn_fallback_matches_the_configured_group_attribute_rdn() {
    assert_dn_fallback_group_result(
        "sAMAccountName=admins,ou=groups,dc=example,dc=com",
        "admins",
        true,
    )
    .await;
}

#[tokio::test]
async fn test_group_dn_fallback_matches_a_multi_valued_rdn_component() {
    assert_dn_fallback_group_result(
        "cn=admins+ou=engineering,ou=groups,dc=example,dc=com",
        "admins",
        true,
    )
    .await;
}

#[tokio::test]
async fn test_entry_nested_under_a_required_group_is_not_that_group() {
    assert_dn_fallback_group_result(
        "uid=visitors,cn=admins,ou=groups,dc=example,dc=com",
        "admins",
        false,
    )
    .await;
}

#[tokio::test]
async fn test_escaped_comma_rdn_cannot_impersonate_a_required_group() {
    assert_dn_fallback_group_result(
        "ou=visitors\\,cn=admins,ou=groups,dc=example,dc=com",
        "admins",
        false,
    )
    .await;
}

#[tokio::test]
async fn test_escaped_comma_inside_a_legitimate_group_rdn_still_matches() {
    assert_dn_fallback_group_result("cn=ad\\,mins,ou=groups,dc=example,dc=com", "ad,mins", true)
        .await;
}

#[tokio::test]
async fn test_hex_escaped_rdn_value_is_decoded_before_matching() {
    assert_dn_fallback_group_result("cn=ad\\2Cmins,ou=groups,dc=example,dc=com", "ad,mins", true)
        .await;
}

#[tokio::test]
async fn test_unparsable_group_dn_fails_closed() {
    assert_dn_fallback_group_result("not-a-distinguished-name", "admins", false).await;
}
