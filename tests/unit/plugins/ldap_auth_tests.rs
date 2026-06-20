//! Tests for ldap_auth plugin — config validation and credential extraction.
//!
//! Note: These tests validate plugin construction (config validation) and
//! credential parsing from the Authorization header. Actual LDAP server
//! interaction is not tested here since it requires a real LDAP server;
//! those scenarios are covered by integration/functional tests.

use ferrum_edge::consumer_index::ConsumerIndex;
use ferrum_edge::plugins::{
    HTTP_FAMILY_PROTOCOLS, Plugin, PluginHttpClient, RequestContext, ldap_auth::LdapAuth, priority,
};
use serde_json::json;

use super::plugin_utils::{assert_continue, assert_reject};

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
fn test_invalid_config_types_rejected() {
    let invalid_configs = [
        json!(null),
        json!(""),
        json!({
            "ldap_url": 123,
            "bind_dn_template": "uid={username},ou=users,dc=example,dc=com"
        }),
        json!({
            "ldap_url": "ldap://ldap.example.com:389",
            "bind_dn_template": 123
        }),
        json!({
            "ldap_url": "ldap://ldap.example.com:389",
            "bind_dn_template": "uid={username},ou=users,dc=example,dc=com",
            "starttls": "yes"
        }),
        json!({
            "ldap_url": "ldap://ldap.example.com:389",
            "bind_dn_template": "uid={username},ou=users,dc=example,dc=com",
            "required_groups": "admins"
        }),
        json!({
            "ldap_url": "ldap://ldap.example.com:389",
            "bind_dn_template": "uid={username},ou=users,dc=example,dc=com",
            "connect_timeout_seconds": 0
        }),
        json!({
            "ldap_url": "ldap://ldap.example.com:389",
            "bind_dn_template": "uid={username},ou=users,dc=example,dc=com",
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
            "bind_dn_template": "uid={username},ou=users,dc=example,dc=com"
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
            "bind_dn_template": "uid={username},ou=users,dc=example,dc=com"
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
            "bind_dn_template": "uid={username},ou=users,dc=example,dc=com"
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
fn test_required_groups_direct_bind_without_service_account_accepted() {
    // Finding #33: direct-bind + required_groups with no service account is a
    // footgun (the group search falls back to an ANONYMOUS bind, which many
    // directories restrict). The plugin emits a startup warning but does NOT
    // reject the config — anonymous group search is legitimate on directories
    // that permit it, so failing construction would break valid deployments.
    let result = LdapAuth::new(
        &json!({
            "ldap_url": "ldap://ldap.example.com:389",
            "bind_dn_template": "uid={username},ou=users,dc=example,dc=com",
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
            "ldap_url": "ldap://ldap.example.com:389",
            "bind_dn_template": "uid={username},ou=users,dc=example,dc=com",
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
    assert_eq!(plugin.priority(), priority::LDAP_AUTH);
    assert_eq!(plugin.priority(), 1250);
}

#[test]
fn test_ldap_auth_plugin_contract() {
    let plugin = LdapAuth::new(
        &json!({
            "ldap_url": "ldap://ldap.example.com:389",
            "bind_dn_template": "uid={username},ou=users,dc=example,dc=com"
        }),
        http_client(),
    )
    .unwrap();

    assert_eq!(plugin.supported_protocols(), HTTP_FAMILY_PROTOCOLS);
    assert!(plugin.is_auth_plugin());
    assert!(!plugin.modifies_request_headers());
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
            "bind_dn_template": "uid={username},ou=users,dc=example,dc=com"
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
            "bind_dn_template": "uid={username},ou=users,dc=corp,dc=internal"
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
            "ldap_url": "ldap://[2001:db8::50]:389",
            "bind_dn_template": "uid={username},ou=users,dc=example,dc=com"
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
            "ldap_url": "ldap://ldap.example.com:389",
            "bind_dn_template": "uid={username},ou=users,dc=example,dc=com"
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
            "bind_dn_template": "uid={username},ou=users,dc=example,dc=com"
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
            // Hold the connection briefly so the client reads the response
            // before the socket is torn down.
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        }
    });

    (port, task)
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

// ─── Cache bounding config tests ─────────────────────────────────────────

#[test]
fn test_ldap_auth_max_cache_entries_default() {
    // Create a valid config without max_cache_entries — default is 10000
    let config = json!({
        "ldap_url": "ldap://ldap.example.com:389",
        "bind_dn_template": "uid={username},ou=users,dc=example,dc=com"
    });
    let plugin = LdapAuth::new(&config, http_client()).unwrap();
    assert_eq!(plugin.name(), "ldap_auth");
}

#[test]
fn test_ldap_auth_max_cache_entries_custom() {
    let config = json!({
        "ldap_url": "ldap://ldap.example.com:389",
        "bind_dn_template": "uid={username},ou=users,dc=example,dc=com",
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
