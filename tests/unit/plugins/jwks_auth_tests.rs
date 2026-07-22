//! Tests for jwks_auth plugin

use ferrum_edge::ConsumerIndex;
use ferrum_edge::config::types::AuthMode;
use ferrum_edge::plugins::{
    HTTP_FAMILY_PROTOCOLS, JwtAuthAttributeValue, Plugin, PluginHttpClient, RequestContext,
    jwks_auth::JwksAuth, key_auth::KeyAuth, priority, validate_plugin_config,
    validate_plugin_config_with_policy,
};
use ferrum_edge::proxy::run_authentication_phase;
use serde_json::{Value, json};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use super::plugin_utils::{assert_continue, assert_reject, create_test_consumer};

static JWKS_TEST_PATH_COUNTER: AtomicUsize = AtomicUsize::new(0);

fn default_client() -> PluginHttpClient {
    PluginHttpClient::default()
}

fn unique_jwks_path(prefix: &str) -> String {
    let id = JWKS_TEST_PATH_COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("/{prefix}-{id}.json")
}

fn make_ctx() -> RequestContext {
    RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/test".to_string(),
    )
}

#[tokio::test]
async fn jwks_marks_forwarded_custom_query_locations_for_opa_redaction() {
    let plugin = JwksAuth::new(
        &json!({
            "providers": [{
                "jwks_uri": "https://idp.example.com/.well-known/jwks.json",
                "from_params": ["sso_token"],
                "forward_original_token": true
            }]
        }),
        default_client(),
    )
    .unwrap();
    let mut ctx = make_ctx();
    ctx.query_params
        .insert("sso_token".to_string(), "forwarded-jwt".to_string());

    plugin.mark_query_credentials_for_redaction(&mut ctx);

    assert_eq!(
        ctx.metadata
            .get("auth.query_credential_param.sso_token")
            .map(String::as_str),
        Some("true")
    );
    assert_eq!(
        ctx.query_params.get("sso_token").map(String::as_str),
        Some("forwarded-jwt"),
        "OPA redaction markers must not change backend forwarding semantics"
    );
}

fn create_consumer(username: &str) -> ferrum_edge::config::types::Consumer {
    use chrono::Utc;
    ferrum_edge::config::types::Consumer {
        id: format!("{}-id", username),
        namespace: ferrum_edge::config::types::default_namespace(),
        username: username.to_string(),
        custom_id: None,
        credentials: HashMap::new(),
        acl_groups: Vec::new(),
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

fn create_consumer_with_custom_id(
    username: &str,
    custom_id: &str,
) -> ferrum_edge::config::types::Consumer {
    use chrono::Utc;
    ferrum_edge::config::types::Consumer {
        id: format!("{}-id", username),
        namespace: ferrum_edge::config::types::default_namespace(),
        username: username.to_string(),
        custom_id: Some(custom_id.to_string()),
        credentials: HashMap::new(),
        acl_groups: Vec::new(),
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

fn claims_with_default_exp(claims: &Value) -> Value {
    let mut claims = claims.clone();
    if let Some(obj) = claims.as_object_mut() {
        obj.entry("exp")
            .or_insert_with(|| json!(chrono::Utc::now().timestamp() + 3600));
    }
    claims
}

fn create_rs256_token_exact(claims: &Value, private_key_pem: &[u8]) -> String {
    use jsonwebtoken::{EncodingKey, Header, encode};
    let mut header = Header::new(jsonwebtoken::Algorithm::RS256);
    header.kid = Some("test-key-1".to_string());
    encode(
        &header,
        claims,
        &EncodingKey::from_rsa_pem(private_key_pem).unwrap(),
    )
    .unwrap()
}

fn create_rs256_token(claims: &Value, private_key_pem: &[u8]) -> String {
    let claims = claims_with_default_exp(claims);
    create_rs256_token_exact(&claims, private_key_pem)
}

#[allow(dead_code)]
fn create_rs256_token_with_kid(claims: &Value, private_key_pem: &[u8], kid: &str) -> String {
    use jsonwebtoken::{EncodingKey, Header, encode};
    let mut header = Header::new(jsonwebtoken::Algorithm::RS256);
    header.kid = Some(kid.to_string());
    let claims = claims_with_default_exp(claims);
    encode(
        &header,
        &claims,
        &EncodingKey::from_rsa_pem(private_key_pem).unwrap(),
    )
    .unwrap()
}

fn create_rs256_token_no_kid(claims: &Value, private_key_pem: &[u8]) -> String {
    use jsonwebtoken::{EncodingKey, Header, encode};
    let header = Header::new(jsonwebtoken::Algorithm::RS256);
    let claims = claims_with_default_exp(claims);
    encode(
        &header,
        &claims,
        &EncodingKey::from_rsa_pem(private_key_pem).unwrap(),
    )
    .unwrap()
}

/// Build a JWKS JSON response from an RSA public key PEM.
fn build_rsa_jwks_from_pem(public_key_pem: &[u8]) -> serde_json::Value {
    build_rsa_jwks_from_pem_with_kid(public_key_pem, "test-key-1")
}

fn build_rsa_jwks_from_pem_with_kid(public_key_pem: &[u8], kid: &str) -> serde_json::Value {
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

    let pem_str = std::str::from_utf8(public_key_pem).unwrap();
    let der = extract_der_from_pem(pem_str);
    let (n, e) = parse_rsa_public_key_der(&der);

    json!({
        "keys": [{
            "kty": "RSA",
            "kid": kid,
            "use": "sig",
            "alg": "RS256",
            "n": URL_SAFE_NO_PAD.encode(&n),
            "e": URL_SAFE_NO_PAD.encode(&e)
        }]
    })
}

fn extract_der_from_pem(pem: &str) -> Vec<u8> {
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;
    let b64: String = pem
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect();
    STANDARD.decode(&b64).unwrap()
}

fn parse_rsa_public_key_der(der: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let mut pos = 0;
    assert_eq!(der[pos], 0x30);
    pos += 1;
    let (_outer_len, consumed) = parse_asn1_length(&der[pos..]);
    pos += consumed;
    assert_eq!(der[pos], 0x30);
    pos += 1;
    let (algo_len, consumed) = parse_asn1_length(&der[pos..]);
    pos += consumed;
    pos += algo_len;
    assert_eq!(der[pos], 0x03);
    pos += 1;
    let (_bs_len, consumed) = parse_asn1_length(&der[pos..]);
    pos += consumed;
    pos += 1;
    assert_eq!(der[pos], 0x30);
    pos += 1;
    let (_inner_len, consumed) = parse_asn1_length(&der[pos..]);
    pos += consumed;
    assert_eq!(der[pos], 0x02);
    pos += 1;
    let (n_len, consumed) = parse_asn1_length(&der[pos..]);
    pos += consumed;
    let mut n = der[pos..pos + n_len].to_vec();
    pos += n_len;
    if !n.is_empty() && n[0] == 0 {
        n.remove(0);
    }
    assert_eq!(der[pos], 0x02);
    pos += 1;
    let (e_len, consumed) = parse_asn1_length(&der[pos..]);
    pos += consumed;
    let e = der[pos..pos + e_len].to_vec();
    (n, e)
}

fn parse_asn1_length(data: &[u8]) -> (usize, usize) {
    if data[0] < 0x80 {
        (data[0] as usize, 1)
    } else {
        let num_bytes = (data[0] & 0x7f) as usize;
        let mut length = 0usize;
        for &byte in &data[1..=num_bytes] {
            length = (length << 8) | byte as usize;
        }
        (length, 1 + num_bytes)
    }
}

/// Helper: start a wiremock server serving a JWKS endpoint and return (server, jwks_uri).
async fn start_jwks_server(public_key_pem: &[u8]) -> (wiremock::MockServer, String) {
    let mock_server = wiremock::MockServer::start().await;
    let jwks_json = build_rsa_jwks_from_pem(public_key_pem);
    let jwks_path = unique_jwks_path("jwks");
    wiremock::Mock::given(wiremock::matchers::method("GET"))
        .and(wiremock::matchers::path(jwks_path.clone()))
        .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(&jwks_json))
        .mount(&mock_server)
        .await;
    let jwks_uri = format!("{}{}", mock_server.uri(), jwks_path);
    (mock_server, jwks_uri)
}

async fn wait_for_received_request_count(server: &wiremock::MockServer, at_least: usize) -> usize {
    let deadline = tokio::time::Instant::now() + tokio::time::Duration::from_secs(2);
    loop {
        let count = server
            .received_requests()
            .await
            .map(|requests| requests.len())
            .unwrap_or(0);
        if count >= at_least {
            return count;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "timed out waiting for {at_least} JWKS request(s), observed {count}"
        );
        tokio::time::sleep(tokio::time::Duration::from_millis(20)).await;
    }
}

/// Helper to make a single-provider config
fn single_provider_config(jwks_uri: &str) -> serde_json::Value {
    json!({
        "providers": [{
            "jwks_uri": jwks_uri
        }]
    })
}

fn endpoint_config(field: &str, value: &str) -> serde_json::Value {
    let mut provider = serde_json::Map::new();
    provider.insert(field.to_string(), json!(value));
    json!({"providers": [provider]})
}

fn start_background_tasks(plugin: &JwksAuth) {
    plugin
        .start_background_tasks()
        .expect("test runtime should start JWKS tasks");
    plugin.commit_background_tasks();
}

// ─── Basic Plugin Tests ────────────────────────────────────────────────

#[tokio::test]
async fn test_jwks_auth_plugin_creation() {
    let mock_server = wiremock::MockServer::start().await;
    let jwks_uri = format!("{}{}", mock_server.uri(), unique_jwks_path("jwks"));
    let plugin = JwksAuth::new(&single_provider_config(&jwks_uri), default_client()).unwrap();
    assert_eq!(plugin.name(), "jwks_auth");
}

#[tokio::test]
async fn test_jwks_auth_plugin_contract_and_warmup_metadata() {
    let mock_server = wiremock::MockServer::start().await;
    let jwks_uri = format!("{}{}", mock_server.uri(), unique_jwks_path("jwks"));
    let plugin = JwksAuth::new(&single_provider_config(&jwks_uri), default_client()).unwrap();

    assert_eq!(plugin.name(), "jwks_auth");
    assert_eq!(plugin.priority(), priority::JWKS_AUTH);
    assert_eq!(plugin.supported_protocols(), HTTP_FAMILY_PROTOCOLS);
    assert!(plugin.is_auth_plugin());
    assert!(!plugin.modifies_request_headers());
    assert!(!plugin.modifies_request_body());
    assert!(!plugin.requires_request_body_buffering());
    assert!(!plugin.requires_response_body_buffering());
    assert!(!plugin.applies_after_proxy_on_reject());
    assert_eq!(plugin.active_jwks_uris(), vec![jwks_uri]);
    assert_eq!(plugin.warmup_hostnames(), vec!["127.0.0.1".to_string()]);
}

#[tokio::test]
async fn test_jwks_auth_requires_providers_array() {
    let result = JwksAuth::new(&json!({}), default_client());
    assert!(result.is_err());
    assert!(result.as_ref().err().unwrap().contains("providers"));
}

#[tokio::test]
async fn test_jwks_auth_requires_non_empty_providers() {
    let result = JwksAuth::new(&json!({"providers": []}), default_client());
    assert!(result.is_err());
}

#[tokio::test]
async fn test_jwks_auth_provider_requires_jwks_or_discovery() {
    let result = JwksAuth::new(
        &json!({"providers": [{"issuer": "https://example.com"}]}),
        default_client(),
    );
    assert!(result.is_err());
    assert!(result.as_ref().err().unwrap().contains("jwks_uri"));
}

#[tokio::test]
async fn test_jwks_auth_rejects_non_object_config() {
    let result = JwksAuth::new(&json!(true), default_client());
    assert!(result.is_err());
    assert!(
        result
            .as_ref()
            .err()
            .unwrap()
            .contains("config must be an object")
    );
}

#[tokio::test]
async fn test_jwks_auth_rejects_zero_refresh_interval() {
    let mock_server = wiremock::MockServer::start().await;
    let result = JwksAuth::new(
        &json!({
            "providers": [{"jwks_uri": format!("{}/jwks", mock_server.uri())}],
            "jwks_refresh_interval_secs": 0
        }),
        default_client(),
    );
    assert!(result.is_err());
    assert!(
        result
            .as_ref()
            .err()
            .unwrap()
            .contains("jwks_refresh_interval_secs")
    );
}

#[tokio::test]
async fn test_jwks_auth_rejects_invalid_provider_entry() {
    let result = JwksAuth::new(&json!({"providers": [42]}), default_client());
    assert!(result.is_err());
    assert!(result.as_ref().err().unwrap().contains("provider[0]"));
}

#[tokio::test]
async fn test_jwks_auth_rejects_invalid_jwks_url() {
    let result = JwksAuth::new(
        &json!({"providers": [{"jwks_uri": "file:///tmp/jwks.json"}]}),
        default_client(),
    );
    assert!(result.is_err());
    assert!(result.as_ref().err().unwrap().contains("http or https"));
}

#[test]
fn synchronous_validation_of_remote_providers_is_runtime_free() {
    use ferrum_edge::plugins::utils::jwks_cache::cached_refresh_state;

    let direct_uri = "https://keys.example.com/.well-known/jwks.json";
    validate_plugin_config(
        "jwks_auth",
        &json!({"providers": [{"jwks_uri": direct_uri}]}),
    )
    .expect("direct remote provider should validate without a Tokio runtime");
    validate_plugin_config(
        "jwks_auth",
        &json!({
            "providers": [{
                "discovery_url": "https://issuer.example.com/.well-known/openid-configuration"
            }]
        }),
    )
    .expect("discovery provider should validate without a Tokio runtime");
    assert!(
        cached_refresh_state(direct_uri).is_none(),
        "validation must not populate the process-wide refresh cache"
    );

    let staged = JwksAuth::new(
        &json!({"providers": [{"jwks_uri": direct_uri}]}),
        default_client(),
    )
    .expect("pure construction should succeed");
    assert!(
        staged.start_background_tasks().is_err(),
        "only committed runtime generations may activate remote workers"
    );

    assert!(
        validate_plugin_config(
            "jwks_auth",
            &json!({"providers": [{"jwks_uri": "not a URL"}]})
        )
        .is_err(),
        "malformed providers must still return structured validation errors"
    );
}

#[test]
fn dpop_replay_cache_uses_published_default_capacity() {
    let plugin = JwksAuth::new(
        &json!({
            "providers": [{
                "jwks": {"keys": []},
                "require_dpop": true
            }]
        }),
        default_client(),
    )
    .expect("valid inline provider");

    assert_eq!(
        plugin.dpop_jti_cache_capacities(),
        vec![Some(
            ferrum_edge::plugins::jwks_auth::DEFAULT_DPOP_JTI_CACHE_MAX_ENTRIES
        )]
    );
}

#[test]
fn unknown_security_control_fields_are_rejected() {
    for config in [
        json!({
            "providers": [{"jwks": {"keys": []}}],
            "required_scope": ["admin"]
        }),
        json!({
            "providers": [{
                "jwks": {"keys": []},
                "required_dpop": true
            }]
        }),
        json!({
            "providers": [{
                "jwks": {"keys": []},
                "from_headers": [{"name": "x-token", "prefx": "Bearer "}]
            }]
        }),
    ] {
        let error = JwksAuth::new(&config, default_client())
            .err()
            .expect("unknown field must fail closed");
        assert!(error.contains("unknown field"), "got: {error}");
    }
}

#[test]
fn remote_key_endpoints_require_https_and_reject_userinfo() {
    for field in ["jwks_uri", "discovery_url"] {
        let remote_http = endpoint_config(field, "http://idp.example.com/keys");
        let error = JwksAuth::new(&remote_http, default_client())
            .err()
            .expect("remote cleartext endpoint must reject");
        assert!(error.contains("must use https"), "got: {error}");

        for local_endpoint in [
            "http://127.0.0.1:8080/keys",
            "http://[::1]:8080/keys",
            "http://localhost:8080/keys",
        ] {
            JwksAuth::new(&endpoint_config(field, local_endpoint), default_client())
                .expect("loopback and localhost remain available for local development");
        }

        let with_userinfo = endpoint_config(field, "https://user:secret@idp.example.com/keys");
        let error = JwksAuth::new(&with_userinfo, default_client())
            .err()
            .expect("URL credentials must reject");
        assert!(error.contains("userinfo"), "got: {error}");
    }
}

#[test]
fn policy_validation_screens_jwks_literal_ips_at_admission() {
    use ferrum_edge::config::{BackendAllowIps, BackendEgressPolicy};

    let policy = BackendEgressPolicy::from_env(BackendAllowIps::Both, "", "", true)
        .expect("valid default egress policy");
    for field in ["jwks_uri", "discovery_url"] {
        for denied in ["https://169.254.169.254/keys", "https://[fe80::1]/keys"] {
            let config = endpoint_config(field, denied);
            let error = validate_plugin_config_with_policy("jwks_auth", &config, &policy)
                .expect_err("dangerous literal must be rejected at config admission");
            assert!(error.contains(field), "got: {error}");
            assert!(error.contains("denied by backend egress policy"));
            validate_plugin_config_with_policy(
                "jwks_auth",
                &config,
                &BackendEgressPolicy::unrestricted(),
            )
            .expect("explicit unrestricted policy should admit the literal");
        }

        for allowed in ["https://127.0.0.1/keys", "https://[::1]/keys"] {
            validate_plugin_config_with_policy(
                "jwks_auth",
                &endpoint_config(field, allowed),
                &policy,
            )
            .expect("loopback literal should remain allowed by the default policy");
        }
    }
}

#[tokio::test]
async fn test_jwks_auth_rejects_empty_authority_jwks_uri() {
    let result = JwksAuth::new(
        &json!({"providers": [{"jwks_uri": "https:///jwks.json"}]}),
        default_client(),
    );
    assert!(result.is_err());
    let err = result.as_ref().err().unwrap();
    assert!(err.contains("jwks_uri"), "got: {err}");
    assert!(err.contains("hostname"), "got: {err}");
}

#[tokio::test]
async fn test_jwks_auth_rejects_empty_authority_discovery_url() {
    let result = JwksAuth::new(
        &json!({"providers": [{"discovery_url": "https:///.well-known/openid-configuration"}]}),
        default_client(),
    );
    assert!(result.is_err());
    let err = result.as_ref().err().unwrap();
    assert!(err.contains("discovery_url"), "got: {err}");
    assert!(err.contains("hostname"), "got: {err}");
}

#[tokio::test]
async fn test_jwks_auth_warmup_hostnames_unbrackets_ipv6_literal() {
    let plugin = JwksAuth::new(
        &json!({"providers": [{"jwks_uri": "https://[2001:db8::40]/jwks.json"}]}),
        default_client(),
    )
    .unwrap();

    assert_eq!(plugin.warmup_hostnames(), vec!["2001:db8::40".to_string()]);
}

#[tokio::test]
async fn test_jwks_auth_rejects_invalid_claim_path() {
    let mock_server = wiremock::MockServer::start().await;
    let result = JwksAuth::new(
        &json!({
            "providers": [{"jwks_uri": format!("{}/jwks", mock_server.uri())}],
            "consumer_identity_claim": "realm..sub"
        }),
        default_client(),
    );
    assert!(result.is_err());
    assert!(
        result
            .as_ref()
            .err()
            .unwrap()
            .contains("without empty segments")
    );
}

#[tokio::test]
async fn test_jwks_auth_rejects_malformed_required_scopes() {
    let mock_server = wiremock::MockServer::start().await;
    let result = JwksAuth::new(
        &json!({
            "providers": [{
                "jwks_uri": format!("{}/jwks", mock_server.uri()),
                "required_scopes": "read"
            }]
        }),
        default_client(),
    );
    assert!(result.is_err());
    assert!(result.as_ref().err().unwrap().contains("required_scopes"));
}

#[tokio::test]
async fn test_jwks_auth_rejects_empty_required_role() {
    let mock_server = wiremock::MockServer::start().await;
    let result = JwksAuth::new(
        &json!({
            "providers": [{
                "jwks_uri": format!("{}/jwks", mock_server.uri()),
                "required_roles": [""]
            }]
        }),
        default_client(),
    );
    assert!(result.is_err());
    assert!(result.as_ref().err().unwrap().contains("required_roles[0]"));
}

#[tokio::test]
async fn test_jwks_auth_warmup_hostnames_includes_discovery_url_before_resolution() {
    let mock_server = wiremock::MockServer::start().await;
    let discovery_url = format!("{}/.well-known/openid-configuration", mock_server.uri());
    let plugin = JwksAuth::new(
        &json!({"providers": [{"discovery_url": discovery_url}]}),
        default_client(),
    )
    .unwrap();

    assert_eq!(plugin.warmup_hostnames(), vec!["127.0.0.1".to_string()]);
    assert!(plugin.active_jwks_uris().is_empty());
}

#[tokio::test]
async fn test_jwks_auth_oidc_discovery_eager_fetches_without_duplicate_jwks_call() {
    let public_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_public.pem");
    let server = wiremock::MockServer::start().await;
    let jwks_path = unique_jwks_path("oidc-jwks");
    let jwks_uri = format!("{}{}", server.uri(), jwks_path);
    let discovery_path = unique_jwks_path("oidc-discovery");
    let discovery_url = format!("{}{}", server.uri(), discovery_path);

    wiremock::Mock::given(wiremock::matchers::method("GET"))
        .and(wiremock::matchers::path(jwks_path))
        .respond_with(
            wiremock::ResponseTemplate::new(200)
                .set_body_json(build_rsa_jwks_from_pem(public_key_pem)),
        )
        .mount(&server)
        .await;
    wiremock::Mock::given(wiremock::matchers::method("GET"))
        .and(wiremock::matchers::path(discovery_path))
        .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(json!({
            "jwks_uri": jwks_uri
        })))
        .mount(&server)
        .await;

    let plugin = JwksAuth::new(
        &json!({
            "providers": [{"discovery_url": discovery_url}],
            "jwks_refresh_interval_secs": 3600
        }),
        default_client(),
    )
    .unwrap();
    start_background_tasks(&plugin);

    let initial_count = wait_for_received_request_count(&server, 2).await;
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    let final_count = server
        .received_requests()
        .await
        .map(|requests| requests.len())
        .unwrap_or(0);
    assert_eq!(initial_count, 2);
    assert_eq!(final_count, 2);
}

#[tokio::test]
async fn oversized_discovery_document_is_rejected_before_deserialization() {
    let server = wiremock::MockServer::start().await;
    let discovery_path = unique_jwks_path("oidc-discovery");
    let discovery_url = format!("{}{}", server.uri(), discovery_path);
    wiremock::Mock::given(wiremock::matchers::method("GET"))
        .and(wiremock::matchers::path(discovery_path))
        .respond_with(
            wiremock::ResponseTemplate::new(200).set_body_bytes(vec![b' '; 128 * 1024 + 1]),
        )
        .mount(&server)
        .await;
    let plugin = JwksAuth::new(
        &json!({
            "providers": [{
                "discovery_url": discovery_url
            }]
        }),
        default_client(),
    )
    .unwrap();
    start_background_tasks(&plugin);

    wait_for_discovery_request(&server).await;
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
    assert!(plugin.active_jwks_uris().is_empty());
}

#[tokio::test]
async fn equivalent_discovery_generation_reuses_last_good_store_during_outage() {
    let _cache_guard = super::jwks_cache_tests::cache_test_lock().lock().await;
    let private_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_private.pem");
    let public_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_public.pem");
    let server = wiremock::MockServer::start().await;
    let jwks_path = unique_jwks_path("reload-jwks");
    let jwks_uri = format!("{}{}", server.uri(), jwks_path);
    let discovery_path = unique_jwks_path("oidc-discovery");
    let discovery_url = format!("{}{discovery_path}", server.uri());

    wiremock::Mock::given(wiremock::matchers::method("GET"))
        .and(wiremock::matchers::path(jwks_path))
        .respond_with(
            wiremock::ResponseTemplate::new(200)
                .set_body_json(build_rsa_jwks_from_pem(public_key_pem)),
        )
        .mount(&server)
        .await;
    wiremock::Mock::given(wiremock::matchers::method("GET"))
        .and(wiremock::matchers::path(discovery_path.clone()))
        .respond_with(
            wiremock::ResponseTemplate::new(200)
                .set_body_json(json!({"jwks_uri": jwks_uri.clone()})),
        )
        .up_to_n_times(1)
        .with_priority(1)
        .mount(&server)
        .await;
    wiremock::Mock::given(wiremock::matchers::method("GET"))
        .and(wiremock::matchers::path(discovery_path))
        .respond_with(wiremock::ResponseTemplate::new(503))
        .with_priority(2)
        .mount(&server)
        .await;

    let config = json!({
        "providers": [{"discovery_url": discovery_url}],
        "jwks_refresh_interval_secs": 3600
    });
    let original = JwksAuth::new(&config, default_client()).unwrap();
    start_background_tasks(&original);
    let deadline = tokio::time::Instant::now() + tokio::time::Duration::from_secs(2);
    while original.active_jwks_uris() != vec![jwks_uri.clone()] {
        assert!(tokio::time::Instant::now() < deadline);
        tokio::time::sleep(tokio::time::Duration::from_millis(20)).await;
    }
    original.warmup_jwks().await;

    let replacement = JwksAuth::new(&config, default_client()).unwrap();
    start_background_tasks(&replacement);
    assert_eq!(
        replacement.active_jwks_uris(),
        vec![jwks_uri.clone()],
        "the replacement generation must hold the resolved store before publication retention"
    );
    drop(original);

    let token = create_rs256_token(&json!({"sub": "still-valid"}), private_key_pem);
    let mut ctx = make_ctx();
    ctx.headers
        .insert("authorization".to_string(), format!("Bearer {token}"));
    let result = replacement
        .authenticate(&mut ctx, &ConsumerIndex::new(&[]))
        .await;
    assert_continue(result);
    assert_eq!(ctx.authenticated_identity.as_deref(), Some("still-valid"));
}

#[tokio::test]
async fn failed_discovery_replacement_retires_unpublished_candidate_store() {
    use ferrum_edge::plugins::utils::jwks_cache::cached_refresh_state;

    let _cache_guard = super::jwks_cache_tests::cache_test_lock().lock().await;
    let public_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_public.pem");
    let server = wiremock::MockServer::start().await;
    let original_path = unique_jwks_path("original-jwks");
    let candidate_path = unique_jwks_path("candidate-jwks");
    let original_uri = format!("{}{}", server.uri(), original_path);
    let candidate_uri = format!("{}{}", server.uri(), candidate_path);
    let discovery_path = unique_jwks_path("oidc-discovery");
    let discovery_url = format!("{}{discovery_path}", server.uri());

    wiremock::Mock::given(wiremock::matchers::method("GET"))
        .and(wiremock::matchers::path(original_path))
        .respond_with(
            wiremock::ResponseTemplate::new(200)
                .set_body_json(build_rsa_jwks_from_pem(public_key_pem)),
        )
        .mount(&server)
        .await;
    wiremock::Mock::given(wiremock::matchers::method("GET"))
        .and(wiremock::matchers::path(candidate_path))
        .respond_with(
            wiremock::ResponseTemplate::new(503).set_delay(tokio::time::Duration::from_millis(150)),
        )
        .mount(&server)
        .await;
    wiremock::Mock::given(wiremock::matchers::method("GET"))
        .and(wiremock::matchers::path(discovery_path.clone()))
        .respond_with(
            wiremock::ResponseTemplate::new(200)
                .set_body_json(json!({"jwks_uri": original_uri.clone()})),
        )
        .up_to_n_times(1)
        .with_priority(1)
        .mount(&server)
        .await;
    wiremock::Mock::given(wiremock::matchers::method("GET"))
        .and(wiremock::matchers::path(discovery_path))
        .respond_with(
            wiremock::ResponseTemplate::new(200)
                .set_body_json(json!({"jwks_uri": candidate_uri.clone()})),
        )
        .with_priority(2)
        .mount(&server)
        .await;

    let config = json!({
        "providers": [{"discovery_url": discovery_url}],
        "jwks_refresh_interval_secs": 3600
    });
    let original = JwksAuth::new(&config, default_client()).unwrap();
    start_background_tasks(&original);
    let deadline = tokio::time::Instant::now() + tokio::time::Duration::from_secs(2);
    while original.active_jwks_uris() != vec![original_uri.clone()] {
        assert!(tokio::time::Instant::now() < deadline);
        tokio::time::sleep(tokio::time::Duration::from_millis(20)).await;
    }
    original.warmup_jwks().await;

    let replacement = JwksAuth::new(&config, default_client()).unwrap();
    start_background_tasks(&replacement);
    drop(original);

    let deadline = tokio::time::Instant::now() + tokio::time::Duration::from_secs(2);
    while cached_refresh_state(&candidate_uri).is_none() {
        assert!(tokio::time::Instant::now() < deadline);
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
    }
    while cached_refresh_state(&candidate_uri).is_some() {
        assert!(tokio::time::Instant::now() < deadline);
        tokio::time::sleep(tokio::time::Duration::from_millis(20)).await;
    }
    assert_eq!(replacement.active_jwks_uris(), vec![original_uri]);
}

/// Wait until the OIDC discovery endpoint has been hit at least once, proving
/// the discovery flow actually ran (so a "no jwks fetch" assertion reflects
/// validation rejecting the discovered URI, not discovery never executing).
async fn wait_for_discovery_request(server: &wiremock::MockServer) {
    let deadline = tokio::time::Instant::now() + tokio::time::Duration::from_secs(2);
    loop {
        let count = server
            .received_requests()
            .await
            .map(|requests| requests.len())
            .unwrap_or(0);
        if count >= 1 {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "timed out waiting for the OIDC discovery request"
        );
        tokio::time::sleep(tokio::time::Duration::from_millis(20)).await;
    }
}

/// Start an OIDC discovery server whose discovery document advertises the given
/// `jwks_uri` value, and return `(server, discovery_url)`.
async fn start_oidc_discovery_server(jwks_uri: &str) -> (wiremock::MockServer, String) {
    let discovery_server = wiremock::MockServer::start().await;
    let discovery_path = unique_jwks_path("oidc-discovery");
    wiremock::Mock::given(wiremock::matchers::method("GET"))
        .and(wiremock::matchers::path(discovery_path.clone()))
        .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(json!({
            "jwks_uri": jwks_uri
        })))
        .mount(&discovery_server)
        .await;
    let discovery_url = format!("{}{discovery_path}", discovery_server.uri());
    (discovery_server, discovery_url)
}

/// Regression test for finding #5 (SSRF): an OIDC discovery document whose
/// `jwks_uri` points at a *different host* than the discovery endpoint — here
/// the cloud metadata endpoint `169.254.169.254` — must be rejected. A spoofed,
/// compromised, or tampered discovery document must not be able to steer the
/// gateway into a server-side request to an attacker-chosen host inside the
/// trust boundary. The provider's JWKS store must never be populated from it.
#[tokio::test]
async fn test_jwks_auth_oidc_discovery_rejects_metadata_endpoint_jwks_uri() {
    // Different host than the loopback discovery server -> blocked by the
    // same-host check before any fetch is attempted.
    let malicious_jwks_uri = "http://169.254.169.254/latest/meta-data/jwks.json";
    let (discovery_server, discovery_url) = start_oidc_discovery_server(malicious_jwks_uri).await;

    let plugin = JwksAuth::new(
        &json!({
            "providers": [{"discovery_url": discovery_url}],
            "jwks_refresh_interval_secs": 3600
        }),
        default_client(),
    )
    .unwrap();
    start_background_tasks(&plugin);

    wait_for_discovery_request(&discovery_server).await;
    // Give any (incorrect) follow-on fetch a chance to publish a store.
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    assert!(
        plugin.active_jwks_uris().is_empty(),
        "cross-host discovery jwks_uri must not create an active store, got: {:?}",
        plugin.active_jwks_uris()
    );
}

/// Regression test for finding #5 (SSRF, userinfo host-confusion): a jwks_uri
/// that embeds the discovery host in the URL **userinfo** while pointing the
/// real authority at a metadata/internal IP
/// (`http://127.0.0.1@169.254.169.254/...`) must be rejected. The same-host
/// check parses the authority host (`169.254.169.254`) rather than substring-
/// matching, so the userinfo cannot smuggle a spurious same-host match. The
/// discovery server binds 127.0.0.1, so its host equals the userinfo here.
#[tokio::test]
async fn test_jwks_auth_oidc_discovery_rejects_userinfo_host_confusion_jwks_uri() {
    let malicious_jwks_uri = "http://127.0.0.1@169.254.169.254/latest/meta-data/jwks.json";
    let (discovery_server, discovery_url) = start_oidc_discovery_server(malicious_jwks_uri).await;

    let plugin = JwksAuth::new(
        &json!({
            "providers": [{"discovery_url": discovery_url}],
            "jwks_refresh_interval_secs": 3600
        }),
        default_client(),
    )
    .unwrap();
    start_background_tasks(&plugin);

    wait_for_discovery_request(&discovery_server).await;
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    assert!(
        plugin.active_jwks_uris().is_empty(),
        "userinfo host-confusion jwks_uri must not create an active store, got: {:?}",
        plugin.active_jwks_uris()
    );
}

/// Regression test for finding #5 (SSRF): an OIDC discovery document whose
/// `jwks_uri` uses a non-URL scheme (`file:`) must be rejected.
#[tokio::test]
async fn test_jwks_auth_oidc_discovery_rejects_non_http_scheme_jwks_uri() {
    let malicious_jwks_uri = "file:///etc/passwd";
    let (discovery_server, discovery_url) = start_oidc_discovery_server(malicious_jwks_uri).await;

    let plugin = JwksAuth::new(
        &json!({
            "providers": [{"discovery_url": discovery_url}],
            "jwks_refresh_interval_secs": 3600
        }),
        default_client(),
    )
    .unwrap();
    start_background_tasks(&plugin);

    wait_for_discovery_request(&discovery_server).await;
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    assert!(
        plugin.active_jwks_uris().is_empty(),
        "non-http-scheme discovery jwks_uri must not create an active store, got: {:?}",
        plugin.active_jwks_uris()
    );
}

/// Defense-in-depth for discovered JWKS origin validation: same host is not
/// sufficient if the discovery document pivots to a different port on that
/// host. The OIDC-discovered JWKS URL must match scheme, host, and effective
/// port with the discovery URL.
#[tokio::test]
async fn test_jwks_auth_oidc_discovery_rejects_same_host_different_port_jwks_uri() {
    let jwks_server = wiremock::MockServer::start().await;
    let jwks_uri = format!("{}/jwks.json", jwks_server.uri());
    let (discovery_server, discovery_url) = start_oidc_discovery_server(&jwks_uri).await;

    let plugin = JwksAuth::new(
        &json!({
            "providers": [{"discovery_url": discovery_url}],
            "jwks_refresh_interval_secs": 3600
        }),
        default_client(),
    )
    .unwrap();
    start_background_tasks(&plugin);

    wait_for_discovery_request(&discovery_server).await;
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    assert!(
        plugin.active_jwks_uris().is_empty(),
        "same-host different-port discovery jwks_uri must not create an active store, got: {:?}",
        plugin.active_jwks_uris()
    );
    assert_eq!(
        jwks_server
            .received_requests()
            .await
            .map(|requests| requests.len())
            .unwrap_or(0),
        0,
        "rejected different-port jwks_uri must not be fetched"
    );
}

/// Regression coverage for the redirect bypass variant: a same-origin
/// discovered JWKS URL that responds with a 3xx must not be followed to a
/// different target. The JWKS fetch sees the 302 as the final response and
/// fails closed without contacting the Location endpoint.
#[tokio::test]
async fn test_jwks_auth_oidc_discovery_does_not_follow_jwks_redirects() {
    let discovery_server = wiremock::MockServer::start().await;
    let redirect_target = wiremock::MockServer::start().await;
    let redirect_path = unique_jwks_path("redirect-jwks");
    let jwks_uri = format!("{}{}", discovery_server.uri(), redirect_path);
    let discovery_path = unique_jwks_path("oidc-discovery");

    wiremock::Mock::given(wiremock::matchers::method("GET"))
        .and(wiremock::matchers::path(redirect_path))
        .respond_with(wiremock::ResponseTemplate::new(302).insert_header(
            "Location",
            format!("{}/metadata-jwks", redirect_target.uri()),
        ))
        .mount(&discovery_server)
        .await;
    wiremock::Mock::given(wiremock::matchers::method("GET"))
        .and(wiremock::matchers::path(discovery_path.clone()))
        .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(json!({
            "jwks_uri": jwks_uri.clone()
        })))
        .mount(&discovery_server)
        .await;
    wiremock::Mock::given(wiremock::matchers::method("GET"))
        .and(wiremock::matchers::path("/metadata-jwks"))
        .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(json!({ "keys": [] })))
        .mount(&redirect_target)
        .await;

    let discovery_url = format!("{}{discovery_path}", discovery_server.uri());
    let plugin = JwksAuth::new(
        &json!({
            "providers": [{"discovery_url": discovery_url}],
            "jwks_refresh_interval_secs": 3600
        }),
        default_client(),
    )
    .unwrap();
    start_background_tasks(&plugin);

    let deadline = tokio::time::Instant::now() + tokio::time::Duration::from_secs(2);
    loop {
        if plugin.active_jwks_uris() == vec![jwks_uri.clone()] {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "timed out waiting for redirecting jwks_uri store to become active, got: {:?}",
            plugin.active_jwks_uris()
        );
        tokio::time::sleep(tokio::time::Duration::from_millis(20)).await;
    }
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    assert_eq!(
        redirect_target
            .received_requests()
            .await
            .map(|requests| requests.len())
            .unwrap_or(0),
        0,
        "discovered JWKS fetch must not follow redirects"
    );
}

/// Positive control for finding #5: a discovery document whose `jwks_uri` shares
/// the discovery host (the normal OIDC case) is still accepted and fetched, so
/// the SSRF hardening does not break legitimate same-host discovery. Both the
/// discovery document and the JWKS are served by the same wiremock server, so
/// they share host:port — the discovered jwks_uri passes the same-host check.
#[tokio::test]
async fn test_jwks_auth_oidc_discovery_accepts_same_host_jwks_uri() {
    let public_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_public.pem");
    let server = wiremock::MockServer::start().await;
    let jwks_path = unique_jwks_path("same-host-jwks");
    let jwks_uri = format!("{}{}", server.uri(), jwks_path);
    let discovery_path = unique_jwks_path("oidc-discovery");

    wiremock::Mock::given(wiremock::matchers::method("GET"))
        .and(wiremock::matchers::path(jwks_path))
        .respond_with(
            wiremock::ResponseTemplate::new(200)
                .set_body_json(build_rsa_jwks_from_pem(public_key_pem)),
        )
        .mount(&server)
        .await;
    wiremock::Mock::given(wiremock::matchers::method("GET"))
        .and(wiremock::matchers::path(discovery_path.clone()))
        .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(json!({
            "jwks_uri": jwks_uri.clone()
        })))
        .mount(&server)
        .await;

    let discovery_url = format!("{}{discovery_path}", server.uri());
    let plugin = JwksAuth::new(
        &json!({
            "providers": [{"discovery_url": discovery_url}],
            "jwks_refresh_interval_secs": 3600
        }),
        default_client(),
    )
    .unwrap();
    start_background_tasks(&plugin);

    // The store for the same-host jwks_uri must become active.
    let deadline = tokio::time::Instant::now() + tokio::time::Duration::from_secs(2);
    loop {
        if plugin.active_jwks_uris() == vec![jwks_uri.clone()] {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "timed out waiting for same-host discovery jwks_uri to become active, got: {:?}",
            plugin.active_jwks_uris()
        );
        tokio::time::sleep(tokio::time::Duration::from_millis(20)).await;
    }
}

#[tokio::test]
async fn test_jwks_auth_does_not_fetch_jwks_on_auth_hot_path_when_cache_empty() {
    let mock_server = wiremock::MockServer::start().await;
    let jwks_path = unique_jwks_path("jwks");
    wiremock::Mock::given(wiremock::matchers::method("GET"))
        .and(wiremock::matchers::path(jwks_path.clone()))
        .respond_with(wiremock::ResponseTemplate::new(500))
        .mount(&mock_server)
        .await;

    let jwks_uri = format!("{}{}", mock_server.uri(), jwks_path);
    let plugin = JwksAuth::new(
        &json!({
            "providers": [{"jwks_uri": jwks_uri}],
            "jwks_refresh_interval_secs": 3600
        }),
        default_client(),
    )
    .unwrap();
    start_background_tasks(&plugin);
    let initial_count = wait_for_received_request_count(&mock_server, 1).await;

    let consumers: Vec<ferrum_edge::config::types::Consumer> = Vec::new();
    let consumer_index = ConsumerIndex::new(&consumers);
    let mut ctx = make_ctx();
    ctx.headers
        .insert("authorization".to_string(), "Bearer not.a.jwt".to_string());

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_reject(result, Some(401));
    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

    let final_count = mock_server
        .received_requests()
        .await
        .map(|requests| requests.len())
        .unwrap_or(0);
    assert_eq!(final_count, initial_count);
}

#[tokio::test]
async fn test_jwks_auth_missing_bearer_token() {
    let (_server, jwks_uri) = start_jwks_server(include_bytes!(
        "../../../tests/fixtures/test_rsa_public.pem"
    ))
    .await;
    let plugin = JwksAuth::new(&single_provider_config(&jwks_uri), default_client()).unwrap();
    let consumer_index = ConsumerIndex::new(&[]);

    let mut ctx = make_ctx();
    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_continue(result);
    assert!(ctx.identified_consumer.is_none());
    assert!(ctx.authenticated_identity.is_none());
    assert!(ctx.authenticated_identity_header.is_none());
}

#[tokio::test]
async fn test_jwks_auth_non_bearer_scheme() {
    let (_server, jwks_uri) = start_jwks_server(include_bytes!(
        "../../../tests/fixtures/test_rsa_public.pem"
    ))
    .await;
    let plugin = JwksAuth::new(&single_provider_config(&jwks_uri), default_client()).unwrap();
    let consumer_index = ConsumerIndex::new(&[]);

    let mut ctx = make_ctx();
    ctx.headers.insert(
        "authorization".to_string(),
        "Basic dXNlcjpwYXNz".to_string(),
    );
    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_continue(result);
}

// ─── Single Provider JWKS Validation ───────────────────────────────────

#[tokio::test]
async fn test_mesh_request_auth_permissive_foreign_scheme_is_missing_token() {
    let (_server, jwks_uri) = start_jwks_server(include_bytes!(
        "../../../tests/fixtures/test_rsa_public.pem"
    ))
    .await;
    let mut config = single_provider_config(&jwks_uri);
    config["emit_mesh_request_principal_metadata"] = json!(true);
    let plugin: Arc<dyn Plugin> = Arc::new(JwksAuth::new(&config, default_client()).unwrap());
    let mut ctx = make_ctx();
    ctx.headers.insert(
        "authorization".to_string(),
        "Basic dXNlcjpwYXNz".to_string(),
    );

    let result = ferrum_edge::proxy::run_authentication_phase(
        AuthMode::Single,
        &[plugin],
        &mut ctx,
        &ConsumerIndex::new(&[]),
    )
    .await;

    assert!(
        result.is_none(),
        "permissive mesh RequestAuthentication must treat a foreign scheme as no JWT"
    );
    assert_eq!(
        ctx.metadata
            .get("mesh_request_auth.permissive_missing_token")
            .map(String::as_str),
        Some("true")
    );
    assert!(ctx.identified_consumer.is_none());
    assert!(ctx.authenticated_identity.is_none());
}

#[tokio::test]
async fn test_jwks_auth_validates_rs256_token() {
    let private_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_private.pem");
    let public_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_public.pem");

    let (_server, jwks_uri) = start_jwks_server(public_key_pem).await;
    let plugin = JwksAuth::new(&single_provider_config(&jwks_uri), default_client()).unwrap();
    plugin.warmup_jwks().await;

    let consumer = create_consumer("idp-user");
    let consumer_index = ConsumerIndex::new(&[consumer]);

    let token = create_rs256_token(&json!({"sub": "idp-user"}), private_key_pem);

    let mut ctx = make_ctx();
    ctx.headers
        .insert("authorization".to_string(), format!("Bearer {}", token));

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_continue(result);
    assert!(ctx.identified_consumer.is_some());
    assert_eq!(ctx.identified_consumer.unwrap().username, "idp-user");
    assert_eq!(ctx.authenticated_identity.as_deref(), Some("idp-user"));
}

#[tokio::test]
async fn test_jwks_auth_rejects_missing_exp_by_default() {
    let private_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_private.pem");
    let public_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_public.pem");

    let (_server, jwks_uri) = start_jwks_server(public_key_pem).await;
    let plugin = JwksAuth::new(&single_provider_config(&jwks_uri), default_client()).unwrap();
    plugin.warmup_jwks().await;

    let consumer_index = ConsumerIndex::new(&[create_consumer("idp-user")]);
    let token = create_rs256_token_exact(&json!({"sub": "idp-user"}), private_key_pem);

    let mut ctx = make_ctx();
    ctx.headers
        .insert("authorization".to_string(), format!("Bearer {}", token));

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_reject(result, Some(401));
}

#[tokio::test]
async fn test_jwks_auth_allows_missing_exp_when_require_exp_false() {
    let private_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_private.pem");
    let public_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_public.pem");

    let (_server, jwks_uri) = start_jwks_server(public_key_pem).await;
    let plugin = JwksAuth::new(
        &json!({
            "providers": [{"jwks_uri": jwks_uri}],
            "require_exp": false
        }),
        default_client(),
    )
    .unwrap();
    plugin.warmup_jwks().await;

    let consumer_index = ConsumerIndex::new(&[create_consumer("idp-user")]);
    let token = create_rs256_token_exact(&json!({"sub": "idp-user"}), private_key_pem);

    let mut ctx = make_ctx();
    ctx.headers
        .insert("authorization".to_string(), format!("Bearer {}", token));

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_continue(result);
    assert_eq!(ctx.authenticated_identity.as_deref(), Some("idp-user"));
}

#[tokio::test]
async fn test_jwks_auth_strips_authorization_when_forward_original_token_false() {
    let private_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_private.pem");
    let public_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_public.pem");

    let (_server, jwks_uri) = start_jwks_server(public_key_pem).await;
    let plugin = JwksAuth::new(
        &json!({
            "providers": [{
                "jwks_uri": jwks_uri,
                "forward_original_token": false
            }]
        }),
        default_client(),
    )
    .unwrap();
    assert!(plugin.modifies_request_headers());
    plugin.warmup_jwks().await;

    let consumers: Vec<ferrum_edge::config::types::Consumer> = Vec::new();
    let consumer_index = ConsumerIndex::new(&consumers);
    let token = create_rs256_token(&json!({"sub": "idp-user"}), private_key_pem);

    let mut ctx = make_ctx();
    ctx.headers
        .insert("authorization".to_string(), format!("Bearer {}", token));

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_continue(result);

    let mut headers = ctx.headers.clone();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);

    assert!(
        !headers.contains_key("authorization"),
        "Authorization should be stripped before proxying"
    );
}

#[tokio::test]
async fn claim_headers_writes_simple_and_array_claims_to_outbound_headers() {
    let private_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_private.pem");
    let public_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_public.pem");

    let (_server, jwks_uri) = start_jwks_server(public_key_pem).await;
    let plugin = JwksAuth::new(
        &json!({
            "providers": [{
                "jwks_uri": jwks_uri,
                "claim_headers": {
                    "email": "X-User-Email",
                    "roles": "X-User-Roles"
                },
                "claim_headers_separator": "|"
            }]
        }),
        default_client(),
    )
    .unwrap();
    assert!(plugin.modifies_request_headers());
    plugin.warmup_jwks().await;

    let consumer_index = ConsumerIndex::new(&[create_consumer("idp-user")]);
    let token = create_rs256_token(
        &json!({
            "sub": "idp-user",
            "email": "idp@example.com",
            "roles": ["admin", "editor"]
        }),
        private_key_pem,
    );

    let mut ctx = make_ctx();
    ctx.headers
        .insert("authorization".to_string(), format!("Bearer {}", token));
    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_continue(result);
    assert!(
        !ctx.metadata
            .keys()
            .any(|key| key.starts_with("jwks_auth.claim_header.")),
        "claim-derived headers must be staged outside log-visible metadata"
    );
    assert!(
        !ctx.metadata
            .values()
            .any(|value| value == "idp@example.com"),
        "claim values must not be available to authorization-phase rejection logs"
    );

    let mut headers = HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);
    assert_eq!(
        headers.get("x-user-email").map(String::as_str),
        Some("idp@example.com")
    );
    assert_eq!(
        headers.get("x-user-roles").map(String::as_str),
        Some("admin|editor")
    );
}

#[tokio::test]
async fn principal_less_jwks_attempt_is_discarded_before_later_key_auth_success() {
    let private_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_private.pem");
    let public_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_public.pem");
    let jwks = build_rsa_jwks_from_pem(public_key_pem);
    let jwks_plugin = Arc::new(
        JwksAuth::new(
            &json!({
                "providers": [{
                    "jwks": jwks,
                    "consumer_identity_claim": "principal",
                    "forward_original_token": false,
                    "claim_headers": {"email": "X-User-Email"}
                }],
                "emit_mesh_request_principal_metadata": true
            }),
            default_client(),
        )
        .expect("valid inline JWKS config"),
    );
    let key_plugin = Arc::new(KeyAuth::new(&json!({})).expect("valid key auth config"));
    let auth_plugins: Vec<Arc<dyn Plugin>> = vec![jwks_plugin.clone(), key_plugin.clone()];
    let consumer_index = ConsumerIndex::new(&[create_test_consumer()]);

    for claims in [
        json!({
            "iss": "https://issuer.example",
            "sub": "token-subject",
            "principal": "   ",
            "email": "unaccepted@example.com"
        }),
        json!({
            "iss": "https://issuer.example",
            "sub": "token-subject",
            "email": "unaccepted@example.com"
        }),
    ] {
        let token = create_rs256_token(&claims, private_key_pem);
        let authorization = format!("Bearer {token}");
        let mut ctx = make_ctx();
        ctx.headers
            .insert("authorization".to_string(), authorization.clone());
        ctx.headers
            .insert("x-api-key".to_string(), "test-api-key".to_string());

        assert!(
            run_authentication_phase(AuthMode::Multi, &auth_plugins, &mut ctx, &consumer_index,)
                .await
                .is_none()
        );
        assert_eq!(
            ctx.identified_consumer
                .as_ref()
                .map(|consumer| consumer.username.as_str()),
            Some("testuser")
        );
        assert_eq!(ctx.auth_method, Some("key_auth"));
        assert!(ctx.authenticated_identity.is_none());
        assert!(ctx.authenticated_identity_header.is_none());
        assert!(!ctx.metadata.contains_key("mesh.request_principal"));
        assert!(ctx.mesh_request_auth_audiences.is_empty());
        assert!(ctx.mesh_request_auth_claims.is_empty());
        assert!(
            !ctx.metadata
                .values()
                .any(|value| value == "unaccepted@example.com")
        );

        let mut headers = ctx.headers.clone();
        assert_continue(jwks_plugin.before_proxy(&mut ctx, &mut headers).await);
        assert_continue(key_plugin.before_proxy(&mut ctx, &mut headers).await);
        assert_eq!(
            headers.get("authorization").map(String::as_str),
            Some(authorization.as_str()),
            "an unaccepted JWKS attempt must not strip its bearer token"
        );
        assert!(
            !headers.contains_key("x-api-key"),
            "the accepted key-auth credential must still be stripped"
        );
        assert!(!headers.contains_key("x-user-email"));
    }
}

#[tokio::test]
async fn first_accepted_jwks_instance_owns_identity_and_claim_headers() {
    let private_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_private.pem");
    let public_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_public.pem");
    let jwks = build_rsa_jwks_from_pem(public_key_pem);
    let first = Arc::new(
        JwksAuth::new(
            &json!({"providers": [{
                "jwks": jwks,
                "from_headers": [{"name": "x-jwt-a"}],
                "forward_original_token": false,
                "consumer_header_claim": "display",
                "claim_headers": {"email": "X-Selected-Email"}
            }]}),
            default_client(),
        )
        .expect("first JWKS config"),
    );
    let second = Arc::new(
        JwksAuth::new(
            &json!({"providers": [{
                "jwks": build_rsa_jwks_from_pem(public_key_pem),
                "from_headers": [{"name": "x-jwt-b"}],
                "forward_original_token": false,
                "consumer_header_claim": "display",
                "claim_headers": {"email": "X-Selected-Email"}
            }]}),
            default_client(),
        )
        .expect("second JWKS config"),
    );
    let auth_plugins: Vec<Arc<dyn Plugin>> = vec![first.clone(), second.clone()];
    let mut ctx = make_ctx();
    ctx.headers.insert(
        "x-jwt-a".to_string(),
        create_rs256_token(
            &json!({"sub": "first", "display": "First Display", "email": "first@example.com"}),
            private_key_pem,
        ),
    );
    ctx.headers.insert(
        "x-jwt-b".to_string(),
        create_rs256_token(
            &json!({"sub": "second", "display": "Second Display", "email": "second@example.com"}),
            private_key_pem,
        ),
    );

    assert!(
        run_authentication_phase(
            AuthMode::Single,
            &auth_plugins,
            &mut ctx,
            &ConsumerIndex::new(&[]),
        )
        .await
        .is_none()
    );
    assert_eq!(ctx.authenticated_identity.as_deref(), Some("first"));
    assert_eq!(
        ctx.authenticated_identity_header.as_deref(),
        Some("First Display")
    );

    let mut headers = ctx.headers.clone();
    assert_continue(first.before_proxy(&mut ctx, &mut headers).await);
    assert_continue(second.before_proxy(&mut ctx, &mut headers).await);
    assert_eq!(
        headers.get("x-selected-email").map(String::as_str),
        Some("first@example.com")
    );
    assert!(!headers.contains_key("x-jwt-a"));
    assert!(
        headers.contains_key("x-jwt-b"),
        "single auth must stop before the later plugin stages credential cleanup"
    );
}

#[test]
fn new_rejects_claim_header_with_reserved_target() {
    let err = match JwksAuth::new(
        &json!({
            "providers": [{
                "jwks": {"keys": []},
                "claim_headers": {"sub": "Authorization"}
            }]
        }),
        default_client(),
    ) {
        Ok(_) => panic!("reserved header should reject"),
        Err(err) => err,
    };
    assert!(err.contains("reserved"));
}

#[tokio::test]
async fn mtls_bound_token_with_matching_thumbprint_succeeds() {
    use ferrum_edge::plugins::utils::cert_hash::sha256_base64url_no_pad;

    let private_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_private.pem");
    let public_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_public.pem");
    let cert_der = b"test client cert der".to_vec();
    let thumbprint = sha256_base64url_no_pad(&cert_der);

    let (_server, jwks_uri) = start_jwks_server(public_key_pem).await;
    let plugin = JwksAuth::new(
        &json!({
            "providers": [{
                "jwks_uri": jwks_uri,
                "require_mtls_binding": true
            }]
        }),
        default_client(),
    )
    .unwrap();
    plugin.warmup_jwks().await;

    let consumer_index = ConsumerIndex::new(&[create_consumer("idp-user")]);
    let token = create_rs256_token(
        &json!({"sub": "idp-user", "cnf": {"x5t#S256": thumbprint}}),
        private_key_pem,
    );

    let mut ctx = make_ctx();
    ctx.tls_client_cert_der = Some(std::sync::Arc::new(cert_der));
    ctx.headers
        .insert("authorization".to_string(), format!("Bearer {}", token));
    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_continue(result);
}

#[tokio::test]
async fn mtls_binding_required_but_no_client_cert_rejects_401() {
    let private_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_private.pem");
    let public_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_public.pem");

    let (_server, jwks_uri) = start_jwks_server(public_key_pem).await;
    let plugin = JwksAuth::new(
        &json!({
            "providers": [{
                "jwks_uri": jwks_uri,
                "require_mtls_binding": true
            }]
        }),
        default_client(),
    )
    .unwrap();
    plugin.warmup_jwks().await;

    let consumer_index = ConsumerIndex::new(&[create_consumer("idp-user")]);
    let token = create_rs256_token(
        &json!({"sub": "idp-user", "cnf": {"x5t#S256": "abc"}}),
        private_key_pem,
    );

    let mut ctx = make_ctx();
    ctx.headers
        .insert("authorization".to_string(), format!("Bearer {}", token));
    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_reject(result, Some(401));
}

#[tokio::test]
async fn dpop_valid_proof_with_matching_jkt_succeeds() {
    use ferrum_edge::plugins::utils::dpop::jwk_thumbprint_sha256;
    use jsonwebtoken::{EncodingKey, Header, encode};

    let private_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_private.pem");
    let public_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_public.pem");
    let jwk_value = build_rsa_jwks_from_pem(public_key_pem)["keys"][0].clone();
    let jwk: jsonwebtoken::jwk::Jwk = serde_json::from_value(jwk_value).unwrap();
    let jkt = jwk_thumbprint_sha256(&jwk).unwrap();

    let (_server, jwks_uri) = start_jwks_server(public_key_pem).await;
    let plugin = JwksAuth::new(
        &json!({
            "providers": [{
                "jwks_uri": jwks_uri,
                "require_dpop": true
            }]
        }),
        default_client(),
    )
    .unwrap();
    plugin.warmup_jwks().await;

    let consumer_index = ConsumerIndex::new(&[create_consumer("idp-user")]);
    let access_token = create_rs256_token(
        &json!({"sub": "idp-user", "cnf": {"jkt": jkt}}),
        private_key_pem,
    );
    let now = chrono::Utc::now().timestamp();
    // RFC 9449 §4.3: the proof must bind to the presented access token via the
    // `ath` claim (SHA-256 of the token, base64url no-pad).
    let ath = {
        use base64::Engine;
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(access_token.as_bytes());
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hasher.finalize())
    };
    let mut dpop_header = Header::new(jsonwebtoken::Algorithm::RS256);
    dpop_header.typ = Some("dpop+jwt".to_string());
    dpop_header.jwk = Some(jwk);
    let proof = encode(
        &dpop_header,
        &json!({
            "htm": "GET",
            "htu": "http://example.com/test",
            "iat": now,
            "exp": now + 60,
            "jti": "proof-1",
            "ath": ath
        }),
        &EncodingKey::from_rsa_pem(private_key_pem).unwrap(),
    )
    .unwrap();

    let mut ctx = make_ctx();
    ctx.headers.insert(
        "authorization".to_string(),
        format!("Bearer {}", access_token),
    );
    ctx.headers.insert("dpop".to_string(), proof);
    ctx.headers
        .insert("host".to_string(), "example.com".to_string());
    ctx.metadata
        .insert("ferrum.frontend_scheme".to_string(), "http".to_string());
    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_continue(result);
}

#[tokio::test]
async fn dpop_required_but_header_missing_rejects_401() {
    let private_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_private.pem");
    let public_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_public.pem");

    let (_server, jwks_uri) = start_jwks_server(public_key_pem).await;
    let plugin = JwksAuth::new(
        &json!({
            "providers": [{
                "jwks_uri": jwks_uri,
                "require_dpop": true
            }]
        }),
        default_client(),
    )
    .unwrap();
    plugin.warmup_jwks().await;

    let consumer_index = ConsumerIndex::new(&[create_consumer("idp-user")]);
    let token = create_rs256_token(
        &json!({"sub": "idp-user", "cnf": {"jkt": "missing"}}),
        private_key_pem,
    );
    let mut ctx = make_ctx();
    ctx.headers
        .insert("authorization".to_string(), format!("Bearer {}", token));
    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_reject(result, Some(401));
}

#[tokio::test]
async fn test_jwks_auth_rejects_wrong_key() {
    let private_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_private.pem");
    let other_public_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_public_other.pem");

    let (_server, jwks_uri) = start_jwks_server(other_public_key_pem).await;
    let plugin = JwksAuth::new(&single_provider_config(&jwks_uri), default_client()).unwrap();
    plugin.warmup_jwks().await;

    let consumer_index = ConsumerIndex::new(&[create_consumer("idp-user")]);
    let token = create_rs256_token(&json!({"sub": "idp-user"}), private_key_pem);

    let mut ctx = make_ctx();
    ctx.headers
        .insert("authorization".to_string(), format!("Bearer {}", token));

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_reject(result, Some(401));
}

#[tokio::test]
async fn test_jwks_auth_validates_with_issuer() {
    let private_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_private.pem");
    let public_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_public.pem");

    let (_server, jwks_uri) = start_jwks_server(public_key_pem).await;
    let plugin = JwksAuth::new(
        &json!({
            "providers": [{
                "jwks_uri": jwks_uri,
                "issuer": "https://auth.example.com"
            }]
        }),
        default_client(),
    )
    .unwrap();
    plugin.warmup_jwks().await;

    let consumer_index = ConsumerIndex::new(&[create_consumer("user")]);
    let token = create_rs256_token(
        &json!({"sub": "user", "iss": "https://auth.example.com"}),
        private_key_pem,
    );

    let mut ctx = make_ctx();
    ctx.headers
        .insert("authorization".to_string(), format!("Bearer {}", token));
    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_continue(result);
}

#[tokio::test]
async fn test_jwks_auth_rejects_wrong_issuer() {
    let private_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_private.pem");
    let public_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_public.pem");

    let (_server, jwks_uri) = start_jwks_server(public_key_pem).await;
    let plugin = JwksAuth::new(
        &json!({
            "providers": [{
                "jwks_uri": jwks_uri,
                "issuer": "https://auth.example.com"
            }]
        }),
        default_client(),
    )
    .unwrap();
    plugin.warmup_jwks().await;

    let consumer_index = ConsumerIndex::new(&[create_consumer("user")]);
    let token = create_rs256_token(
        &json!({"sub": "user", "iss": "https://evil.example.com"}),
        private_key_pem,
    );

    let mut ctx = make_ctx();
    ctx.headers
        .insert("authorization".to_string(), format!("Bearer {}", token));
    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_reject(result, Some(401));
}

#[tokio::test]
async fn test_jwks_auth_validates_with_audience() {
    let private_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_private.pem");
    let public_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_public.pem");

    let (_server, jwks_uri) = start_jwks_server(public_key_pem).await;
    let plugin = JwksAuth::new(
        &json!({
            "providers": [{
                "jwks_uri": jwks_uri,
                "audience": "my-api"
            }]
        }),
        default_client(),
    )
    .unwrap();
    plugin.warmup_jwks().await;

    let consumer_index = ConsumerIndex::new(&[create_consumer("user")]);
    let token = create_rs256_token(&json!({"sub": "user", "aud": "my-api"}), private_key_pem);

    let mut ctx = make_ctx();
    ctx.headers
        .insert("authorization".to_string(), format!("Bearer {}", token));
    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_continue(result);
}

#[tokio::test]
async fn test_jwks_auth_token_without_kid_tries_all_keys() {
    let private_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_private.pem");
    let public_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_public.pem");

    let (_server, jwks_uri) = start_jwks_server(public_key_pem).await;
    let plugin = JwksAuth::new(&single_provider_config(&jwks_uri), default_client()).unwrap();
    plugin.warmup_jwks().await;

    let consumer_index = ConsumerIndex::new(&[create_consumer("user")]);
    let token = create_rs256_token_no_kid(&json!({"sub": "user"}), private_key_pem);

    let mut ctx = make_ctx();
    ctx.headers
        .insert("authorization".to_string(), format!("Bearer {}", token));
    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_continue(result);
}

// ─── Consumer-Optional Flow ────────────────────────────────────────────

#[tokio::test]
async fn test_jwks_auth_continues_without_consumer_in_index() {
    let private_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_private.pem");
    let public_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_public.pem");

    let (_server, jwks_uri) = start_jwks_server(public_key_pem).await;
    let plugin = JwksAuth::new(&single_provider_config(&jwks_uri), default_client()).unwrap();
    plugin.warmup_jwks().await;

    // Empty consumer index — no consumers defined at all
    let consumer_index = ConsumerIndex::new(&[]);

    let token = create_rs256_token(&json!({"sub": "external-user"}), private_key_pem);

    let mut ctx = make_ctx();
    ctx.headers
        .insert("authorization".to_string(), format!("Bearer {}", token));

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_continue(result);
    // No identified_consumer (not in index), but authenticated_identity is set
    assert!(ctx.identified_consumer.is_none());
    assert_eq!(ctx.authenticated_identity.as_deref(), Some("external-user"));
}

#[tokio::test]
async fn test_jwks_auth_signed_tokens_do_not_authenticate_blank_identity_claims() {
    let private_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_private.pem");
    let public_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_public.pem");
    let (_server, jwks_uri) = start_jwks_server(public_key_pem).await;
    let plugin = JwksAuth::new(&single_provider_config(&jwks_uri), default_client()).unwrap();
    plugin.warmup_jwks().await;

    for claims in [
        json!({}),
        json!({"sub": null}),
        json!({"sub": 42}),
        json!({"sub": ""}),
        json!({"sub": "   \t"}),
    ] {
        let token = create_rs256_token(&claims, private_key_pem);
        let mut ctx = make_ctx();
        ctx.headers
            .insert("authorization".to_string(), format!("Bearer {token}"));

        let result = plugin
            .authenticate(&mut ctx, &ConsumerIndex::new(&[]))
            .await;
        assert_continue(result);
        assert!(ctx.identified_consumer.is_none());
        assert!(ctx.authenticated_identity.is_none());
        assert!(ctx.effective_identity().is_none());
        assert!(ctx.auth_method.is_none());
    }
}

#[tokio::test]
async fn jwks_multi_auth_does_not_commit_failed_attempt_header_side_effects() {
    let private_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_private.pem");
    let public_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_public.pem");
    let (_server, jwks_uri) = start_jwks_server(public_key_pem).await;
    let jwks = Arc::new(
        JwksAuth::new(
            &json!({
                "providers": [{
                    "jwks_uri": jwks_uri,
                    "forward_original_token": false,
                    "claim_headers": {"email": "X-Untrusted-Email"}
                }]
            }),
            default_client(),
        )
        .unwrap(),
    );
    jwks.warmup_jwks().await;
    let key_auth: Arc<dyn Plugin> =
        Arc::new(KeyAuth::new(&json!({"key_location": "header:X-API-Key"})).unwrap());
    let consumers = [create_test_consumer()];
    let consumer_index = ConsumerIndex::new(&consumers);

    let attempted_tokens = [
        create_rs256_token(
            &json!({"email": "missing-principal@example.test"}),
            private_key_pem,
        ),
        create_rs256_token(
            &json!({"sub": "  \t", "email": "blank-principal@example.test"}),
            private_key_pem,
        ),
        "not-a-jwt".to_string(),
    ];

    for attempted_token in attempted_tokens {
        let mut ctx = make_ctx();
        let expected_authorization = format!("Bearer {attempted_token}");
        ctx.headers
            .insert("authorization".to_string(), expected_authorization.clone());
        ctx.headers
            .insert("x-api-key".to_string(), "test-api-key".to_string());

        let jwks_plugin: Arc<dyn Plugin> = jwks.clone();
        let auth_plugins: Vec<Arc<dyn Plugin>> = vec![jwks_plugin, Arc::clone(&key_auth)];
        let rejection =
            run_authentication_phase(AuthMode::Multi, &auth_plugins, &mut ctx, &consumer_index)
                .await;
        assert!(rejection.is_none(), "later key_auth must authenticate");
        assert_eq!(ctx.auth_method, Some("key_auth"));

        let mut headers = ctx.headers.clone();
        assert_continue(jwks.before_proxy(&mut ctx, &mut headers).await);
        assert_eq!(
            headers.get("authorization").map(String::as_str),
            Some(expected_authorization.as_str()),
            "an uncommitted JWKS attempt must not strip its credential"
        );
        assert!(
            !headers.contains_key("x-untrusted-email"),
            "an uncommitted JWKS attempt must not fan out claims"
        );
    }
}

#[tokio::test]
async fn test_jwks_auth_consumer_header_claim_separate_from_identity() {
    let private_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_private.pem");
    let public_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_public.pem");

    let (_server, jwks_uri) = start_jwks_server(public_key_pem).await;
    let plugin = JwksAuth::new(
        &json!({
            "providers": [{"jwks_uri": jwks_uri}],
            "consumer_identity_claim": "sub",
            "consumer_header_claim": "email"
        }),
        default_client(),
    )
    .unwrap();
    plugin.warmup_jwks().await;

    let consumer_index = ConsumerIndex::new(&[]);

    let token = create_rs256_token(
        &json!({"sub": "user-123", "email": "user@example.com"}),
        private_key_pem,
    );

    let mut ctx = make_ctx();
    ctx.headers
        .insert("authorization".to_string(), format!("Bearer {}", token));

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_continue(result);
    assert_eq!(ctx.authenticated_identity.as_deref(), Some("user-123"));
    assert_eq!(
        ctx.authenticated_identity_header.as_deref(),
        Some("user@example.com")
    );
}

#[tokio::test]
async fn test_jwks_auth_maps_subject_to_custom_id() {
    let private_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_private.pem");
    let public_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_public.pem");

    let (_server, jwks_uri) = start_jwks_server(public_key_pem).await;
    let plugin = JwksAuth::new(&single_provider_config(&jwks_uri), default_client()).unwrap();
    plugin.warmup_jwks().await;

    let consumer = create_consumer_with_custom_id("local-user", "idp-subject-12345");
    let consumer_index = ConsumerIndex::new(&[consumer]);

    let token = create_rs256_token(&json!({"sub": "idp-subject-12345"}), private_key_pem);

    let mut ctx = make_ctx();
    ctx.headers
        .insert("authorization".to_string(), format!("Bearer {}", token));

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_continue(result);
    assert_eq!(ctx.identified_consumer.unwrap().username, "local-user");
}

// ─── Scope/Role Claim-Based Authorization ──────────────────────────────

#[tokio::test]
async fn test_jwks_auth_required_scopes_pass() {
    let private_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_private.pem");
    let public_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_public.pem");

    let (_server, jwks_uri) = start_jwks_server(public_key_pem).await;
    let plugin = JwksAuth::new(
        &json!({
            "providers": [{
                "jwks_uri": jwks_uri,
                "required_scopes": ["read:data", "write:data"]
            }],
            "scope_claim": "scope"
        }),
        default_client(),
    )
    .unwrap();
    plugin.warmup_jwks().await;

    let consumer_index = ConsumerIndex::new(&[]);

    // Space-delimited scope string (OAuth2 standard format)
    let token = create_rs256_token(
        &json!({"sub": "user", "scope": "read:data write:data admin"}),
        private_key_pem,
    );

    let mut ctx = make_ctx();
    ctx.headers
        .insert("authorization".to_string(), format!("Bearer {}", token));
    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_continue(result);
}

#[tokio::test]
async fn test_jwks_auth_required_scopes_fail() {
    let private_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_private.pem");
    let public_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_public.pem");

    let (_server, jwks_uri) = start_jwks_server(public_key_pem).await;
    let plugin = JwksAuth::new(
        &json!({
            "providers": [{
                "jwks_uri": jwks_uri,
                "required_scopes": ["read:data", "write:data"]
            }],
            "scope_claim": "scope"
        }),
        default_client(),
    )
    .unwrap();
    plugin.warmup_jwks().await;

    let consumer_index = ConsumerIndex::new(&[]);

    // Missing write:data scope
    let token = create_rs256_token(
        &json!({"sub": "user", "scope": "read:data"}),
        private_key_pem,
    );

    let mut ctx = make_ctx();
    ctx.headers
        .insert("authorization".to_string(), format!("Bearer {}", token));
    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_reject(result, Some(403));
}

#[tokio::test]
async fn test_jwks_auth_required_scopes_array_format() {
    let private_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_private.pem");
    let public_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_public.pem");

    let (_server, jwks_uri) = start_jwks_server(public_key_pem).await;
    let plugin = JwksAuth::new(
        &json!({
            "providers": [{
                "jwks_uri": jwks_uri,
                "required_scopes": ["read"]
            }],
            "scope_claim": "scp"
        }),
        default_client(),
    )
    .unwrap();
    plugin.warmup_jwks().await;

    let consumer_index = ConsumerIndex::new(&[]);

    // Okta-style array format
    let token = create_rs256_token(
        &json!({"sub": "user", "scp": ["read", "write"]}),
        private_key_pem,
    );

    let mut ctx = make_ctx();
    ctx.headers
        .insert("authorization".to_string(), format!("Bearer {}", token));
    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_continue(result);
}

#[tokio::test]
async fn test_jwks_auth_required_roles_any_match() {
    let private_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_private.pem");
    let public_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_public.pem");

    let (_server, jwks_uri) = start_jwks_server(public_key_pem).await;
    let plugin = JwksAuth::new(
        &json!({
            "providers": [{
                "jwks_uri": jwks_uri,
                "required_roles": ["admin", "editor"]
            }],
            "role_claim": "roles"
        }),
        default_client(),
    )
    .unwrap();
    plugin.warmup_jwks().await;

    let consumer_index = ConsumerIndex::new(&[]);

    // User has "editor" — one of the required roles (any match)
    let token = create_rs256_token(
        &json!({"sub": "user", "roles": ["editor", "viewer"]}),
        private_key_pem,
    );

    let mut ctx = make_ctx();
    ctx.headers
        .insert("authorization".to_string(), format!("Bearer {}", token));
    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_continue(result);
}

#[tokio::test]
async fn test_jwks_auth_required_roles_no_match() {
    let private_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_private.pem");
    let public_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_public.pem");

    let (_server, jwks_uri) = start_jwks_server(public_key_pem).await;
    let plugin = JwksAuth::new(
        &json!({
            "providers": [{
                "jwks_uri": jwks_uri,
                "required_roles": ["admin"]
            }],
            "role_claim": "roles"
        }),
        default_client(),
    )
    .unwrap();
    plugin.warmup_jwks().await;

    let consumer_index = ConsumerIndex::new(&[]);

    // User only has "viewer" — doesn't match required "admin"
    let token = create_rs256_token(
        &json!({"sub": "user", "roles": ["viewer"]}),
        private_key_pem,
    );

    let mut ctx = make_ctx();
    ctx.headers
        .insert("authorization".to_string(), format!("Bearer {}", token));
    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_reject(result, Some(403));
}

#[tokio::test]
async fn test_jwks_auth_nested_role_claim_keycloak_style() {
    let private_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_private.pem");
    let public_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_public.pem");

    let (_server, jwks_uri) = start_jwks_server(public_key_pem).await;
    let plugin = JwksAuth::new(
        &json!({
            "providers": [{
                "jwks_uri": jwks_uri,
                "required_roles": ["admin"],
                "role_claim": "realm_access.roles"
            }]
        }),
        default_client(),
    )
    .unwrap();
    plugin.warmup_jwks().await;

    let consumer_index = ConsumerIndex::new(&[]);

    // Keycloak-style nested roles
    let token = create_rs256_token(
        &json!({
            "sub": "user",
            "realm_access": {
                "roles": ["admin", "user"]
            }
        }),
        private_key_pem,
    );

    let mut ctx = make_ctx();
    ctx.headers
        .insert("authorization".to_string(), format!("Bearer {}", token));
    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_continue(result);
}

#[tokio::test]
async fn test_jwks_auth_no_scopes_or_roles_required_allows_all() {
    let private_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_private.pem");
    let public_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_public.pem");

    let (_server, jwks_uri) = start_jwks_server(public_key_pem).await;
    let plugin = JwksAuth::new(&single_provider_config(&jwks_uri), default_client()).unwrap();
    plugin.warmup_jwks().await;

    let consumer_index = ConsumerIndex::new(&[]);

    // Minimal token — no scopes or roles at all
    let token = create_rs256_token(&json!({"sub": "user"}), private_key_pem);

    let mut ctx = make_ctx();
    ctx.headers
        .insert("authorization".to_string(), format!("Bearer {}", token));
    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_continue(result);
}

// ─── Multi-Provider Tests ──────────────────────────────────────────────

#[tokio::test]
async fn test_jwks_auth_multi_provider_routes_by_issuer() {
    let private_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_private.pem");
    let public_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_public.pem");

    // Both providers use the same key for simplicity, but have different issuers
    let server1 = wiremock::MockServer::start().await;
    let jwks_json = build_rsa_jwks_from_pem(public_key_pem);
    let jwks_path1 = unique_jwks_path("jwks1");
    wiremock::Mock::given(wiremock::matchers::method("GET"))
        .and(wiremock::matchers::path(jwks_path1.clone()))
        .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(&jwks_json))
        .mount(&server1)
        .await;

    let server2 = wiremock::MockServer::start().await;
    let jwks_path2 = unique_jwks_path("jwks2");
    wiremock::Mock::given(wiremock::matchers::method("GET"))
        .and(wiremock::matchers::path(jwks_path2.clone()))
        .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(&jwks_json))
        .mount(&server2)
        .await;

    let plugin = JwksAuth::new(
        &json!({
            "providers": [
                {
                    "issuer": "https://idp-one.example.com",
                    "jwks_uri": format!("{}{}", server1.uri(), jwks_path1),
                    "required_roles": ["admin"]
                },
                {
                    "issuer": "https://idp-two.example.com",
                    "jwks_uri": format!("{}{}", server2.uri(), jwks_path2),
                    "required_roles": ["partner"]
                }
            ],
            "role_claim": "roles"
        }),
        default_client(),
    )
    .unwrap();
    plugin.warmup_jwks().await;

    let consumer_index = ConsumerIndex::new(&[]);

    // Token from IdP 2 with "partner" role — should pass via second provider
    let token = create_rs256_token(
        &json!({
            "sub": "partner-user",
            "iss": "https://idp-two.example.com",
            "roles": ["partner"]
        }),
        private_key_pem,
    );

    let mut ctx = make_ctx();
    ctx.headers
        .insert("authorization".to_string(), format!("Bearer {}", token));
    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_continue(result);
    assert_eq!(ctx.authenticated_identity.as_deref(), Some("partner-user"));
}

#[tokio::test]
async fn test_jwks_auth_multi_provider_wrong_role_rejected() {
    let private_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_private.pem");
    let public_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_public.pem");

    let server = wiremock::MockServer::start().await;
    let jwks_json = build_rsa_jwks_from_pem(public_key_pem);
    let jwks_path = unique_jwks_path("jwks");
    wiremock::Mock::given(wiremock::matchers::method("GET"))
        .and(wiremock::matchers::path(jwks_path.clone()))
        .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(&jwks_json))
        .mount(&server)
        .await;

    let jwks_uri = format!("{}{}", server.uri(), jwks_path);
    let plugin = JwksAuth::new(
        &json!({
            "providers": [{
                "issuer": "https://idp.example.com",
                "jwks_uri": jwks_uri,
                "required_roles": ["admin"]
            }],
            "role_claim": "roles"
        }),
        default_client(),
    )
    .unwrap();
    plugin.warmup_jwks().await;

    let consumer_index = ConsumerIndex::new(&[]);

    // Token has "viewer" but provider requires "admin"
    let token = create_rs256_token(
        &json!({
            "sub": "user",
            "iss": "https://idp.example.com",
            "roles": ["viewer"]
        }),
        private_key_pem,
    );

    let mut ctx = make_ctx();
    ctx.headers
        .insert("authorization".to_string(), format!("Bearer {}", token));
    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_reject(result, Some(403));
}

// ─── Claim Extraction Helpers ──────────────────────────────────────────

#[test]
fn test_extract_claim_values_space_delimited_string() {
    use ferrum_edge::plugins::utils::claim_resolver::extract_claim_values;

    let claims = json!({"scope": "read:data write:data admin"});
    let values = extract_claim_values(&claims, "scope");
    assert_eq!(values, vec!["read:data", "write:data", "admin"]);
}

#[test]
fn test_extract_claim_values_array() {
    use ferrum_edge::plugins::utils::claim_resolver::extract_claim_values;

    let claims = json!({"scp": ["read", "write"]});
    let values = extract_claim_values(&claims, "scp");
    assert_eq!(values, vec!["read", "write"]);
}

#[test]
fn test_extract_claim_values_nested_dot_path() {
    use ferrum_edge::plugins::utils::claim_resolver::extract_claim_values;

    let claims = json!({"realm_access": {"roles": ["admin", "user"]}});
    let values = extract_claim_values(&claims, "realm_access.roles");
    assert_eq!(values, vec!["admin", "user"]);
}

#[test]
fn test_extract_claim_values_missing_path() {
    use ferrum_edge::plugins::utils::claim_resolver::extract_claim_values;

    let claims = json!({"sub": "user"});
    let values = extract_claim_values(&claims, "nonexistent.path");
    assert!(values.is_empty());
}

#[test]
fn test_extract_claim_values_deeply_nested() {
    use ferrum_edge::plugins::utils::claim_resolver::extract_claim_values;

    // Two levels of nesting (Keycloak resource_access style)
    let claims = json!({
        "resource_access": {
            "my_client": {
                "roles": ["superadmin"]
            }
        }
    });
    let values = extract_claim_values(&claims, "resource_access.my_client.roles");
    assert_eq!(values, vec!["superadmin"]);
}

// ─── Per-Provider Claim Overrides ──────────────────────────────────────

#[tokio::test]
async fn test_jwks_auth_per_provider_scope_claim_override() {
    let private_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_private.pem");
    let public_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_public.pem");

    let (_server, jwks_uri) = start_jwks_server(public_key_pem).await;

    // Global scope_claim is "scope", but provider overrides to "scp"
    let plugin = JwksAuth::new(
        &json!({
            "providers": [{
                "jwks_uri": jwks_uri,
                "required_scopes": ["read"],
                "scope_claim": "scp"
            }],
            "scope_claim": "scope"
        }),
        default_client(),
    )
    .unwrap();
    plugin.warmup_jwks().await;

    let consumer_index = ConsumerIndex::new(&[]);

    // Token uses "scp" (Okta style) — should work with provider override
    let token = create_rs256_token(
        &json!({"sub": "user", "scp": ["read", "write"]}),
        private_key_pem,
    );

    let mut ctx = make_ctx();
    ctx.headers
        .insert("authorization".to_string(), format!("Bearer {}", token));
    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_continue(result);
}

// ─── Per-Provider Consumer Claim Overrides ─────────────────────────────

#[tokio::test]
async fn test_jwks_auth_per_provider_consumer_identity_claim_override() {
    let private_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_private.pem");
    let public_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_public.pem");

    let (_server, jwks_uri) = start_jwks_server(public_key_pem).await;

    // Global consumer_identity_claim is "sub", but provider overrides to "preferred_username"
    let plugin = JwksAuth::new(
        &json!({
            "providers": [{
                "jwks_uri": jwks_uri,
                "consumer_identity_claim": "preferred_username"
            }],
            "consumer_identity_claim": "sub"
        }),
        default_client(),
    )
    .unwrap();
    plugin.warmup_jwks().await;

    let consumer = create_consumer("keycloak-user");
    let consumer_index = ConsumerIndex::new(&[consumer]);

    // Token has both "sub" and "preferred_username" — provider override picks "preferred_username"
    let token = create_rs256_token(
        &json!({
            "sub": "some-uuid-12345",
            "preferred_username": "keycloak-user"
        }),
        private_key_pem,
    );

    let mut ctx = make_ctx();
    ctx.headers
        .insert("authorization".to_string(), format!("Bearer {}", token));
    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_continue(result);
    // Consumer found via "preferred_username", not "sub"
    assert!(ctx.identified_consumer.is_some());
    assert_eq!(ctx.identified_consumer.unwrap().username, "keycloak-user");
    assert_eq!(ctx.authenticated_identity.as_deref(), Some("keycloak-user"));
}

#[tokio::test]
async fn test_jwks_auth_per_provider_consumer_header_claim_override() {
    let private_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_private.pem");
    let public_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_public.pem");

    let (_server, jwks_uri) = start_jwks_server(public_key_pem).await;

    // Global header claim is "email", provider overrides to "upn"
    let plugin = JwksAuth::new(
        &json!({
            "providers": [{
                "jwks_uri": jwks_uri,
                "consumer_identity_claim": "sub",
                "consumer_header_claim": "upn"
            }],
            "consumer_identity_claim": "sub",
            "consumer_header_claim": "email"
        }),
        default_client(),
    )
    .unwrap();
    plugin.warmup_jwks().await;

    let consumer_index = ConsumerIndex::new(&[]);

    let token = create_rs256_token(
        &json!({
            "sub": "user-123",
            "email": "user@google.com",
            "upn": "user@corp.example.com"
        }),
        private_key_pem,
    );

    let mut ctx = make_ctx();
    ctx.headers
        .insert("authorization".to_string(), format!("Bearer {}", token));
    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_continue(result);
    assert_eq!(ctx.authenticated_identity.as_deref(), Some("user-123"));
    // Header uses per-provider "upn", not global "email"
    assert_eq!(
        ctx.authenticated_identity_header.as_deref(),
        Some("user@corp.example.com")
    );
}

#[tokio::test]
async fn test_jwks_auth_multi_provider_different_identity_claims() {
    let private_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_private.pem");
    let public_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_public.pem");

    // Two providers with different JWKS endpoints and different identity claims
    let server1 = wiremock::MockServer::start().await;
    let jwks_json = build_rsa_jwks_from_pem(public_key_pem);
    let jwks_path1 = unique_jwks_path("jwks1");
    wiremock::Mock::given(wiremock::matchers::method("GET"))
        .and(wiremock::matchers::path(jwks_path1.clone()))
        .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(&jwks_json))
        .mount(&server1)
        .await;

    let server2 = wiremock::MockServer::start().await;
    let jwks_path2 = unique_jwks_path("jwks2");
    wiremock::Mock::given(wiremock::matchers::method("GET"))
        .and(wiremock::matchers::path(jwks_path2.clone()))
        .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(&jwks_json))
        .mount(&server2)
        .await;

    let plugin = JwksAuth::new(
        &json!({
            "providers": [
                {
                    "issuer": "https://google.com",
                    "jwks_uri": format!("{}{}", server1.uri(), jwks_path1),
                    "consumer_identity_claim": "email",
                    "consumer_header_claim": "email"
                },
                {
                    "issuer": "https://keycloak.internal",
                    "jwks_uri": format!("{}{}", server2.uri(), jwks_path2),
                    "consumer_identity_claim": "preferred_username",
                    "consumer_header_claim": "preferred_username"
                }
            ],
            "consumer_identity_claim": "sub"
        }),
        default_client(),
    )
    .unwrap();
    plugin.warmup_jwks().await;

    let consumer_index = ConsumerIndex::new(&[]);

    // Token from Google — identity should come from "email" claim
    let token_google = create_rs256_token(
        &json!({
            "sub": "google-uid-123",
            "iss": "https://google.com",
            "email": "alice@gmail.com"
        }),
        private_key_pem,
    );

    let mut ctx = make_ctx();
    ctx.headers.insert(
        "authorization".to_string(),
        format!("Bearer {}", token_google),
    );
    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_continue(result);
    assert_eq!(
        ctx.authenticated_identity.as_deref(),
        Some("alice@gmail.com")
    );

    // Token from Keycloak — identity should come from "preferred_username" claim
    let token_kc = create_rs256_token(
        &json!({
            "sub": "kc-uid-456",
            "iss": "https://keycloak.internal",
            "preferred_username": "bob"
        }),
        private_key_pem,
    );

    let mut ctx2 = make_ctx();
    ctx2.headers
        .insert("authorization".to_string(), format!("Bearer {}", token_kc));
    let result = plugin.authenticate(&mut ctx2, &consumer_index).await;
    assert_continue(result);
    assert_eq!(ctx2.authenticated_identity.as_deref(), Some("bob"));
}

#[tokio::test]
async fn test_jwks_auth_provider_without_override_uses_global() {
    let private_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_private.pem");
    let public_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_public.pem");

    let (_server, jwks_uri) = start_jwks_server(public_key_pem).await;

    // Provider has no consumer_identity_claim — should fall back to global "email"
    let plugin = JwksAuth::new(
        &json!({
            "providers": [{
                "jwks_uri": jwks_uri
            }],
            "consumer_identity_claim": "email"
        }),
        default_client(),
    )
    .unwrap();
    plugin.warmup_jwks().await;

    let consumer_index = ConsumerIndex::new(&[]);

    let token = create_rs256_token(
        &json!({
            "sub": "user-123",
            "email": "user@example.com"
        }),
        private_key_pem,
    );

    let mut ctx = make_ctx();
    ctx.headers
        .insert("authorization".to_string(), format!("Bearer {}", token));
    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_continue(result);
    // Falls back to global consumer_identity_claim="email"
    assert_eq!(
        ctx.authenticated_identity.as_deref(),
        Some("user@example.com")
    );
}

// ─── Request Principal Metadata (Istio iss/sub) ──────────────────────

#[tokio::test]
async fn test_jwks_auth_sets_request_principal_metadata() {
    let private_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_private.pem");
    let public_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_public.pem");

    let (_server, jwks_uri) = start_jwks_server(public_key_pem).await;
    let mut config = single_provider_config(&jwks_uri);
    config["emit_mesh_request_principal_metadata"] = json!(true);
    let plugin = JwksAuth::new(&config, default_client()).unwrap();
    plugin.warmup_jwks().await;

    let consumer_index = ConsumerIndex::new(&[]);

    let token = create_rs256_token(
        &json!({"sub": "user-42", "iss": "https://auth.example.com"}),
        private_key_pem,
    );

    let mut ctx = make_ctx();
    ctx.headers
        .insert("authorization".to_string(), format!("Bearer {}", token));
    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_continue(result);
    assert_eq!(
        ctx.metadata
            .get("mesh.request_principal")
            .map(String::as_str),
        Some("https://auth.example.com/user-42")
    );
}

#[tokio::test]
async fn test_jwks_auth_emits_mesh_audiences_and_claims_outside_metadata() {
    // The mesh RequestAuthentication plugin sets
    // `emit_mesh_request_principal_metadata`, which must surface the JWT
    // audiences and scalar/string-array claims so mesh authz `when:`
    // conditions on `request.auth.audiences` / `request.auth.claims[...]`
    // can be evaluated without serializing claims into transaction metadata.
    let private_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_private.pem");
    let public_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_public.pem");

    let (_server, jwks_uri) = start_jwks_server(public_key_pem).await;
    // Provider must accept the token's audiences for validation to succeed;
    // the emitted `request.auth.audiences` metadata reflects the token's
    // `aud` claim, not the provider's accepted list.
    let config = json!({
        "providers": [{
            "jwks_uri": jwks_uri,
            "audiences": ["api.default", "api.alt"]
        }],
        "emit_mesh_request_principal_metadata": true
    });
    let plugin = JwksAuth::new(&config, default_client()).unwrap();
    plugin.warmup_jwks().await;

    let consumer_index = ConsumerIndex::new(&[]);

    let token = create_rs256_token(
        &json!({
            "sub": "user-42",
            "iss": "https://auth.example.com",
            "aud": ["api.default", "api.alt"],
            "azp": "client-app",
            "groups": ["dev", "ops"],
            "mixed_groups": ["admin", 7],
            "tier": "gold",
            "realm_access][roles": "admin",
            "level": 7,
            "active": true,
            "realm_access": {
                "roles": ["admin", "writer"],
                "level": 9,
                "flags": {
                    "privileged": true,
                    "bad][path": "admin"
                }
            }
        }),
        private_key_pem,
    );

    let mut ctx = make_ctx();
    ctx.headers
        .insert("authorization".to_string(), format!("Bearer {}", token));
    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_continue(result);

    assert_eq!(
        ctx.mesh_request_auth_audiences,
        vec!["api.default".to_string(), "api.alt".to_string()],
        "array audiences should retain item boundaries"
    );
    assert_eq!(
        ctx.mesh_request_auth_claims.get("groups"),
        Some(&JwtAuthAttributeValue::StringList(vec![
            "dev".to_string(),
            "ops".to_string()
        ])),
        "string-array claim should retain item boundaries"
    );
    assert_eq!(
        ctx.mesh_request_auth_claims.get("tier"),
        Some(&JwtAuthAttributeValue::Scalar("gold".to_string()))
    );
    assert_eq!(
        ctx.mesh_request_auth_claims.get("azp"),
        Some(&JwtAuthAttributeValue::Scalar("client-app".to_string())),
        "string azp claim should be available for request.auth.presenter"
    );
    assert!(
        !ctx.mesh_request_auth_claims.contains_key("mixed_groups"),
        "mixed-type arrays must not be narrowed to their string elements"
    );
    assert!(
        !ctx.mesh_request_auth_claims.contains_key("level"),
        "numeric claim should not be emitted for Istio request.auth.claims matching"
    );
    assert!(
        !ctx.mesh_request_auth_claims.contains_key("active"),
        "boolean claim should not be emitted for Istio request.auth.claims matching"
    );
    assert_eq!(
        ctx.mesh_request_auth_claims.get("realm_access][roles"),
        Some(&JwtAuthAttributeValue::StringList(vec![
            "admin".to_string(),
            "writer".to_string()
        ])),
        "nested string-array claim should retain item boundaries and not be overridden by a flat bracket-named claim"
    );
    assert!(
        !ctx.mesh_request_auth_claims
            .contains_key("realm_access][flags][bad][path"),
        "nested claim names containing bracket syntax must not masquerade as deeper paths"
    );
    assert!(
        !ctx.mesh_request_auth_claims
            .contains_key("realm_access][level"),
        "nested numeric claim should not be emitted"
    );
    assert!(
        !ctx.mesh_request_auth_claims
            .contains_key("realm_access][flags][privileged"),
        "nested boolean claim should not be emitted"
    );
    assert!(
        !ctx.metadata
            .keys()
            .any(|key| key.starts_with("mesh.request_auth.")),
        "JWT audiences/claims must not be written to generic log metadata"
    );
}

#[tokio::test]
async fn test_jwks_auth_request_principal_not_set_without_iss() {
    let private_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_private.pem");
    let public_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_public.pem");

    let (_server, jwks_uri) = start_jwks_server(public_key_pem).await;
    let mut config = single_provider_config(&jwks_uri);
    config["emit_mesh_request_principal_metadata"] = json!(true);
    let plugin = JwksAuth::new(&config, default_client()).unwrap();
    plugin.warmup_jwks().await;

    let consumer_index = ConsumerIndex::new(&[]);

    // Token without iss claim — request_principal should not be set
    let token = create_rs256_token(&json!({"sub": "user-42"}), private_key_pem);

    let mut ctx = make_ctx();
    ctx.headers
        .insert("authorization".to_string(), format!("Bearer {}", token));
    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_continue(result);
    assert!(
        !ctx.metadata.contains_key("mesh.request_principal"),
        "request_principal should not be set without iss claim"
    );
}

#[tokio::test]
async fn test_jwks_auth_no_request_principal_when_no_token() {
    let (_server, jwks_uri) = start_jwks_server(include_bytes!(
        "../../../tests/fixtures/test_rsa_public.pem"
    ))
    .await;
    let mut config = single_provider_config(&jwks_uri);
    config["emit_mesh_request_principal_metadata"] = json!(true);
    let plugin = JwksAuth::new(&config, default_client()).unwrap();
    let consumer_index = ConsumerIndex::new(&[]);

    let mut ctx = make_ctx();
    // No Authorization header
    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_continue(result);
    assert!(
        !ctx.metadata.contains_key("mesh.request_principal"),
        "request_principal should not be set for anonymous requests"
    );
}
