//! Tests for jwks_auth plugin

use ferrum_edge::ConsumerIndex;
use ferrum_edge::config::types::AuthMode;
use ferrum_edge::plugins::{
    HTTP_FAMILY_PROTOCOLS, JwtAuthAttributeValue, Plugin, PluginHttpClient, PluginResult,
    RequestContext,
    jwks_auth::{
        DEFAULT_KID_MISS_REFRESH_COOLDOWN_SECONDS, JwksAuth, MAX_JWKS_MAX_STALE_SECONDS,
        MAX_KID_MISS_REFRESH_COOLDOWN_SECONDS,
    },
    key_auth::KeyAuth,
    priority, validate_plugin_config, validate_plugin_config_with_policy,
};
use ferrum_edge::proxy::run_authentication_phase;
use serde_json::{Value, json};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use super::plugin_utils::{
    assert_continue, assert_reject, assert_reject_body, context_with_materialized_raw_header_lines,
    create_test_consumer,
};

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
pub(super) fn build_rsa_jwks_from_pem(public_key_pem: &[u8]) -> serde_json::Value {
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
pub(super) async fn start_jwks_server(public_key_pem: &[u8]) -> (wiremock::MockServer, String) {
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

pub(super) async fn wait_for_received_request_count(
    server: &wiremock::MockServer,
    at_least: usize,
) -> usize {
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

// Remote JWKS background tasks register in the process-global `jwks_cache`.
// Any test that starts those tasks or calls `clear_jwks_cache()` must use
// `#[serial_test::serial(jwks_remote_global_cache)]` so parallel cache resets
// cannot abort a live refresh fetch.

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

#[test]
fn jwks_max_stale_is_finite_bounded_and_cannot_be_disabled() {
    let base = |value| {
        json!({
            "providers": [{"jwks_uri": "https://keys.example.com/jwks"}],
            "jwks_refresh_interval_secs": 30,
            "jwks_max_stale_seconds": value
        })
    };
    for invalid in [0, MAX_JWKS_MAX_STALE_SECONDS + 1] {
        let error = JwksAuth::new(&base(invalid), default_client())
            .err()
            .expect("out-of-range max stale must fail");
        assert!(error.contains("jwks_max_stale_seconds"));
    }

    let shorter_than_refresh = json!({
        "providers": [{"jwks_uri": "https://keys.example.com/jwks"}],
        "jwks_refresh_interval_secs": 60,
        "jwks_max_stale_seconds": 30
    });
    assert!(
        JwksAuth::new(&shorter_than_refresh, default_client())
            .err()
            .expect("refresh beyond trust deadline must fail")
            .contains("must be <=")
    );
}

#[test]
fn provider_max_stale_override_is_reported_for_shared_store_arbitration() {
    let uri = "https://keys.example.com/jwks";
    let plugin = JwksAuth::new(
        &json!({
            "providers": [
                {"jwks_uri": uri, "jwks_max_stale_seconds": 1_800},
                {"jwks_uri": uri, "jwks_max_stale_seconds": 600}
            ],
            "jwks_refresh_interval_secs": 300,
            "jwks_max_stale_seconds": 3_600
        }),
        default_client(),
    )
    .expect("provider overrides are valid");

    let requirements = plugin.active_jwks_refresh_requirements();
    assert_eq!(requirements.len(), 2);
    assert_eq!(requirements[0].1.max_stale.as_secs(), 1_800);
    assert_eq!(requirements[1].1.max_stale.as_secs(), 600);
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
fn dpop_replay_lane_uses_published_default_capacity() {
    let plugin = JwksAuth::new(
        &json!({
            "providers": [{
                "jwks": {"keys": []},
                "issuer": "https://idp.example.com",
                "require_dpop": true,
                "dpop_replay_scope": "process"
            }]
        }),
        default_client(),
    )
    .expect("valid inline provider");

    assert_eq!(
        plugin.dpop_replay_lane_capacities(),
        vec![Some(
            ferrum_edge::plugins::jwks_auth::DEFAULT_DPOP_REPLAY_MAX_ENTRIES
        )]
    );
    assert_eq!(plugin.dpop_replay_modes(), vec![Some("process")]);
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

#[serial_test::serial(jwks_remote_global_cache)]
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

#[serial_test::serial(jwks_remote_global_cache)]
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

#[serial_test::serial(jwks_remote_global_cache)]
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

#[serial_test::serial(jwks_remote_global_cache)]
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
#[serial_test::serial(jwks_remote_global_cache)]
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
#[serial_test::serial(jwks_remote_global_cache)]
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
#[serial_test::serial(jwks_remote_global_cache)]
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
#[serial_test::serial(jwks_remote_global_cache)]
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
#[serial_test::serial(jwks_remote_global_cache)]
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
#[serial_test::serial(jwks_remote_global_cache)]
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

#[serial_test::serial(jwks_remote_global_cache)]
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

#[test]
fn test_jwks_auth_skips_below_floor_rsa_key() {
    let public_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_1024_public.pem");
    let jwks = build_rsa_jwks_from_pem(public_key_pem);
    let error = JwksAuth::new(
        &json!({
            "providers": [{ "jwks": jwks }]
        }),
        default_client(),
    )
    .err()
    .expect("a JWKS with only below-floor RSA keys must not load");
    assert!(
        error.contains("no usable signing keys"),
        "unexpected error: {error}"
    );
}

#[tokio::test]
async fn test_jwks_auth_rejects_token_signed_with_below_floor_rsa_key() {
    let private_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_1024_private.pem");
    let public_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_1024_public.pem");

    let (_server, jwks_uri) = start_jwks_server(public_key_pem).await;
    let plugin = JwksAuth::new(&single_provider_config(&jwks_uri), default_client()).unwrap();
    plugin.warmup_jwks().await;

    let consumer_index = ConsumerIndex::new(&[create_consumer("idp-user")]);
    let token = create_rs256_token(&json!({"sub": "idp-user"}), private_key_pem);

    let mut ctx = make_ctx();
    ctx.headers
        .insert("authorization".to_string(), format!("Bearer {}", token));

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_reject(result, Some(401));
    assert!(ctx.identified_consumer.is_none());
}

#[tokio::test]
async fn test_jwks_auth_trusts_2048_bit_rsa_key_when_mixed_with_below_floor_key() {
    let strong_private = include_bytes!("../../../tests/fixtures/test_rsa_private.pem");
    let strong_public = include_bytes!("../../../tests/fixtures/test_rsa_public.pem");
    let weak_public = include_bytes!("../../../tests/fixtures/test_rsa_1024_public.pem");

    let jwks = json!({
        "keys": [
            build_rsa_jwks_from_pem_with_kid(weak_public, "weak-key")["keys"][0].clone(),
            build_rsa_jwks_from_pem_with_kid(strong_public, "strong-key")["keys"][0].clone(),
        ]
    });
    let plugin = JwksAuth::new(
        &json!({
            "providers": [{ "jwks": jwks }]
        }),
        default_client(),
    )
    .unwrap();

    let consumer_index = ConsumerIndex::new(&[create_consumer("idp-user")]);
    let token =
        create_rs256_token_with_kid(&json!({"sub": "idp-user"}), strong_private, "strong-key");

    let mut ctx = make_ctx();
    ctx.headers
        .insert("authorization".to_string(), format!("Bearer {}", token));

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_continue(result);
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
async fn test_jwks_auth_rejects_future_nbf() {
    let private_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_private.pem");
    let public_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_public.pem");
    let jwks = build_rsa_jwks_from_pem(public_key_pem);
    let plugin = JwksAuth::new(
        &json!({
            "providers": [{ "jwks": jwks }]
        }),
        default_client(),
    )
    .unwrap();

    let now = chrono::Utc::now().timestamp();
    let token = create_rs256_token_exact(
        &json!({
            "sub": "nbf-user",
            "exp": now + 3600,
            "nbf": now + 3600
        }),
        private_key_pem,
    );
    let mut ctx = make_ctx();
    ctx.headers
        .insert("authorization".to_string(), format!("Bearer {token}"));

    let result = plugin
        .authenticate(&mut ctx, &ConsumerIndex::new(&[]))
        .await;
    assert_reject(result, Some(401));
    assert!(ctx.authenticated_identity.is_none());
}

#[tokio::test]
async fn test_jwks_auth_accepts_past_nbf_with_zero_leeway() {
    let private_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_private.pem");
    let public_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_public.pem");
    let jwks = build_rsa_jwks_from_pem(public_key_pem);
    let plugin = JwksAuth::new(
        &json!({
            "providers": [{ "jwks": jwks }]
        }),
        default_client(),
    )
    .unwrap();

    let now = chrono::Utc::now().timestamp();
    let token = create_rs256_token_exact(
        &json!({
            "sub": "nbf-user",
            "exp": now + 3600,
            "nbf": now - 60
        }),
        private_key_pem,
    );
    let mut ctx = make_ctx();
    ctx.headers
        .insert("authorization".to_string(), format!("Bearer {token}"));

    let consumer_index = ConsumerIndex::new(&[create_consumer("nbf-user")]);
    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_continue(result);
    assert_eq!(ctx.authenticated_identity.as_deref(), Some("nbf-user"));
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
                "issuer": "https://idp.example.com",
                "require_dpop": true,
                "dpop_replay_scope": "process"
            }]
        }),
        default_client(),
    )
    .unwrap();
    plugin.warmup_jwks().await;

    let consumer_index = ConsumerIndex::new(&[create_consumer("idp-user")]);
    let access_token = create_rs256_token(
        &json!({"sub": "idp-user", "iss": "https://idp.example.com", "cnf": {"jkt": jkt}}),
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
                "issuer": "https://idp.example.com",
                "require_dpop": true,
                "dpop_replay_scope": "process"
            }]
        }),
        default_client(),
    )
    .unwrap();
    plugin.warmup_jwks().await;

    let consumer_index = ConsumerIndex::new(&[create_consumer("idp-user")]);
    let token = create_rs256_token(
        &json!({"sub": "idp-user", "iss": "https://idp.example.com", "cnf": {"jkt": "missing"}}),
        private_key_pem,
    );
    let mut ctx = make_ctx();
    ctx.headers
        .insert("authorization".to_string(), format!("Bearer {}", token));
    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_reject(result, Some(401));
}

#[tokio::test]
async fn dpop_present_but_non_materialized_rejects_invalid_not_missing() {
    let private_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_private.pem");
    let public_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_public.pem");

    let (_server, jwks_uri) = start_jwks_server(public_key_pem).await;
    let plugin = JwksAuth::new(
        &json!({
            "providers": [{
                "jwks_uri": jwks_uri,
                "issuer": "https://idp.example.com",
                "require_dpop": true,
                "dpop_replay_scope": "process"
            }]
        }),
        default_client(),
    )
    .unwrap();
    plugin.warmup_jwks().await;

    let consumer_index = ConsumerIndex::new(&[create_consumer("idp-user")]);
    let token = create_rs256_token(
        &json!({"sub": "idp-user", "iss": "https://idp.example.com", "cnf": {"jkt": "missing"}}),
        private_key_pem,
    );

    // A present but non-materializable DPoP proof field line: raw bytes hold a
    // non-ASCII suffix that `materialize_headers()` must omit. Extraction must
    // report it as invalid proof material, not as a missing proof.
    let mut ctx = context_with_materialized_raw_header_lines("dpop", &[b"proof\xe3\x80\x80"]);
    ctx.headers
        .insert("authorization".to_string(), format!("Bearer {}", token));
    ctx.headers
        .insert("host".to_string(), "example.com".to_string());
    ctx.metadata
        .insert("ferrum.frontend_scheme".to_string(), "http".to_string());

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_reject_body(result, r#"{"error":"Invalid DPoP proof"}"#);
    assert!(ctx.identified_consumer.is_none());
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

const GENERIC_JWKS_401: &str = r#"{"error":"Invalid or unrecognized JWT"}"#;
const KEY_1_PEM: &[u8] = include_bytes!("../../../tests/fixtures/test_rsa_private.pem");
const KEY_1_PUB: &[u8] = include_bytes!("../../../tests/fixtures/test_rsa_public.pem");
const KEY_2_PEM: &[u8] = include_bytes!("../../../tests/fixtures/test_rsa_private_other.pem");
const KEY_2_PUB: &[u8] = include_bytes!("../../../tests/fixtures/test_rsa_public_other.pem");

fn two_key_jwks() -> Value {
    let key1 = build_rsa_jwks_from_pem_with_kid(KEY_1_PUB, "key-1");
    let key2 = build_rsa_jwks_from_pem_with_kid(KEY_2_PUB, "key-2");
    json!({
        "keys": [key1["keys"][0].clone(), key2["keys"][0].clone()]
    })
}

fn two_key_inline_plugin() -> JwksAuth {
    JwksAuth::new(
        &json!({
            "providers": [{
                "jwks": two_key_jwks()
            }]
        }),
        default_client(),
    )
    .unwrap()
}

async fn authenticate_bearer(plugin: &JwksAuth, token: &str) -> PluginResult {
    let mut ctx = make_ctx();
    ctx.headers
        .insert("authorization".to_string(), format!("Bearer {token}"));
    plugin
        .authenticate(&mut ctx, &ConsumerIndex::new(&[]))
        .await
}

fn assert_generic_jwt_401(result: PluginResult) {
    match result {
        PluginResult::Reject {
            status_code, body, ..
        } => {
            assert_eq!(status_code, 401);
            assert_eq!(body, GENERIC_JWKS_401);
            assert!(
                !body.to_ascii_lowercase().contains("kid"),
                "generic 401 must not echo kid"
            );
        }
        other => panic!("expected generic 401, got {other:?}"),
    }
}

#[tokio::test]
async fn test_jwks_auth_token_without_kid_is_rejected() {
    let plugin = two_key_inline_plugin();
    let token = create_rs256_token_no_kid(&json!({"sub": "user"}), KEY_1_PEM);
    assert_generic_jwt_401(authenticate_bearer(&plugin, &token).await);
}

#[tokio::test]
async fn test_jwks_auth_unknown_kid_is_rejected_even_when_another_published_key_verifies() {
    let plugin = two_key_inline_plugin();
    let token = create_rs256_token_with_kid(&json!({"sub": "user"}), KEY_1_PEM, "no-such-kid");
    assert_generic_jwt_401(authenticate_bearer(&plugin, &token).await);
}

#[tokio::test]
async fn test_jwks_auth_known_kid_wrong_key_is_rejected() {
    let plugin = two_key_inline_plugin();
    let token = create_rs256_token_with_kid(&json!({"sub": "user"}), KEY_2_PEM, "key-1");
    assert_generic_jwt_401(authenticate_bearer(&plugin, &token).await);
}

#[tokio::test]
async fn test_jwks_auth_known_kid_matching_key_is_accepted() {
    let plugin = two_key_inline_plugin();
    let token = create_rs256_token_with_kid(&json!({"sub": "user"}), KEY_1_PEM, "key-1");
    let mut ctx = make_ctx();
    ctx.headers
        .insert("authorization".to_string(), format!("Bearer {token}"));
    let result = plugin
        .authenticate(&mut ctx, &ConsumerIndex::new(&[]))
        .await;
    assert_continue(result);
    assert_eq!(ctx.authenticated_identity.as_deref(), Some("user"));
}

#[tokio::test]
async fn test_jwks_auth_second_published_key_is_accepted_only_under_its_own_kid() {
    let plugin = two_key_inline_plugin();
    let matching = create_rs256_token_with_kid(&json!({"sub": "other"}), KEY_2_PEM, "key-2");
    let mut ctx = make_ctx();
    ctx.headers
        .insert("authorization".to_string(), format!("Bearer {matching}"));
    let result = plugin
        .authenticate(&mut ctx, &ConsumerIndex::new(&[]))
        .await;
    assert_continue(result);
    assert_eq!(ctx.authenticated_identity.as_deref(), Some("other"));

    let swapped = create_rs256_token_with_kid(&json!({"sub": "other"}), KEY_1_PEM, "key-2");
    assert_generic_jwt_401(authenticate_bearer(&plugin, &swapped).await);
}

#[tokio::test]
async fn test_jwks_auth_multi_provider_does_not_fall_back_across_key_sets() {
    let plugin = JwksAuth::new(
        &json!({
            "providers": [
                {
                    "issuer": "https://idp-a.example.com",
                    "jwks": build_rsa_jwks_from_pem_with_kid(KEY_1_PUB, "key-a")
                },
                {
                    "issuer": "https://idp-b.example.com",
                    "jwks": build_rsa_jwks_from_pem_with_kid(KEY_2_PUB, "key-b")
                }
            ]
        }),
        default_client(),
    )
    .unwrap();

    let valid_a = create_rs256_token_with_kid(
        &json!({"iss": "https://idp-a.example.com", "sub": "user-a"}),
        KEY_1_PEM,
        "key-a",
    );
    let mut ctx = make_ctx();
    ctx.headers
        .insert("authorization".to_string(), format!("Bearer {valid_a}"));
    let result = plugin
        .authenticate(&mut ctx, &ConsumerIndex::new(&[]))
        .await;
    assert_continue(result);
    assert_eq!(ctx.authenticated_identity.as_deref(), Some("user-a"));

    let unknown_kid = create_rs256_token_with_kid(
        &json!({"iss": "https://idp-a.example.com", "sub": "user-a"}),
        KEY_1_PEM,
        "key-b",
    );
    assert_generic_jwt_401(authenticate_bearer(&plugin, &unknown_kid).await);

    let missing_kid = create_rs256_token_no_kid(
        &json!({"iss": "https://idp-a.example.com", "sub": "user-a"}),
        KEY_1_PEM,
    );
    assert_generic_jwt_401(authenticate_bearer(&plugin, &missing_kid).await);

    let wrong_key = create_rs256_token_with_kid(
        &json!({"iss": "https://idp-a.example.com", "sub": "user-a"}),
        KEY_2_PEM,
        "key-a",
    );
    assert_generic_jwt_401(authenticate_bearer(&plugin, &wrong_key).await);
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
async fn mesh_shaped_jwks_auth_rejects_aud_less_and_future_nbf_before_identity_staging() {
    // Config shape produced by mesh RequestAuthentication injection:
    // issuer + audiences + emit_mesh_request_principal_metadata.
    let private_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_private.pem");
    let public_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_public.pem");
    let jwks = build_rsa_jwks_from_pem(public_key_pem);
    let plugin = JwksAuth::new(
        &json!({
            "providers": [{
                "issuer": "https://issuer.example.com",
                "jwks": jwks,
                "audiences": ["orders-api"],
                "forward_original_token": false
            }],
            "require_exp": true,
            "emit_mesh_request_principal_metadata": true
        }),
        default_client(),
    )
    .unwrap();

    let now = chrono::Utc::now().timestamp();
    let aud_less = create_rs256_token_exact(
        &json!({
            "iss": "https://issuer.example.com",
            "sub": "mesh-user",
            "exp": now + 3600
        }),
        private_key_pem,
    );
    let mut aud_less_ctx = make_ctx();
    aud_less_ctx
        .headers
        .insert("authorization".to_string(), format!("Bearer {aud_less}"));
    let aud_less_result = plugin
        .authenticate(&mut aud_less_ctx, &ConsumerIndex::new(&[]))
        .await;
    assert_reject(aud_less_result, Some(401));
    assert!(aud_less_ctx.authenticated_identity.is_none());
    assert!(
        !aud_less_ctx.metadata.contains_key("mesh.request_principal"),
        "aud-less tokens must not stage mesh identity attributes"
    );
    assert!(aud_less_ctx.mesh_request_auth_audiences.is_empty());

    let future_nbf = create_rs256_token_exact(
        &json!({
            "iss": "https://issuer.example.com",
            "sub": "mesh-user",
            "aud": "orders-api",
            "exp": now + 7200,
            "nbf": now + 3600
        }),
        private_key_pem,
    );
    let mut nbf_ctx = make_ctx();
    nbf_ctx
        .headers
        .insert("authorization".to_string(), format!("Bearer {future_nbf}"));
    let nbf_result = plugin
        .authenticate(&mut nbf_ctx, &ConsumerIndex::new(&[]))
        .await;
    assert_reject(nbf_result, Some(401));
    assert!(nbf_ctx.authenticated_identity.is_none());
    assert!(
        !nbf_ctx.metadata.contains_key("mesh.request_principal"),
        "future-nbf tokens must not stage mesh identity attributes"
    );
    assert!(nbf_ctx.mesh_request_auth_audiences.is_empty());
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

// ---------------------------------------------------------------------------
// Discovery-backed trust health parity (issue #3739)
// ---------------------------------------------------------------------------

/// Mount a discovery document plus its JWKS endpoint on one server and return
/// `(discovery_url, jwks_uri)`.
async fn mount_discovery_and_jwks(
    server: &wiremock::MockServer,
    public_key_pem: &[u8],
) -> (String, String) {
    let jwks_path = unique_jwks_path("trust-jwks");
    let jwks_uri = format!("{}{jwks_path}", server.uri());
    let discovery_path = unique_jwks_path("trust-discovery");
    let discovery_url = format!("{}{discovery_path}", server.uri());
    wiremock::Mock::given(wiremock::matchers::method("GET"))
        .and(wiremock::matchers::path(jwks_path))
        .respond_with(
            wiremock::ResponseTemplate::new(200)
                .set_body_json(build_rsa_jwks_from_pem(public_key_pem)),
        )
        .mount(server)
        .await;
    wiremock::Mock::given(wiremock::matchers::method("GET"))
        .and(wiremock::matchers::path(discovery_path))
        .respond_with(
            wiremock::ResponseTemplate::new(200).set_body_json(json!({ "jwks_uri": jwks_uri })),
        )
        .mount(server)
        .await;
    (discovery_url, jwks_uri)
}

async fn wait_for_active_remote_stores(expected: u64) -> u64 {
    use ferrum_edge::plugins::utils::jwks_cache::trust_health_snapshot;
    let deadline = tokio::time::Instant::now() + tokio::time::Duration::from_secs(3);
    loop {
        let snapshot = trust_health_snapshot();
        let total = snapshot.fresh + snapshot.grace + snapshot.expired;
        if total == expected || tokio::time::Instant::now() >= deadline {
            return total;
        }
        tokio::time::sleep(tokio::time::Duration::from_millis(20)).await;
    }
}

#[serial_test::serial(jwks_remote_global_cache)]
#[tokio::test]
async fn discovery_resolved_after_publication_becomes_active_without_another_reload() {
    use ferrum_edge::plugins::utils::jwks_cache::{cached_requirement, clear_jwks_cache};

    let public_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_public.pem");
    let server = wiremock::MockServer::start().await;
    let (discovery_url, jwks_uri) = mount_discovery_and_jwks(&server, public_key_pem).await;
    let _guard = super::jwks_cache_tests::cache_test_lock().lock().await;
    clear_jwks_cache();

    let plugin = JwksAuth::new(
        &json!({
            "providers": [{"discovery_url": discovery_url, "jwks_max_stale_seconds": 900}],
            "jwks_refresh_interval_secs": 300
        }),
        default_client(),
    )
    .unwrap();

    // Publication order in PluginCache: stage workers, install the generation,
    // reconcile requirements, then commit. Discovery here resolves only after
    // the reconciliation, which is exactly the case that previously left the
    // store invisible to readiness and metrics.
    plugin
        .start_background_tasks()
        .expect("test runtime should start JWKS tasks");
    ferrum_edge::plugins::utils::jwks_cache::retain_active_requirements(
        &std::collections::HashMap::new(),
    );
    plugin.commit_background_tasks();

    assert_eq!(
        wait_for_active_remote_stores(1).await,
        1,
        "a committed discovery-backed store must join the active trust aggregate"
    );
    let requirement = cached_requirement(&jwks_uri).expect("discovered store is cached");
    assert_eq!(
        requirement.max_stale,
        tokio::time::Duration::from_secs(900),
        "the discovered store must carry this provider's exact max-stale bound"
    );
    assert_eq!(
        requirement.refresh_interval,
        tokio::time::Duration::from_secs(300)
    );

    drop(plugin);
    assert_eq!(
        wait_for_active_remote_stores(0).await,
        0,
        "retiring the owning generation must withdraw its contribution"
    );
    clear_jwks_cache();
}

#[serial_test::serial(jwks_remote_global_cache)]
#[tokio::test]
async fn staged_discovery_is_withheld_until_commit_and_a_rejected_generation_leaves_nothing() {
    use ferrum_edge::plugins::utils::jwks_cache::{clear_jwks_cache, trust_health_snapshot};

    let public_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_public.pem");
    let server = wiremock::MockServer::start().await;
    let (discovery_url, _jwks_uri) = mount_discovery_and_jwks(&server, public_key_pem).await;
    let _guard = super::jwks_cache_tests::cache_test_lock().lock().await;
    clear_jwks_cache();

    let build = || {
        JwksAuth::new(
            &json!({
                "providers": [{
                    "discovery_url": discovery_url.clone(),
                    "jwks_max_stale_seconds": 900
                }],
                "jwks_refresh_interval_secs": 300
            }),
            default_client(),
        )
        .unwrap()
    };

    // A staged generation whose discovery task already published into its local
    // slot must contribute nothing, and a rejected one must not stick.
    let rejected = build();
    rejected
        .start_background_tasks()
        .expect("test runtime should start JWKS tasks");
    wait_for_received_request_count(&server, 2).await;
    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
    let staged = trust_health_snapshot();
    assert_eq!(
        (staged.fresh, staged.grace, staged.expired),
        (0, 0, 0),
        "an unpublished generation must not reach readiness or metrics"
    );
    drop(rejected);
    let after_reject = trust_health_snapshot();
    assert_eq!(
        (after_reject.fresh, after_reject.grace, after_reject.expired),
        (0, 0, 0),
        "a rejected staged generation must leave no active contribution"
    );

    // The same resolution, once its generation commits, is adopted at commit
    // rather than at some later reload.
    let committed = build();
    committed
        .start_background_tasks()
        .expect("test runtime should start JWKS tasks");
    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
    committed.commit_background_tasks();
    assert_eq!(
        wait_for_active_remote_stores(1).await,
        1,
        "commit must adopt a store discovery resolved while the generation was staged"
    );

    drop(committed);
    assert_eq!(wait_for_active_remote_stores(0).await, 0);
    clear_jwks_cache();
}

async fn wait_for_cached_max_stale(jwks_uri: &str, expected_secs: u64) {
    use ferrum_edge::plugins::utils::jwks_cache::cached_requirement;
    let expected = tokio::time::Duration::from_secs(expected_secs);
    let deadline = tokio::time::Instant::now() + tokio::time::Duration::from_secs(3);
    loop {
        let observed = cached_requirement(jwks_uri).map(|requirement| requirement.max_stale);
        if observed == Some(expected) || tokio::time::Instant::now() >= deadline {
            assert_eq!(
                observed,
                Some(expected),
                "shared store must settle on the strictest active max-stale"
            );
            return;
        }
        tokio::time::sleep(tokio::time::Duration::from_millis(20)).await;
    }
}

#[serial_test::serial(jwks_remote_global_cache)]
#[tokio::test]
async fn shared_discovery_uri_relaxes_only_after_the_stricter_generation_retires() {
    use ferrum_edge::plugins::utils::jwks_cache::clear_jwks_cache;

    let public_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_public.pem");
    let server = wiremock::MockServer::start().await;
    let (discovery_url, jwks_uri) = mount_discovery_and_jwks(&server, public_key_pem).await;
    let _guard = super::jwks_cache_tests::cache_test_lock().lock().await;
    clear_jwks_cache();

    let build = |max_stale_secs: u64| {
        JwksAuth::new(
            &json!({
                "providers": [{
                    "discovery_url": discovery_url.clone(),
                    "jwks_max_stale_seconds": max_stale_secs
                }],
                "jwks_refresh_interval_secs": 300
            }),
            default_client(),
        )
        .unwrap()
    };

    // Publish the relaxed consumer first and observe its contribution land.
    let relaxed = build(3_600);
    start_background_tasks(&relaxed);
    assert_eq!(wait_for_active_remote_stores(1).await, 1);
    wait_for_cached_max_stale(&jwks_uri, 3_600).await;

    // A second committed consumer of the same discovered URI tightens it.
    let strict = build(600);
    start_background_tasks(&strict);
    wait_for_cached_max_stale(&jwks_uri, 600).await;
    assert_eq!(
        wait_for_active_remote_stores(1).await,
        1,
        "same-URI consumers share exactly one active store"
    );

    // Relaxation happens only once the stricter committed consumer is gone,
    // and must not deactivate the surviving co-tenant.
    drop(strict);
    wait_for_cached_max_stale(&jwks_uri, 3_600).await;
    assert_eq!(
        wait_for_active_remote_stores(1).await,
        1,
        "retiring one consumer must not deactivate the surviving co-tenant"
    );

    drop(relaxed);
    assert_eq!(wait_for_active_remote_stores(0).await, 0);
    clear_jwks_cache();
}

// ────────────────────────────────────────────────────────────────────
// Issue #3834 — DPoP proofs are single-use across reloads and replicas
// ────────────────────────────────────────────────────────────────────

/// Everything a DPoP request needs, built once so the reload / replica /
/// isolation cases can replay byte-identical inputs.
struct DpopFixture {
    access_token: String,
    proof: String,
}

fn build_dpop_fixture(jti: &str) -> (DpopFixture, serde_json::Value) {
    let now = chrono::Utc::now().timestamp();
    build_dpop_fixture_with_times(jti, now, Some(now + 60))
}

/// Build a DPoP fixture with an explicit `iat` and an OPTIONAL `exp`.
///
/// RFC 9449 §4.2 defines no `exp` proof claim, so `None` is the conformant
/// shape most client libraries emit; `Some` covers the clients that send one
/// anyway and must still be held to it.
fn build_dpop_fixture_with_times(
    jti: &str,
    iat: i64,
    exp: Option<i64>,
) -> (DpopFixture, serde_json::Value) {
    use base64::Engine;
    use ferrum_edge::plugins::utils::dpop::jwk_thumbprint_sha256;
    use jsonwebtoken::{EncodingKey, Header, encode};
    use sha2::{Digest, Sha256};

    let private_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_private.pem");
    let public_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_public.pem");
    let jwks = build_rsa_jwks_from_pem(public_key_pem);
    let jwk: jsonwebtoken::jwk::Jwk = serde_json::from_value(jwks["keys"][0].clone()).unwrap();
    let jkt = jwk_thumbprint_sha256(&jwk).unwrap();

    let access_token = create_rs256_token(
        &json!({"sub": "idp-user", "iss": DPOP_TEST_ISSUER, "cnf": {"jkt": jkt}}),
        private_key_pem,
    );
    let mut hasher = Sha256::new();
    hasher.update(access_token.as_bytes());
    let ath = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hasher.finalize());

    let mut dpop_header = Header::new(jsonwebtoken::Algorithm::RS256);
    dpop_header.typ = Some("dpop+jwt".to_string());
    dpop_header.jwk = Some(jwk);
    let mut proof_claims = json!({
        "htm": "GET",
        "htu": "http://example.com/test",
        "iat": iat,
        "jti": jti,
        "ath": ath
    });
    if let Some(exp) = exp {
        proof_claims["exp"] = json!(exp);
    }
    let proof = encode(
        &dpop_header,
        &proof_claims,
        &EncodingKey::from_rsa_pem(private_key_pem).unwrap(),
    )
    .unwrap();

    (
        DpopFixture {
            access_token,
            proof,
        },
        jwks,
    )
}

fn dpop_ctx(fixture: &DpopFixture) -> RequestContext {
    let mut ctx = make_ctx();
    ctx.headers.insert(
        "authorization".to_string(),
        format!("Bearer {}", fixture.access_token),
    );
    ctx.headers
        .insert("dpop".to_string(), fixture.proof.clone());
    ctx.headers
        .insert("host".to_string(), "example.com".to_string());
    ctx.metadata
        .insert("ferrum.frontend_scheme".to_string(), "http".to_string());
    ctx
}

fn dpop_plugin(jwks: &serde_json::Value, config_id: &str) -> JwksAuth {
    JwksAuth::new_with_config_id(
        &json!({
            "providers": [{
                "jwks": jwks,
                "issuer": DPOP_TEST_ISSUER,
                "require_dpop": true,
                "dpop_replay_scope": "process"
            }]
        }),
        default_client(),
        Some(config_id),
    )
    .expect("inline-JWKS DPoP provider with a declared replay scope")
}

#[tokio::test]
async fn dpop_exact_proof_replay_is_rejected() {
    let (fixture, jwks) = build_dpop_fixture("dpop-replay-sequential");
    let plugin = dpop_plugin(&jwks, "dpop-sequential");
    let consumer_index = ConsumerIndex::new(&[create_consumer("idp-user")]);

    let mut first = dpop_ctx(&fixture);
    assert_continue(plugin.authenticate(&mut first, &consumer_index).await);

    let mut replay = dpop_ctx(&fixture);
    assert_reject(
        plugin.authenticate(&mut replay, &consumer_index).await,
        Some(401),
    );
}

/// The reload opening from issue #3834: a rebuilt plugin generation must
/// inherit the retired generation's replay markers instead of starting empty.
#[tokio::test]
async fn dpop_replay_stays_rejected_after_an_equivalent_plugin_rebuild() {
    let (fixture, jwks) = build_dpop_fixture("dpop-replay-reload");
    let consumer_index = ConsumerIndex::new(&[create_consumer("idp-user")]);

    let original = dpop_plugin(&jwks, "dpop-reload");
    let mut first = dpop_ctx(&fixture);
    assert_continue(original.authenticate(&mut first, &consumer_index).await);

    // Retire the generation that admitted the proof, exactly as a plugin-cache
    // rebuild does, and construct an equivalent replacement.
    drop(original);
    let reloaded = dpop_plugin(&jwks, "dpop-reload");
    let mut replay = dpop_ctx(&fixture);
    assert_reject(
        reloaded.authenticate(&mut replay, &consumer_index).await,
        Some(401),
    );
}

/// Two equivalent generations alive at once (the rolling-deployment shape)
/// share one protection domain, so a proof admitted by either is a replay for
/// the other.
#[tokio::test]
async fn dpop_replay_is_rejected_across_equivalent_concurrent_generations() {
    let (fixture, jwks) = build_dpop_fixture("dpop-replay-rolling");
    let consumer_index = ConsumerIndex::new(&[create_consumer("idp-user")]);

    let old_generation = dpop_plugin(&jwks, "dpop-rolling");
    let new_generation = dpop_plugin(&jwks, "dpop-rolling");

    let mut first = dpop_ctx(&fixture);
    assert_continue(
        old_generation
            .authenticate(&mut first, &consumer_index)
            .await,
    );
    let mut replay = dpop_ctx(&fixture);
    assert_reject(
        new_generation
            .authenticate(&mut replay, &consumer_index)
            .await,
        Some(401),
    );
}

/// Distinct policies must not suppress one another: the same proof presented to
/// an unrelated `jwks_auth` policy is that policy's first sighting.
#[tokio::test]
async fn dpop_replay_lanes_are_isolated_across_policies() {
    let (fixture, jwks) = build_dpop_fixture("dpop-replay-isolation");
    let consumer_index = ConsumerIndex::new(&[create_consumer("idp-user")]);

    let policy_a = dpop_plugin(&jwks, "dpop-isolation-a");
    let policy_b = dpop_plugin(&jwks, "dpop-isolation-b");

    let mut first = dpop_ctx(&fixture);
    assert_continue(policy_a.authenticate(&mut first, &consumer_index).await);
    let mut second = dpop_ctx(&fixture);
    assert_continue(policy_b.authenticate(&mut second, &consumer_index).await);
}

/// Filling a provider's replay lane must never make an unexpired proof
/// reusable: at capacity a NEW proof is refused (503) while the retained one
/// stays a replay (401).
#[tokio::test]
async fn dpop_capacity_refuses_new_proofs_without_freeing_a_live_marker() {
    let (retained, jwks) = build_dpop_fixture("dpop-capacity-retained");
    let (fresh, _) = build_dpop_fixture("dpop-capacity-fresh");
    let consumer_index = ConsumerIndex::new(&[create_consumer("idp-user")]);

    let plugin = JwksAuth::new_with_config_id(
        &json!({
            "providers": [{
                "jwks": jwks,
                "issuer": DPOP_TEST_ISSUER,
                "require_dpop": true,
                "dpop_replay_scope": "process",
                "dpop_replay_max_entries": 1
            }]
        }),
        default_client(),
        Some("dpop-capacity"),
    )
    .expect("single-slot DPoP replay lane");

    let mut first = dpop_ctx(&retained);
    assert_continue(plugin.authenticate(&mut first, &consumer_index).await);

    // The lane is full and the retained marker is live: the new proof is
    // refused rather than the live marker evicted.
    let mut new_proof = dpop_ctx(&fresh);
    assert_reject(
        plugin.authenticate(&mut new_proof, &consumer_index).await,
        Some(503),
    );

    // …and the retained proof is still a replay, so capacity pressure did not
    // reopen it.
    let mut replay = dpop_ctx(&retained);
    assert_reject(
        plugin.authenticate(&mut replay, &consumer_index).await,
        Some(401),
    );
}

/// `require_dpop` without a declared replay scope is refused at admission: a
/// gateway cannot observe its own replica count, so the declaration is the
/// control that prevents silent per-replica replay.
#[test]
fn dpop_requires_an_explicitly_declared_replay_scope() {
    let error = JwksAuth::new(
        &json!({
            "providers": [{
                "jwks": {"keys": []},
                "issuer": "https://idp.example.com",
                "require_dpop": true
            }]
        }),
        default_client(),
    )
    .map(|_| ())
    .expect_err("require_dpop without a replay scope must be refused");
    assert!(
        error.contains("dpop_replay_scope"),
        "diagnostic should name the missing declaration: {error}"
    );

    // The scope is meaningless without the feature it protects.
    assert!(
        JwksAuth::new(
            &json!({
                "providers": [{"jwks": {"keys": []}, "dpop_replay_scope": "process"}]
            }),
            default_client(),
        )
        .is_err()
    );

    // `shared` must be backed by Redis, and Redis must be consumed by a
    // `shared` provider — a scope/backend disagreement is a misconfiguration in
    // both directions, never a silent degradation to process-local state.
    assert!(
        JwksAuth::new(
            &json!({
                "providers": [{
                    "jwks": {"keys": []},
                    "issuer": "https://idp.example.com",
                    "require_dpop": true,
                    "dpop_replay_scope": "shared"
                }]
            }),
            default_client(),
        )
        .is_err()
    );
    assert!(
        JwksAuth::new(
            &json!({
                "providers": [{
                    "jwks": {"keys": []},
                    "issuer": "https://idp.example.com",
                    "require_dpop": true,
                    "dpop_replay_scope": "process"
                }],
                "sync_mode": "redis",
                "redis_url": "redis://127.0.0.1:6379"
            }),
            default_client(),
        )
        .is_err()
    );
}

/// `require_dpop` without a nonblank exact issuer is refused: the replay realm
/// is the issuer, so omitting it would make key rotation or a source-URI change
/// reopen every live proof.
#[test]
fn dpop_requires_a_nonblank_exact_issuer() {
    let error = JwksAuth::new(
        &json!({
            "providers": [{
                "jwks": {"keys": []},
                "require_dpop": true,
                "dpop_replay_scope": "process"
            }]
        }),
        default_client(),
    )
    .map(|_| ())
    .expect_err("require_dpop without an issuer must be refused");
    assert!(
        error.contains("issuer") && error.contains("require_dpop"),
        "diagnostic should name the missing issuer: {error}"
    );
}

// ── semantic provider identity ──────────────────────────────────────
//
// A provider's DPoP protection sub-domain is a digest of its exact issuer
// realm, never its JWKS contents, key ids, source URL, or position in the
// `providers` array. An ordinal is not an identity: reordering an unchanged
// list, or inserting or deleting an unrelated provider ahead of one, would
// otherwise strand a provider's live markers in a lane nothing consults and
// readmit a proof it had already claimed. Hashing the JWKS document or source
// endpoint would reopen those markers on an ordinary key rotation.

const DPOP_TEST_ISSUER: &str = "https://idp.example.com";
const DPOP_DECOY_ISSUER: &str = "https://decoy.example.invalid";

fn dpop_provider(jwks: &serde_json::Value) -> serde_json::Value {
    json!({
        "jwks": jwks,
        "issuer": DPOP_TEST_ISSUER,
        "require_dpop": true,
        "dpop_replay_scope": "process"
    })
}

fn dpop_shared_provider(jwks: &serde_json::Value) -> serde_json::Value {
    json!({
        "jwks": jwks,
        "issuer": DPOP_TEST_ISSUER,
        "require_dpop": true,
        "dpop_replay_scope": "shared"
    })
}

/// Construction with a configured Redis backend. Used to prove mixed
/// process/shared equivalent providers are refused even when the plugin-level
/// effective scope would otherwise be `shared` (the previous hole).
fn jwks_with_redis(providers: serde_json::Value, config_id: &str) -> Result<JwksAuth, String> {
    JwksAuth::new_with_config_id(
        &json!({
            "providers": providers,
            "sync_mode": "redis",
            "redis_url": "redis://127.0.0.1:6379"
        }),
        default_client(),
        Some(config_id),
    )
}

/// A provider that requires DPoP but can never validate a token, so it is only
/// ever an ordinal neighbour of the provider under test. It uses a distinct
/// issuer so it does not share the real provider's replay realm.
fn dpop_decoy_provider() -> serde_json::Value {
    let mut decoy = dpop_provider(&json!({"keys": []}));
    decoy["issuer"] = json!(DPOP_DECOY_ISSUER);
    decoy
}

fn dpop_plugin_with_providers(providers: serde_json::Value, config_id: &str) -> JwksAuth {
    JwksAuth::new_with_config_id(
        &json!({ "providers": providers }),
        default_client(),
        Some(config_id),
    )
    .expect("multi-provider DPoP config with declared replay scopes")
}

/// Reordering an otherwise equivalent provider list must not reopen a proof.
#[tokio::test]
async fn dpop_provider_reordering_does_not_reopen_an_accepted_proof() {
    let (fixture, jwks) = build_dpop_fixture("dpop-provider-reorder");
    let consumer_index = ConsumerIndex::new(&[create_consumer("idp-user")]);

    let decoy_first = dpop_plugin_with_providers(
        json!([dpop_decoy_provider(), dpop_provider(&jwks)]),
        "dpop-reorder",
    );
    let mut first = dpop_ctx(&fixture);
    assert_continue(decoy_first.authenticate(&mut first, &consumer_index).await);

    // The same two providers, swapped. Under array-position identity the real
    // provider would move from sub-domain `1` to `0` and start a fresh lane.
    let real_first = dpop_plugin_with_providers(
        json!([dpop_provider(&jwks), dpop_decoy_provider()]),
        "dpop-reorder",
    );
    let mut replay = dpop_ctx(&fixture);
    assert_reject(
        real_first.authenticate(&mut replay, &consumer_index).await,
        Some(401),
    );
}

/// Inserting, then deleting, then recreating a neighbouring provider must not
/// reopen a proof at any step.
#[tokio::test]
async fn dpop_provider_insert_delete_and_recreate_do_not_reopen_a_proof() {
    let (fixture, jwks) = build_dpop_fixture("dpop-provider-lifecycle");
    let consumer_index = ConsumerIndex::new(&[create_consumer("idp-user")]);

    let only = dpop_plugin_with_providers(json!([dpop_provider(&jwks)]), "dpop-lifecycle");
    let mut first = dpop_ctx(&fixture);
    assert_continue(only.authenticate(&mut first, &consumer_index).await);
    drop(only);

    for providers in [
        // A neighbour inserted ahead of it.
        json!([dpop_decoy_provider(), dpop_provider(&jwks)]),
        // The neighbour deleted again.
        json!([dpop_provider(&jwks)]),
        // And recreated behind it.
        json!([dpop_provider(&jwks), dpop_decoy_provider()]),
    ] {
        let generation = dpop_plugin_with_providers(providers, "dpop-lifecycle");
        let mut replay = dpop_ctx(&fixture);
        assert_reject(
            generation.authenticate(&mut replay, &consumer_index).await,
            Some(401),
        );
    }
}

/// A security-irrelevant edit is not a new trust anchor: it must not reopen a
/// proof the previous generation already claimed. Widening the clock skew is the
/// sharpest case — the fixed retention horizon already dominates the widest
/// admissible skew, so the marker outlives the wider window.
#[tokio::test]
async fn security_irrelevant_provider_edits_do_not_reopen_a_proof() {
    let (fixture, jwks) = build_dpop_fixture("dpop-provider-irrelevant-edit");
    let consumer_index = ConsumerIndex::new(&[create_consumer("idp-user")]);

    let original = dpop_plugin_with_providers(json!([dpop_provider(&jwks)]), "dpop-irrelevant");
    let mut first = dpop_ctx(&fixture);
    assert_continue(original.authenticate(&mut first, &consumer_index).await);
    drop(original);

    let mut edited = dpop_provider(&jwks);
    edited["dpop_clock_skew_secs"] = json!(120);
    edited["dpop_replay_max_entries"] = json!(4096);
    edited["forward_original_token"] = json!(false);
    let reloaded = dpop_plugin_with_providers(json!([edited]), "dpop-irrelevant");

    let mut replay = dpop_ctx(&fixture);
    assert_reject(
        reloaded.authenticate(&mut replay, &consumer_index).await,
        Some(401),
    );
}

/// Additive inline key rotation for the same issuer must not reopen a proof
/// the previous generation already claimed.
#[tokio::test]
async fn inline_key_rotation_for_the_same_issuer_does_not_reopen_a_proof() {
    let (fixture, jwks) = build_dpop_fixture("dpop-provider-key-rotation");
    let consumer_index = ConsumerIndex::new(&[create_consumer("idp-user")]);

    let original = dpop_plugin_with_providers(json!([dpop_provider(&jwks)]), "dpop-key-rotation");
    let mut first = dpop_ctx(&fixture);
    assert_continue(original.authenticate(&mut first, &consumer_index).await);
    drop(original);

    let mut rotated = jwks.clone();
    let extra = rotated["keys"][0].clone();
    rotated["keys"] = json!([jwks["keys"][0].clone(), extra]);
    rotated["keys"][1]["kid"] = json!("rotated-kid");
    let reloaded =
        dpop_plugin_with_providers(json!([dpop_provider(&rotated)]), "dpop-key-rotation");
    let mut replay = dpop_ctx(&fixture);
    assert_reject(
        reloaded.authenticate(&mut replay, &consumer_index).await,
        Some(401),
    );
}

/// Two duplicate provider entries are one trust anchor, so they converge on one
/// lane. A duplicated entry can therefore not launder a second acceptance.
#[tokio::test]
async fn duplicate_providers_converge_on_one_replay_lane() {
    let (fixture, jwks) = build_dpop_fixture("dpop-provider-duplicate");
    let consumer_index = ConsumerIndex::new(&[create_consumer("idp-user")]);

    let duplicated = dpop_plugin_with_providers(
        json!([dpop_provider(&jwks), dpop_provider(&jwks)]),
        "dpop-duplicate",
    );
    let markers = duplicated.dpop_replay_domain_markers("thumbprint", "proof-id");
    assert_eq!(markers.len(), 2);
    assert_eq!(
        markers[0], markers[1],
        "equivalent providers must share one protection domain"
    );

    let mut first = dpop_ctx(&fixture);
    assert_continue(duplicated.authenticate(&mut first, &consumer_index).await);
    let mut replay = dpop_ctx(&fixture);
    assert_reject(
        duplicated.authenticate(&mut replay, &consumer_index).await,
        Some(401),
    );
}

/// Same-issuer providers share one replay realm even when their key sets or
/// JWKS sources differ; different exact issuers stay isolated. Inline JWKS
/// member order is not part of the identity.
#[test]
fn dpop_provider_identity_is_the_exact_issuer_realm() {
    let (_, jwks) = build_dpop_fixture("dpop-provider-identity");

    // Different inline key sets under one issuer share a realm — key rotation
    // must not reopen a proof.
    let mut other_keys = jwks.clone();
    other_keys["keys"][0]["kid"] = json!("a-different-key-id");
    let overlapping_inline = dpop_plugin_with_providers(
        json!([dpop_provider(&jwks), dpop_provider(&other_keys)]),
        "dpop-identity-inline",
    );
    let markers = overlapping_inline.dpop_replay_domain_markers("thumbprint", "proof-id");
    assert_eq!(
        markers[0], markers[1],
        "different inline key sets with the same issuer must share a replay realm"
    );

    // Different remote sources under one issuer also share a realm.
    let remote = |uri: &str, issuer: &str| {
        json!({
            "jwks_uri": uri,
            "issuer": issuer,
            "require_dpop": true,
            "dpop_replay_scope": "process"
        })
    };
    let overlapping_sources = dpop_plugin_with_providers(
        json!([
            remote("https://a.example.com/jwks", "https://idp.example.com"),
            remote("https://b.example.com/jwks", "https://idp.example.com"),
        ]),
        "dpop-identity-source",
    );
    let markers = overlapping_sources.dpop_replay_domain_markers("thumbprint", "proof-id");
    assert_eq!(
        markers[0], markers[1],
        "different JWKS URIs with the same issuer must share a replay realm"
    );

    // Same remote source, different issuers: isolated.
    let distinct_issuers = dpop_plugin_with_providers(
        json!([
            remote("https://idp.example.com/jwks", "https://a.example.com"),
            remote("https://idp.example.com/jwks", "https://b.example.com"),
        ]),
        "dpop-identity-issuer",
    );
    let markers = distinct_issuers.dpop_replay_domain_markers("thumbprint", "proof-id");
    assert_ne!(
        markers[0], markers[1],
        "different exact issuers must stay isolated"
    );

    // Inline JWKS spelling is not part of the identity.
    let compact = serde_json::to_string(&jwks).expect("inline JWKS serializes");
    let spaced = serde_json::to_string_pretty(&jwks).expect("inline JWKS pretty-prints");
    let canonicalized = dpop_plugin_with_providers(
        json!([
            dpop_provider(&json!(compact)),
            dpop_provider(&json!(spaced)),
        ]),
        "dpop-identity-canonical",
    );
    let markers = canonicalized.dpop_replay_domain_markers("thumbprint", "proof-id");
    assert_eq!(
        markers[0], markers[1],
        "inline JWKS spelling must not open a fresh replay lane"
    );
}

/// Distinct JWKS or discovery URLs with the same exact issuer share one replay
/// realm. Issuer matching remains exact: host-case on `issuer` is not
/// normalized.
#[test]
fn dpop_same_issuer_sources_share_a_realm_and_issuer_matching_stays_exact() {
    let remote = |uri: &str, issuer: &str| {
        json!({
            "jwks_uri": uri,
            "issuer": issuer,
            "require_dpop": true,
            "dpop_replay_scope": "process"
        })
    };
    let discovery = |url: &str, issuer: &str| {
        json!({
            "discovery_url": url,
            "issuer": issuer,
            "require_dpop": true,
            "dpop_replay_scope": "process"
        })
    };
    let issuer = "https://idp.example.com";

    let equivalent_jwks = dpop_plugin_with_providers(
        json!([
            remote("https://idp.example.com/jwks", issuer),
            remote("https://IDP.EXAMPLE.COM/jwks", issuer),
            remote("https://idp.example.com:443/jwks", issuer),
        ]),
        "dpop-identity-url-jwks",
    );
    let markers = equivalent_jwks.dpop_replay_domain_markers("thumbprint", "proof-id");
    assert_eq!(markers.len(), 3);
    assert_eq!(markers[0], markers[1]);
    assert_eq!(markers[0], markers[2]);

    let equivalent_discovery = dpop_plugin_with_providers(
        json!([
            discovery(
                "https://idp.example.com/.well-known/openid-configuration",
                issuer
            ),
            discovery(
                "https://IDP.EXAMPLE.COM/.well-known/openid-configuration",
                issuer
            ),
            discovery("http://127.0.0.1/.well-known/openid-configuration", issuer),
            discovery(
                "http://127.0.0.1:80/.well-known/openid-configuration",
                issuer
            ),
        ]),
        "dpop-identity-url-discovery",
    );
    let markers = equivalent_discovery.dpop_replay_domain_markers("thumbprint", "proof-id");
    assert_eq!(markers[0], markers[1]);
    assert_eq!(markers[2], markers[3]);

    // Distinct endpoints with the same issuer still share one realm.
    let overlapping = dpop_plugin_with_providers(
        json!([
            remote("https://idp.example.com/jwks", issuer),
            remote("https://idp.example.com:444/jwks", issuer),
            remote("https://idp.example.com/other", issuer),
            remote("https://other.example.com/jwks", issuer),
            remote("https://idp.example.com/jwks?kid=a", issuer),
        ]),
        "dpop-identity-url-overlap",
    );
    let markers = overlapping.dpop_replay_domain_markers("thumbprint", "proof-id");
    for (left, right) in [(0, 1), (0, 2), (0, 3), (0, 4), (1, 2), (1, 3), (2, 3)] {
        assert_eq!(
            markers[left], markers[right],
            "same-issuer remote sources must share a replay realm ({left} vs {right})"
        );
    }

    // Issuer matching stays exact: URL-like host-case on issuer is not a
    // canonicalization of the realm.
    let issuer_exact = dpop_plugin_with_providers(
        json!([
            remote("https://idp.example.com/jwks", "https://idp.example.com"),
            remote("https://idp.example.com/jwks", "https://IDP.EXAMPLE.COM"),
        ]),
        "dpop-identity-issuer-exact",
    );
    let markers = issuer_exact.dpop_replay_domain_markers("thumbprint", "proof-id");
    assert_ne!(
        markers[0], markers[1],
        "issuer matching remains exact; host-case on issuer must not converge"
    );
}

/// Filling a provider's replay lane, then reloading with a *lower* cap, must
/// refuse new proofs at the new cap while every previously admitted marker
/// stays a replay.
#[tokio::test]
async fn dpop_capacity_decrease_across_equivalent_generations_preserves_live_markers() {
    let (retained_a, jwks) = build_dpop_fixture("dpop-cap-dec-a");
    let (retained_b, _) = build_dpop_fixture("dpop-cap-dec-b");
    let (fresh, _) = build_dpop_fixture("dpop-cap-dec-fresh");
    let consumer_index = ConsumerIndex::new(&[create_consumer("idp-user")]);

    let mut high = dpop_provider(&jwks);
    high["dpop_replay_max_entries"] = json!(2);
    let original = dpop_plugin_with_providers(json!([high]), "dpop-cap-decrease");
    assert_eq!(original.dpop_replay_lane_capacities(), vec![Some(2)]);

    let mut first = dpop_ctx(&retained_a);
    assert_continue(original.authenticate(&mut first, &consumer_index).await);
    let mut second = dpop_ctx(&retained_b);
    assert_continue(original.authenticate(&mut second, &consumer_index).await);
    drop(original);

    let mut low = dpop_provider(&jwks);
    low["dpop_replay_max_entries"] = json!(1);
    let lowered = dpop_plugin_with_providers(json!([low]), "dpop-cap-decrease");
    assert_eq!(lowered.dpop_replay_lane_capacities(), vec![Some(1)]);

    let mut replay_a = dpop_ctx(&retained_a);
    assert_reject(
        lowered.authenticate(&mut replay_a, &consumer_index).await,
        Some(401),
    );
    let mut replay_b = dpop_ctx(&retained_b);
    assert_reject(
        lowered.authenticate(&mut replay_b, &consumer_index).await,
        Some(401),
    );
    let mut new_proof = dpop_ctx(&fresh);
    assert_reject(
        lowered.authenticate(&mut new_proof, &consumer_index).await,
        Some(503),
    );
}

/// Reloading with a *higher* cap must restore headroom on the same lane
/// without reopening an already-claimed proof.
#[tokio::test]
async fn dpop_capacity_increase_across_equivalent_generations_restores_headroom() {
    let (retained, jwks) = build_dpop_fixture("dpop-cap-inc-retained");
    let (fresh, _) = build_dpop_fixture("dpop-cap-inc-fresh");
    let consumer_index = ConsumerIndex::new(&[create_consumer("idp-user")]);

    let mut low = dpop_provider(&jwks);
    low["dpop_replay_max_entries"] = json!(1);
    let original = dpop_plugin_with_providers(json!([low]), "dpop-cap-increase");
    let mut first = dpop_ctx(&retained);
    assert_continue(original.authenticate(&mut first, &consumer_index).await);
    let mut blocked = dpop_ctx(&fresh);
    assert_reject(
        original.authenticate(&mut blocked, &consumer_index).await,
        Some(503),
    );
    drop(original);

    let mut high = dpop_provider(&jwks);
    high["dpop_replay_max_entries"] = json!(2);
    let raised = dpop_plugin_with_providers(json!([high]), "dpop-cap-increase");
    assert_eq!(raised.dpop_replay_lane_capacities(), vec![Some(2)]);

    let mut replay = dpop_ctx(&retained);
    assert_reject(
        raised.authenticate(&mut replay, &consumer_index).await,
        Some(401),
    );
    let mut new_proof = dpop_ctx(&fresh);
    assert_continue(raised.authenticate(&mut new_proof, &consumer_index).await);
}

/// Duplicate equivalent providers with incompatible capacities cannot share a
/// deterministic process-lane contract: matching order would pick which cap
/// applies. Admission must refuse that configuration in either order.
#[test]
fn duplicate_equivalent_providers_with_incompatible_capacities_are_rejected() {
    let (_, jwks) = build_dpop_fixture("dpop-cap-dup-reject");
    let mut low = dpop_provider(&jwks);
    low["dpop_replay_max_entries"] = json!(1);
    let mut high = dpop_provider(&jwks);
    high["dpop_replay_max_entries"] = json!(2);

    for providers in [json!([low.clone(), high.clone()]), json!([high, low])] {
        let error = JwksAuth::new_with_config_id(
            &json!({ "providers": providers }),
            default_client(),
            Some("dpop-cap-dup-reject"),
        )
        .map(|_| ())
        .expect_err("incompatible duplicate capacities must be refused");
        assert!(
            error.contains("dpop_replay_max_entries") && error.contains("incompatible"),
            "diagnostic should name the disagreeing cap: {error}"
        );
    }
}

/// Duplicate equivalent providers that agree on capacity stay admitted and
/// still share one lane, so a duplicated entry cannot launder a second
/// acceptance. Explicit matching caps must not be mistaken for the
/// incompatible-cap refusal.
#[tokio::test]
async fn duplicate_equivalent_providers_with_matching_capacity_share_one_lane() {
    let (fixture, jwks) = build_dpop_fixture("dpop-cap-dup-match");
    let consumer_index = ConsumerIndex::new(&[create_consumer("idp-user")]);
    let mut provider = dpop_provider(&jwks);
    provider["dpop_replay_max_entries"] = json!(8);

    let duplicated =
        dpop_plugin_with_providers(json!([provider.clone(), provider]), "dpop-cap-dup-match");
    assert_eq!(
        duplicated.dpop_replay_lane_capacities(),
        vec![Some(8), Some(8)]
    );
    let markers = duplicated.dpop_replay_domain_markers("thumbprint", "proof-id");
    assert_eq!(markers[0], markers[1]);

    let mut first = dpop_ctx(&fixture);
    assert_continue(duplicated.authenticate(&mut first, &consumer_index).await);
    let mut replay = dpop_ctx(&fixture);
    assert_reject(
        duplicated.authenticate(&mut replay, &consumer_index).await,
        Some(401),
    );
}

/// Equivalent remote URL spellings that share one exact issuer are still one
/// replay realm, so the incompatible-cap admission rule applies to them too —
/// otherwise a host-case duplicate could smuggle a second cap.
#[test]
fn equivalent_remote_url_spellings_with_incompatible_capacities_are_rejected() {
    let error = JwksAuth::new_with_config_id(
        &json!({
            "providers": [
                {
                    "jwks_uri": "https://idp.example.com/jwks",
                    "issuer": "https://idp.example.com",
                    "require_dpop": true,
                    "dpop_replay_scope": "process",
                    "dpop_replay_max_entries": 1
                },
                {
                    "jwks_uri": "https://IDP.EXAMPLE.COM:443/jwks",
                    "issuer": "https://idp.example.com",
                    "require_dpop": true,
                    "dpop_replay_scope": "process",
                    "dpop_replay_max_entries": 8
                }
            ]
        }),
        default_client(),
        Some("dpop-cap-url-dup"),
    )
    .map(|_| ())
    .expect_err("canonical URL duplicates with different caps must be refused");
    assert!(
        error.contains("dpop_replay_max_entries"),
        "diagnostic should name the disagreeing cap: {error}"
    );
}

/// Mixed process/shared scopes on the same semantic DPoP provider split the
/// proof across two stores: the process lane and Redis. Matching order, a
/// reload, or a rolling replica would then accept the same proof twice.
/// Admission must refuse that configuration in either order, including when
/// Redis is configured so the failure cannot be blamed on a missing backend.
#[test]
fn equivalent_dpop_providers_with_mixed_process_and_shared_scopes_are_rejected() {
    let (_, jwks) = build_dpop_fixture("dpop-scope-mix-reject");
    let process = dpop_provider(&jwks);
    let shared = dpop_shared_provider(&jwks);

    for providers in [
        json!([process.clone(), shared.clone()]),
        json!([shared, process]),
    ] {
        let error = jwks_with_redis(providers, "dpop-scope-mix-reject")
            .map(|_| ())
            .expect_err(
                "mixed process/shared equivalent DPoP providers must be refused \
                 even when Redis is configured",
            );
        assert!(
            error.contains("dpop_replay_scope") && error.contains("incompatible"),
            "diagnostic should name the disagreeing replay authority: {error}"
        );
        assert!(
            !error.contains("requires sync_mode"),
            "refusal must be the equivalent-authority contract, not missing Redis: {error}"
        );
    }
}

/// Canonical remote URL spellings are one trust source, so mixing process and
/// shared on them is the same split-authority hole as a verbatim duplicate.
#[test]
fn equivalent_remote_url_spellings_with_mixed_replay_scopes_are_rejected() {
    for providers in [
        json!([
            {
                "jwks_uri": "https://idp.example.com/jwks",
                "issuer": "https://idp.example.com",
                "require_dpop": true,
                "dpop_replay_scope": "process"
            },
            {
                "jwks_uri": "https://IDP.EXAMPLE.COM:443/jwks",
                "issuer": "https://idp.example.com",
                "require_dpop": true,
                "dpop_replay_scope": "shared"
            }
        ]),
        json!([
            {
                "jwks_uri": "https://IDP.EXAMPLE.COM:443/jwks",
                "issuer": "https://idp.example.com",
                "require_dpop": true,
                "dpop_replay_scope": "shared"
            },
            {
                "jwks_uri": "https://idp.example.com/jwks",
                "issuer": "https://idp.example.com",
                "require_dpop": true,
                "dpop_replay_scope": "process"
            }
        ]),
    ] {
        let error = jwks_with_redis(providers, "dpop-scope-url-mix")
            .map(|_| ())
            .expect_err("canonical URL duplicates with mixed replay scopes must be refused");
        assert!(
            error.contains("dpop_replay_scope") && error.contains("incompatible"),
            "diagnostic should name the disagreeing replay authority: {error}"
        );
    }
}

/// Distinct trust anchors may declare different replay scopes in one plugin:
/// they do not share a domain, so they cannot launder one proof across stores.
/// Redis is required only because one of them is `shared`.
#[test]
fn distinct_dpop_providers_may_mix_process_and_shared_scopes_when_redis_is_configured() {
    let (_, jwks) = build_dpop_fixture("dpop-scope-mix-distinct");
    let mut process = dpop_provider(&jwks);
    process["issuer"] = json!("https://a.example.com");
    let mut shared = dpop_shared_provider(&jwks);
    shared["issuer"] = json!("https://b.example.com");

    for providers in [
        json!([process.clone(), shared.clone()]),
        json!([shared.clone(), process.clone()]),
    ] {
        let plugin = jwks_with_redis(providers, "dpop-scope-mix-distinct")
            .expect("distinct issuer realms may disagree on replay scope");
        let markers = plugin.dpop_replay_domain_markers("thumbprint", "proof-id");
        assert_ne!(
            markers[0], markers[1],
            "distinct issuer realms must not share a replay domain"
        );
        let modes = plugin.dpop_replay_modes();
        assert!(
            modes.contains(&Some("process")) && modes.contains(&Some("shared")),
            "distinct issuers keep the scope each declared: {modes:?}"
        );
    }
}

/// Equivalent shared providers still converge on one shared authority in either
/// order. Reorder therefore cannot move the domain onto a process store.
#[test]
fn equivalent_shared_dpop_providers_converge_on_one_shared_authority() {
    let (_, jwks) = build_dpop_fixture("dpop-shared-dup");
    let shared = dpop_shared_provider(&jwks);

    for providers in [
        json!([shared.clone(), shared.clone()]),
        json!([shared.clone(), dpop_shared_provider(&jwks)]),
    ] {
        let plugin = jwks_with_redis(providers, "dpop-shared-dup")
            .expect("equivalent shared providers with Redis must be admitted");
        let markers = plugin.dpop_replay_domain_markers("thumbprint", "proof-id");
        assert_eq!(markers[0], markers[1]);
        assert_eq!(
            plugin.dpop_replay_modes(),
            vec![Some("shared"), Some("shared")]
        );
    }
}

/// A token that verifies against both siblings is matched to the first success.
/// If one sibling requires DPoP and the other does not, matching order is an
/// authentication bypass of the single-use proof. Fail closed on that
/// ambiguous pair; distinct trust anchors may still disagree.
#[test]
fn equivalent_providers_that_disagree_on_require_dpop_are_rejected() {
    let (_, jwks) = build_dpop_fixture("dpop-require-mix-reject");
    let with_dpop = dpop_provider(&jwks);
    let without_dpop = json!({ "jwks": jwks, "issuer": DPOP_TEST_ISSUER });

    for providers in [
        json!([with_dpop.clone(), without_dpop.clone()]),
        json!([without_dpop.clone(), with_dpop.clone()]),
    ] {
        let error = JwksAuth::new_with_config_id(
            &json!({ "providers": providers }),
            default_client(),
            Some("dpop-require-mix-reject"),
        )
        .map(|_| ())
        .expect_err("equivalent providers must agree on require_dpop");
        assert!(
            error.contains("require_dpop") && error.contains("incompatible"),
            "diagnostic should name the disagreeing DPoP requirement: {error}"
        );
    }

    // The same hole with a configured Redis backend and a `shared` DPoP
    // sibling: refusal must not be attributable to scope/backend admission.
    let shared = dpop_shared_provider(&jwks);
    for providers in [
        json!([shared.clone(), without_dpop.clone()]),
        json!([without_dpop, shared]),
    ] {
        let error = jwks_with_redis(providers, "dpop-require-mix-redis")
            .map(|_| ())
            .expect_err(
                "equivalent require_dpop disagreement must be refused with Redis configured",
            );
        assert!(
            error.contains("require_dpop") && error.contains("incompatible"),
            "diagnostic should name the disagreeing DPoP requirement: {error}"
        );
    }
}

/// Equivalent providers with matching authorization fields still converge on
/// one replay lane; disagreement on those fields is refused separately.
#[test]
fn equivalent_providers_with_matching_authorization_fields_converge_on_one_replay_lane() {
    let (_, jwks) = build_dpop_fixture("dpop-auth-fields-converge");
    let provider = json!({
        "jwks": jwks,
        "issuer": DPOP_TEST_ISSUER,
        "require_dpop": true,
        "dpop_replay_scope": "process",
        "require_mtls_binding": true,
        "required_scopes": ["read:data"],
        "required_roles": ["admin"],
    });

    let plugin = dpop_plugin_with_providers(
        json!([provider.clone(), provider]),
        "dpop-auth-fields-converge",
    );
    let markers = plugin.dpop_replay_domain_markers("thumbprint", "proof-id");
    assert_eq!(
        markers[0], markers[1],
        "equivalent providers with matching authorization fields must share one replay lane"
    );
}

/// A token that verifies against both siblings is matched to the first success.
/// If one sibling requires certificate binding and the other does not, matching
/// order is an authentication bypass of the RFC 8705 gate.
#[test]
fn equivalent_providers_that_disagree_on_require_mtls_binding_are_rejected() {
    let (_, jwks) = build_dpop_fixture("mtls-binding-mix-reject");
    let with_binding = json!({
        "jwks": jwks,
        "issuer": DPOP_TEST_ISSUER,
        "require_mtls_binding": true,
    });
    let without_binding = json!({ "jwks": jwks, "issuer": DPOP_TEST_ISSUER });

    for providers in [
        json!([with_binding.clone(), without_binding.clone()]),
        json!([without_binding.clone(), with_binding.clone()]),
    ] {
        let error = JwksAuth::new_with_config_id(
            &json!({ "providers": providers }),
            default_client(),
            Some("mtls-binding-mix-reject"),
        )
        .map(|_| ())
        .expect_err("equivalent providers must agree on require_mtls_binding");
        assert!(
            error.contains("require_mtls_binding") && error.contains("incompatible"),
            "diagnostic should name the disagreeing certificate-binding requirement: {error}"
        );
    }
}

/// Matching order would otherwise let a permissive sibling satisfy a token that
/// lacks scopes the stricter sibling demands.
#[test]
fn equivalent_providers_that_disagree_on_required_scopes_are_rejected() {
    let (_, jwks) = build_dpop_fixture("required-scopes-mix-reject");
    let strict = json!({
        "jwks": jwks,
        "issuer": DPOP_TEST_ISSUER,
        "required_scopes": ["read:data", "write:data"],
    });
    let permissive = json!({
        "jwks": jwks,
        "issuer": DPOP_TEST_ISSUER,
        "required_scopes": ["read:data"],
    });

    for providers in [
        json!([strict.clone(), permissive.clone()]),
        json!([permissive.clone(), strict.clone()]),
    ] {
        let error = JwksAuth::new_with_config_id(
            &json!({ "providers": providers }),
            default_client(),
            Some("required-scopes-mix-reject"),
        )
        .map(|_| ())
        .expect_err("equivalent providers must agree on required_scopes");
        assert!(
            error.contains("required_scopes") && error.contains("incompatible"),
            "diagnostic should name the disagreeing scope requirement: {error}"
        );
    }
}

/// Matching order would otherwise let a permissive sibling satisfy a token that
/// lacks roles the stricter sibling demands.
#[test]
fn equivalent_providers_that_disagree_on_required_roles_are_rejected() {
    let (_, jwks) = build_dpop_fixture("required-roles-mix-reject");
    let strict = json!({
        "jwks": jwks,
        "issuer": DPOP_TEST_ISSUER,
        "required_roles": ["admin", "operator"],
    });
    let permissive = json!({
        "jwks": jwks,
        "issuer": DPOP_TEST_ISSUER,
        "required_roles": ["admin"],
    });

    for providers in [
        json!([strict.clone(), permissive.clone()]),
        json!([permissive.clone(), strict.clone()]),
    ] {
        let error = JwksAuth::new_with_config_id(
            &json!({ "providers": providers }),
            default_client(),
            Some("required-roles-mix-reject"),
        )
        .map(|_| ())
        .expect_err("equivalent providers must agree on required_roles");
        assert!(
            error.contains("required_roles") && error.contains("incompatible"),
            "diagnostic should name the disagreeing role requirement: {error}"
        );
    }
}

/// Distinct issuers are different replay realms. One may require DPoP and the
/// other may not; a token matching only one of them is not an ambiguous DPoP
/// bypass. A non-DPoP sibling without an issuer is also not the same realm.
#[test]
fn non_equivalent_providers_may_disagree_on_require_dpop() {
    let distinct_issuers = JwksAuth::new(
        &json!({
            "providers": [
                {
                    "jwks_uri": "https://idp.example.com/jwks",
                    "issuer": "https://a.example.com",
                    "require_dpop": true,
                    "dpop_replay_scope": "process"
                },
                {
                    "jwks_uri": "https://idp.example.com/jwks",
                    "issuer": "https://b.example.com"
                }
            ]
        }),
        default_client(),
    )
    .expect("distinct issuers may disagree on require_dpop");
    assert_eq!(
        distinct_issuers.dpop_replay_modes(),
        vec![Some("process"), None]
    );

    let (_, jwks) = build_dpop_fixture("dpop-require-mix-distinct");
    let mut other_keys = jwks.clone();
    other_keys["keys"][0]["kid"] = json!("a-different-key-id");
    let distinct_keys = dpop_plugin_with_providers(
        json!([dpop_provider(&jwks), json!({ "jwks": other_keys })]),
        "dpop-require-mix-distinct",
    );
    assert_eq!(
        distinct_keys.dpop_replay_modes(),
        vec![Some("process"), None]
    );
}

/// A claimed process-scoped proof must stay a replay across equivalent reorder
/// and cannot be reopened by a rolling generation that would move the same
/// domain onto a shared Redis authority. Mixed process/shared equivalent
/// configs are refused, so that rolling shape cannot be admitted.
#[tokio::test]
async fn claimed_dpop_proof_cannot_move_across_replay_authorities_on_reorder_or_reload() {
    let (fixture, jwks) = build_dpop_fixture("dpop-authority-move");
    let consumer_index = ConsumerIndex::new(&[create_consumer("idp-user")]);

    let original = dpop_plugin_with_providers(json!([dpop_provider(&jwks)]), "dpop-authority-move");
    let mut first = dpop_ctx(&fixture);
    assert_continue(original.authenticate(&mut first, &consumer_index).await);

    let process = dpop_provider(&jwks);
    let shared = dpop_shared_provider(&jwks);
    for providers in [
        json!([process.clone(), shared.clone()]),
        json!([shared, process.clone()]),
    ] {
        jwks_with_redis(providers, "dpop-authority-move")
            .map(|_| ())
            .expect_err(
                "a rolling generation must not be able to split one domain across authorities",
            );
    }

    let reordered = dpop_plugin_with_providers(
        json!([dpop_provider(&jwks), dpop_decoy_provider()]),
        "dpop-authority-move",
    );
    assert_eq!(
        original.dpop_replay_domain_markers("thumbprint", "proof-id")[0],
        reordered.dpop_replay_domain_markers("thumbprint", "proof-id")[0],
        "equivalent reorder must keep the claimed domain on the same authority"
    );
    assert_eq!(reordered.dpop_replay_modes()[0], Some("process"));
    let mut replay = dpop_ctx(&fixture);
    assert_reject(
        reordered.authenticate(&mut replay, &consumer_index).await,
        Some(401),
    );
}

/// The removed retention/capacity knobs are rejected with their replacement
/// named, rather than silently ignored — a config still carrying
/// `dpop_jti_ttl_secs` was written believing it controls how long a proof stays
/// single-use.
#[test]
fn removed_dpop_replay_knobs_are_rejected_with_guidance() {
    for (removed, expected) in [
        ("dpop_jti_ttl_secs", "fixed horizon"),
        ("dpop_jti_cache_max_entries", "dpop_replay_max_entries"),
    ] {
        let mut provider = json!({
            "jwks": {"keys": []},
            "require_dpop": true,
            "dpop_replay_scope": "process"
        });
        provider[removed] = json!(300);
        let error = JwksAuth::new(&json!({"providers": [provider]}), default_client())
            .map(|_| ())
            .expect_err("a removed replay knob must be rejected");
        assert!(
            error.contains(removed) && error.contains(expected),
            "diagnostic should name the removal and its replacement: {error}"
        );
    }
}

// ─── Unknown-`kid` on-demand refetch (issue #4508) ──────────────────────────

/// An identity provider that rotates its signing key: the first fetch serves
/// v1, every later fetch serves v2.
async fn rotating_jwks_endpoint() -> (wiremock::MockServer, String) {
    let server = wiremock::MockServer::start().await;
    let jwks_path = unique_jwks_path("rotating-jwks");
    wiremock::Mock::given(wiremock::matchers::method("GET"))
        .and(wiremock::matchers::path(jwks_path.clone()))
        .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(
            build_rsa_jwks_from_pem_with_kid(
                include_bytes!("../../../tests/fixtures/test_rsa_public.pem"),
                "key-v1",
            ),
        ))
        .up_to_n_times(1)
        .with_priority(1)
        .mount(&server)
        .await;
    wiremock::Mock::given(wiremock::matchers::method("GET"))
        .and(wiremock::matchers::path(jwks_path.clone()))
        .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(
            build_rsa_jwks_from_pem_with_kid(
                include_bytes!("../../../tests/fixtures/test_rsa_public_other.pem"),
                "key-v2",
            ),
        ))
        .with_priority(2)
        .mount(&server)
        .await;
    let jwks_uri = format!("{}{}", server.uri(), jwks_path);
    (server, jwks_uri)
}

fn bearer_ctx(token: &str) -> RequestContext {
    let mut ctx = make_ctx();
    ctx.headers
        .insert("authorization".to_string(), format!("Bearer {token}"));
    ctx
}

/// End-to-end key rotation: the token minted with the new `kid` is rejected
/// once — the gateway never blocks a request on a fetch — and verifies on a
/// later attempt, with the refresh interval set to an hour so only the
/// on-demand path can explain the recovery.
#[serial_test::serial(jwks_remote_global_cache)]
#[tokio::test]
async fn rotated_signing_key_verifies_without_waiting_out_the_refresh_interval() {
    let _cache_guard = super::jwks_cache_tests::cache_test_lock().lock().await;
    let (server, jwks_uri) = rotating_jwks_endpoint().await;
    let plugin = JwksAuth::new(
        &json!({
            "providers": [{"jwks_uri": jwks_uri}],
            "jwks_refresh_interval_secs": 3600,
            "kid_miss_refresh_cooldown_seconds": 30
        }),
        default_client(),
    )
    .unwrap();
    start_background_tasks(&plugin);
    wait_for_received_request_count(&server, 1).await;

    let store = plugin
        .remote_jwks_stores_for_test()
        .first()
        .cloned()
        .expect("remote provider store");
    let consumer_index = ConsumerIndex::new(&[]);
    let token = create_rs256_token_with_kid(
        &json!({"sub": "user"}),
        include_bytes!("../../../tests/fixtures/test_rsa_private_other.pem"),
        "key-v2",
    );

    let before = store.refresh_completions();
    let mut first = bearer_ctx(&token);
    assert_reject(
        plugin.authenticate(&mut first, &consumer_index).await,
        Some(401),
    );
    assert_eq!(
        store.kid_miss_refresh_requests(),
        1,
        "the unknown kid must have asked for exactly one out-of-band refresh"
    );

    store.wait_for_refresh_completion_after(before).await;

    let mut second = bearer_ctx(&token);
    assert_continue(plugin.authenticate(&mut second, &consumer_index).await);
    assert_eq!(
        second.authenticated_identity.as_deref(),
        Some("user"),
        "the rotated key must verify on the next request"
    );
}

/// Tokens with no `kid`, and with an empty `kid`, name no rotation and must
/// never cost an upstream fetch.
#[serial_test::serial(jwks_remote_global_cache)]
#[tokio::test]
async fn tokens_without_a_kid_never_trigger_an_on_demand_refetch() {
    let _cache_guard = super::jwks_cache_tests::cache_test_lock().lock().await;
    let (server, jwks_uri) = rotating_jwks_endpoint().await;
    let plugin = JwksAuth::new(
        &json!({
            "providers": [{"jwks_uri": jwks_uri}],
            "jwks_refresh_interval_secs": 3600
        }),
        default_client(),
    )
    .unwrap();
    start_background_tasks(&plugin);
    let after_startup = wait_for_received_request_count(&server, 1).await;

    let store = plugin
        .remote_jwks_stores_for_test()
        .first()
        .cloned()
        .expect("remote provider store");
    let consumer_index = ConsumerIndex::new(&[]);
    let private_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_private.pem");
    let no_kid = create_rs256_token_no_kid(&json!({"sub": "user"}), private_key_pem);
    let empty_kid = create_rs256_token_with_kid(&json!({"sub": "user"}), private_key_pem, "");

    for token in [no_kid, empty_kid] {
        let mut ctx = bearer_ctx(&token);
        assert_reject(
            plugin.authenticate(&mut ctx, &consumer_index).await,
            Some(401),
        );
    }
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    assert_eq!(store.kid_miss_refresh_requests(), 0);
    assert_eq!(
        server
            .received_requests()
            .await
            .map(|requests| requests.len())
            .unwrap_or(0),
        after_startup,
        "a token with no key identifier must cost no upstream fetch"
    );
}

/// The cooldown is a plugin field: default, explicit, disabled, and bounded.
#[tokio::test]
async fn kid_miss_refresh_cooldown_is_validated_and_defaults_to_thirty_seconds() {
    let with_cooldown = |value: Option<u64>| {
        let mut config = json!({"providers": [{"jwks_uri": "https://keys.example.com/jwks"}]});
        if let Some(value) = value {
            config["kid_miss_refresh_cooldown_seconds"] = json!(value);
        }
        config
    };

    let default_cooldown = JwksAuth::new(&with_cooldown(None), default_client())
        .expect("default config")
        .remote_jwks_stores_for_test()
        .first()
        .cloned()
        .expect("remote store")
        .kid_miss_cooldown();
    assert_eq!(
        default_cooldown,
        std::time::Duration::from_secs(DEFAULT_KID_MISS_REFRESH_COOLDOWN_SECONDS)
    );

    for (configured, expected) in [
        (0u64, 0u64),
        (5, 5),
        (
            MAX_KID_MISS_REFRESH_COOLDOWN_SECONDS,
            MAX_KID_MISS_REFRESH_COOLDOWN_SECONDS,
        ),
    ] {
        let cooldown = JwksAuth::new(&with_cooldown(Some(configured)), default_client())
            .expect("valid cooldown")
            .remote_jwks_stores_for_test()
            .first()
            .cloned()
            .expect("remote store")
            .kid_miss_cooldown();
        assert_eq!(cooldown, std::time::Duration::from_secs(expected));
    }

    let error = JwksAuth::new(
        &with_cooldown(Some(MAX_KID_MISS_REFRESH_COOLDOWN_SECONDS + 1)),
        default_client(),
    )
    .err()
    .expect("out-of-range cooldown must fail");
    assert!(error.contains("kid_miss_refresh_cooldown_seconds"));

    let unknown_key = JwksAuth::new(
        &json!({
            "providers": [{"jwks_uri": "https://keys.example.com/jwks"}],
            "kid_miss_refresh_cooldown": 30
        }),
        default_client(),
    )
    .err()
    .expect("closed plugin config must reject a misspelled key");
    assert!(unknown_key.contains("kid_miss_refresh_cooldown"));
}

// ────────────────────────────────────────────────────────────────────
// Issue #5017 — RFC 9449 §7.1 `Authorization: DPoP <token>` presentation
// ────────────────────────────────────────────────────────────────────

/// The RFC 9449 §7.1 presentation form: the access token under the `DPoP`
/// scheme beside the proof header.
fn dpop_scheme_ctx(fixture: &DpopFixture) -> RequestContext {
    let mut ctx = make_ctx();
    ctx.headers.insert(
        "authorization".to_string(),
        format!("DPoP {}", fixture.access_token),
    );
    ctx.headers
        .insert("dpop".to_string(), fixture.proof.clone());
    ctx.headers
        .insert("host".to_string(), "example.com".to_string());
    ctx.metadata
        .insert("ferrum.frontend_scheme".to_string(), "http".to_string());
    ctx
}

#[tokio::test]
async fn dpop_authorization_scheme_authenticates_with_a_valid_proof() {
    let (fixture, jwks) = build_dpop_fixture("dpop-scheme-valid");
    let plugin = dpop_plugin(&jwks, "dpop-scheme-valid");
    let consumer_index = ConsumerIndex::new(&[create_consumer("idp-user")]);

    let mut ctx = dpop_scheme_ctx(&fixture);
    assert_continue(plugin.authenticate(&mut ctx, &consumer_index).await);
    assert_eq!(ctx.authenticated_identity.as_deref(), Some("idp-user"));
}

#[tokio::test]
async fn dpop_authorization_scheme_rejects_an_invalid_proof() {
    let (fixture, jwks) = build_dpop_fixture("dpop-scheme-invalid");
    let plugin = dpop_plugin(&jwks, "dpop-scheme-invalid");
    let consumer_index = ConsumerIndex::new(&[create_consumer("idp-user")]);

    let mut ctx = dpop_scheme_ctx(&fixture);
    ctx.headers
        .insert("dpop".to_string(), "not-a-proof".to_string());
    assert_reject(
        plugin.authenticate(&mut ctx, &consumer_index).await,
        Some(401),
    );
}

#[tokio::test]
async fn dpop_authorization_scheme_rejects_a_replayed_proof() {
    let (fixture, jwks) = build_dpop_fixture("dpop-scheme-replay");
    let plugin = dpop_plugin(&jwks, "dpop-scheme-replay");
    let consumer_index = ConsumerIndex::new(&[create_consumer("idp-user")]);

    let mut first = dpop_scheme_ctx(&fixture);
    assert_continue(plugin.authenticate(&mut first, &consumer_index).await);

    let mut replay = dpop_scheme_ctx(&fixture);
    assert_reject(
        plugin.authenticate(&mut replay, &consumer_index).await,
        Some(401),
    );
}

/// A `DPoP`-scheme presentation announces a sender-constrained token. A plugin
/// whose providers validate no proof must keep treating the scheme as foreign,
/// otherwise the binding the scheme announces is silently dropped.
#[tokio::test]
async fn dpop_authorization_scheme_is_not_accepted_by_a_bearer_only_provider() {
    let (fixture, jwks) = build_dpop_fixture("dpop-scheme-bearer-only");
    let plugin = JwksAuth::new_with_config_id(
        &json!({
            "providers": [{"jwks": jwks, "issuer": DPOP_TEST_ISSUER}]
        }),
        default_client(),
        Some("dpop-scheme-bearer-only"),
    )
    .expect("bearer-only inline provider");
    let consumer_index = ConsumerIndex::new(&[create_consumer("idp-user")]);

    let mut ctx = dpop_scheme_ctx(&fixture);
    assert_continue(plugin.authenticate(&mut ctx, &consumer_index).await);
    assert!(ctx.identified_consumer.is_none());
    assert!(ctx.authenticated_identity.is_none());
}

/// The migration form RFC 9449 §7.1 permits stays available: `Bearer` plus a
/// `DPoP` proof header still authenticates against a `require_dpop` provider.
#[tokio::test]
async fn bearer_scheme_still_authenticates_a_dpop_provider() {
    let (fixture, jwks) = build_dpop_fixture("dpop-scheme-bearer-migration");
    let plugin = dpop_plugin(&jwks, "dpop-scheme-bearer-migration");
    let consumer_index = ConsumerIndex::new(&[create_consumer("idp-user")]);

    let mut ctx = dpop_ctx(&fixture);
    assert_continue(plugin.authenticate(&mut ctx, &consumer_index).await);
    assert_eq!(ctx.authenticated_identity.as_deref(), Some("idp-user"));
}

#[tokio::test]
async fn dpop_authorization_scheme_with_an_empty_token_rejects() {
    let (_, jwks) = build_dpop_fixture("dpop-scheme-empty");
    let plugin = dpop_plugin(&jwks, "dpop-scheme-empty");
    let consumer_index = ConsumerIndex::new(&[create_consumer("idp-user")]);

    let mut ctx = make_ctx();
    ctx.headers
        .insert("authorization".to_string(), "DPoP   ".to_string());
    assert_reject(
        plugin.authenticate(&mut ctx, &consumer_index).await,
        Some(401),
    );
}

// ────────────────────────────────────────────────────────────────────
// Issue #5018 — RFC 9449 §4.2 defines no `exp` proof claim
// ────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn dpop_proof_without_exp_is_accepted() {
    let now = chrono::Utc::now().timestamp();
    let (fixture, jwks) = build_dpop_fixture_with_times("dpop-no-exp", now, None);
    let plugin = dpop_plugin(&jwks, "dpop-no-exp");
    let consumer_index = ConsumerIndex::new(&[create_consumer("idp-user")]);

    let mut ctx = dpop_ctx(&fixture);
    assert_continue(plugin.authenticate(&mut ctx, &consumer_index).await);
    assert_eq!(ctx.authenticated_identity.as_deref(), Some("idp-user"));
}

/// A client that sends the non-standard claim is still held to it, so a proof
/// can never outlive its own declared expiry.
#[tokio::test]
async fn dpop_proof_with_a_past_exp_is_rejected() {
    let now = chrono::Utc::now().timestamp();
    let (fixture, jwks) = build_dpop_fixture_with_times("dpop-past-exp", now, Some(now - 3_600));
    let plugin = dpop_plugin(&jwks, "dpop-past-exp");
    let consumer_index = ConsumerIndex::new(&[create_consumer("idp-user")]);

    let mut ctx = dpop_ctx(&fixture);
    assert_reject_body(
        plugin.authenticate(&mut ctx, &consumer_index).await,
        r#"{"error":"DPoP validation failed"}"#,
    );
}

/// `iat` ± `dpop_clock_skew_secs` remains the freshness bound with `exp` gone.
#[tokio::test]
async fn dpop_proof_with_iat_outside_the_skew_window_is_rejected() {
    let now = chrono::Utc::now().timestamp();
    let (fixture, jwks) = build_dpop_fixture_with_times("dpop-stale-iat", now - 3_600, None);
    let plugin = dpop_plugin(&jwks, "dpop-stale-iat");
    let consumer_index = ConsumerIndex::new(&[create_consumer("idp-user")]);

    let mut ctx = dpop_ctx(&fixture);
    assert_reject_body(
        plugin.authenticate(&mut ctx, &consumer_index).await,
        r#"{"error":"DPoP validation failed"}"#,
    );
}

#[tokio::test]
async fn dpop_proof_with_a_future_iat_outside_the_skew_window_is_rejected() {
    let now = chrono::Utc::now().timestamp();
    let (fixture, jwks) = build_dpop_fixture_with_times("dpop-future-iat", now + 3_600, None);
    let plugin = dpop_plugin(&jwks, "dpop-future-iat");
    let consumer_index = ConsumerIndex::new(&[create_consumer("idp-user")]);

    let mut ctx = dpop_ctx(&fixture);
    assert_reject_body(
        plugin.authenticate(&mut ctx, &consumer_index).await,
        r#"{"error":"DPoP validation failed"}"#,
    );
}

// ────────────────────────────────────────────────────────────────────
// Equivalent providers must agree on the claim PATH, not only the values
// ────────────────────────────────────────────────────────────────────

#[test]
fn equivalent_providers_reading_required_scopes_from_different_claims_are_rejected() {
    let public_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_public.pem");
    let jwks = build_rsa_jwks_from_pem(public_key_pem);
    let error = JwksAuth::new(
        &json!({
            "providers": [
                {
                    "jwks": jwks,
                    "issuer": DPOP_TEST_ISSUER,
                    "required_scopes": ["admin"],
                    "scope_claim": "delegated"
                },
                {
                    "jwks": jwks,
                    "issuer": DPOP_TEST_ISSUER,
                    "required_scopes": ["admin"],
                    "scope_claim": "scope"
                }
            ]
        }),
        default_client(),
    )
    .err()
    .expect("same-issuer siblings reading different scope claims must be refused");
    assert!(error.contains("scope_claim"), "unexpected error: {error}");
}

/// The override must be compared against the RESOLVED path, not the raw
/// `Option`: an omitted override under the default is the same gate as one that
/// spells the default out.
#[test]
fn equivalent_providers_agreeing_on_the_effective_scope_claim_are_admitted() {
    let public_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_public.pem");
    let jwks = build_rsa_jwks_from_pem(public_key_pem);
    JwksAuth::new(
        &json!({
            "providers": [
                {
                    "jwks": jwks,
                    "issuer": DPOP_TEST_ISSUER,
                    "required_scopes": ["admin"],
                    "scope_claim": "scope"
                },
                {
                    "jwks": jwks,
                    "issuer": DPOP_TEST_ISSUER,
                    "required_scopes": ["admin"]
                }
            ]
        }),
        default_client(),
    )
    .expect("an explicit override equal to the default is the same scope gate");
}

#[test]
fn equivalent_providers_reading_required_roles_from_different_claims_are_rejected() {
    let public_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_public.pem");
    let jwks = build_rsa_jwks_from_pem(public_key_pem);
    let error = JwksAuth::new(
        &json!({
            "providers": [
                {
                    "jwks": jwks,
                    "issuer": DPOP_TEST_ISSUER,
                    "required_roles": ["admin"],
                    "role_claim": "realm.roles"
                },
                {
                    "jwks": jwks,
                    "issuer": DPOP_TEST_ISSUER,
                    "required_roles": ["admin"],
                    "role_claim": "roles"
                }
            ]
        }),
        default_client(),
    )
    .err()
    .expect("same-issuer siblings reading different role claims must be refused");
    assert!(error.contains("role_claim"), "unexpected error: {error}");
}

/// With no requirement declared the claim path is inert, so disagreeing on it
/// is not a split gate and must not be refused.
#[test]
fn equivalent_providers_without_requirements_may_differ_on_claim_paths() {
    let public_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_public.pem");
    let jwks = build_rsa_jwks_from_pem(public_key_pem);
    JwksAuth::new(
        &json!({
            "providers": [
                {"jwks": jwks, "issuer": DPOP_TEST_ISSUER, "scope_claim": "delegated"},
                {"jwks": jwks, "issuer": DPOP_TEST_ISSUER, "scope_claim": "scope"}
            ]
        }),
        default_client(),
    )
    .expect("an unused claim path cannot split a gate that is never evaluated");
}

/// The live consequence: a token satisfying only the permissive sibling's claim
/// path must never reach the backend. The configuration that would allow it is
/// refused at construction, so the only reachable shape is the single-gate one.
#[tokio::test]
async fn a_token_satisfying_only_a_permissive_claim_path_is_refused() {
    let private_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_private.pem");
    let public_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_public.pem");
    let jwks = build_rsa_jwks_from_pem(public_key_pem);
    let plugin = JwksAuth::new(
        &json!({
            "providers": [{
                "jwks": jwks,
                "issuer": DPOP_TEST_ISSUER,
                "required_scopes": ["admin"],
                "scope_claim": "scope"
            }]
        }),
        default_client(),
    )
    .expect("single scope gate");

    let token = create_rs256_token(
        &json!({
            "sub": "idp-user",
            "iss": DPOP_TEST_ISSUER,
            "scope": "read",
            "delegated": "admin"
        }),
        private_key_pem,
    );
    let mut ctx = make_ctx();
    ctx.headers
        .insert("authorization".to_string(), format!("Bearer {token}"));
    let consumer_index = ConsumerIndex::new(&[create_consumer("idp-user")]);
    assert_reject(
        plugin.authenticate(&mut ctx, &consumer_index).await,
        Some(403),
    );
}

// ────────────────────────────────────────────────────────────────────
// Issue #5021 — the shared `Insufficient scope` body must be valid JSON
// ────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn insufficient_scope_body_is_valid_json_for_control_characters() {
    let private_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_private.pem");
    let public_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_public.pem");
    let jwks = build_rsa_jwks_from_pem(public_key_pem);
    let required = "admin\nwrite\ttab\"quote\\slash<tag>";
    let plugin = JwksAuth::new(
        &json!({
            "providers": [{
                "jwks": jwks,
                "issuer": DPOP_TEST_ISSUER,
                "required_scopes": [required]
            }]
        }),
        default_client(),
    )
    .expect("control characters inside a required scope are admitted");

    let token = create_rs256_token(
        &json!({"sub": "idp-user", "iss": DPOP_TEST_ISSUER, "scope": "read"}),
        private_key_pem,
    );
    let mut ctx = make_ctx();
    ctx.headers
        .insert("authorization".to_string(), format!("Bearer {token}"));
    let consumer_index = ConsumerIndex::new(&[create_consumer("idp-user")]);

    let PluginResult::Reject {
        status_code, body, ..
    } = plugin.authenticate(&mut ctx, &consumer_index).await
    else {
        panic!("an unsatisfied required scope must reject");
    };
    assert_eq!(status_code, 403);
    let parsed: Value = serde_json::from_str(&body).expect("403 body must parse as JSON");
    assert_eq!(parsed["error"], json!("Insufficient scope"));
    assert_eq!(parsed["required"], json!(required));
    // Angle brackets keep their JSON unicode-escape form so the body stays
    // inert in a browser context, exactly as the previous HTML escaper
    // produced.
    assert!(body.contains("\\u003ctag\\u003e"), "body: {body}");
}
