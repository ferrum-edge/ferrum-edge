use ferrum_edge::plugins::soap_ws_security::SoapWsSecurity;
use ferrum_edge::plugins::{Plugin, PluginResult, RequestContext};
use serde_json::json;
use std::collections::HashMap;

// ── Helper functions ────────────────────────────────────────────────────────

fn make_ctx_with_soap_body(body: &str) -> RequestContext {
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/ws".to_string(),
    );
    ctx.headers
        .insert("content-type".to_string(), "text/xml".to_string());
    ctx.metadata
        .insert("request_body".to_string(), body.to_string());
    ctx
}

fn soap_headers() -> HashMap<String, String> {
    let mut h = HashMap::new();
    h.insert("content-type".to_string(), "text/xml".to_string());
    h
}

fn non_soap_headers() -> HashMap<String, String> {
    let mut h = HashMap::new();
    h.insert("content-type".to_string(), "application/json".to_string());
    h
}

fn make_ctx_non_soap() -> RequestContext {
    RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/api".to_string(),
    )
}

fn timestamp_only_config() -> serde_json::Value {
    json!({
        "timestamp": {
            "require": true,
            "max_age_seconds": 300,
            "clock_skew_seconds": 300
        },
        "reject_missing_security_header": true
    })
}

fn username_token_config() -> serde_json::Value {
    json!({
        "timestamp": { "require": false },
        "username_token": {
            "enabled": true,
            "password_type": "PasswordText",
            "credentials": [
                {"username": "alice", "password": "secret123"},
                {"username": "bob", "password": "bobpass"}
            ]
        },
        "reject_missing_security_header": true
    })
}

fn username_token_digest_config() -> serde_json::Value {
    json!({
        "timestamp": { "require": false },
        "username_token": {
            "enabled": true,
            "password_type": "PasswordDigest",
            "credentials": [
                {"username": "alice", "password": "secret123"}
            ]
        },
        "reject_missing_security_header": true
    })
}

fn wrap_soap(security_content: &str) -> String {
    format!(
        r#"<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Header>
    <wsse:Security xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
                   xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
      {}
    </wsse:Security>
  </soap:Header>
  <soap:Body>
    <GetPrice xmlns="http://example.com/prices"><Item>Widget</Item></GetPrice>
  </soap:Body>
</soap:Envelope>"#,
        security_content
    )
}

fn fresh_timestamp() -> String {
    let now = chrono::Utc::now();
    let created = now.format("%Y-%m-%dT%H:%M:%S%.3fZ");
    let expires = (now + chrono::Duration::minutes(5)).format("%Y-%m-%dT%H:%M:%S%.3fZ");
    format!(
        r#"<wsu:Timestamp wsu:Id="TS-1">
        <wsu:Created>{}</wsu:Created>
        <wsu:Expires>{}</wsu:Expires>
      </wsu:Timestamp>"#,
        created, expires
    )
}

fn is_reject(result: &PluginResult) -> bool {
    matches!(result, PluginResult::Reject { .. })
}

fn reject_status(result: &PluginResult) -> u16 {
    match result {
        PluginResult::Reject { status_code, .. } => *status_code,
        _ => panic!("Expected Reject, got {:?}", result),
    }
}

fn reject_body(result: &PluginResult) -> &str {
    match result {
        PluginResult::Reject { body, .. } => body.as_str(),
        _ => panic!("Expected Reject, got {:?}", result),
    }
}

// ── Constructor validation tests ────────────────────────────────────────────

#[test]
fn test_no_features_enabled_is_error() {
    let config = json!({
        "timestamp": { "require": false },
        "username_token": { "enabled": false },
        "x509_signature": { "enabled": false },
        "saml": { "enabled": false }
    });
    let result = SoapWsSecurity::new(&config);
    assert!(result.is_err());
    assert!(
        result
            .err()
            .unwrap()
            .contains("no security features enabled")
    );
}

#[test]
fn test_username_token_no_credentials_is_error() {
    let config = json!({
        "timestamp": { "require": false },
        "username_token": {
            "enabled": true,
            "password_type": "PasswordText",
            "credentials": []
        }
    });
    let result = SoapWsSecurity::new(&config);
    assert!(result.is_err());
    assert!(
        result
            .err()
            .unwrap()
            .contains("no credentials are configured")
    );
}

#[test]
fn test_invalid_password_type_is_error() {
    let config = json!({
        "timestamp": { "require": false },
        "username_token": {
            "enabled": true,
            "password_type": "InvalidType",
            "credentials": [{"username": "a", "password": "b"}]
        }
    });
    let result = SoapWsSecurity::new(&config);
    assert!(result.is_err());
    assert!(result.err().unwrap().contains("invalid password_type"));
}

#[test]
fn test_x509_no_trusted_certs_is_error() {
    let config = json!({
        "timestamp": { "require": false },
        "x509_signature": {
            "enabled": true,
            "trusted_certs": []
        }
    });
    let result = SoapWsSecurity::new(&config);
    assert!(result.is_err());
    assert!(result.err().unwrap().contains("no trusted_certs"));
}

#[test]
fn test_saml_no_issuers_is_error() {
    let config = json!({
        "timestamp": { "require": false },
        "saml": {
            "enabled": true,
            "trusted_issuers": []
        }
    });
    let result = SoapWsSecurity::new(&config);
    assert!(result.is_err());
    assert!(result.err().unwrap().contains("no trusted_issuers"));
}

#[test]
fn test_valid_timestamp_only_config() {
    let plugin = SoapWsSecurity::new(&timestamp_only_config()).unwrap();
    assert_eq!(plugin.name(), "soap_ws_security");
}

#[test]
fn test_valid_username_token_config() {
    let plugin = SoapWsSecurity::new(&username_token_config()).unwrap();
    assert_eq!(plugin.name(), "soap_ws_security");
}

// ── Non-SOAP request passthrough tests ──────────────────────────────────────

#[tokio::test]
async fn test_non_soap_content_type_passes_through() {
    let plugin = SoapWsSecurity::new(&timestamp_only_config()).unwrap();
    let mut ctx = make_ctx_non_soap();
    let mut headers = non_soap_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
}

#[tokio::test]
async fn test_no_content_type_passes_through() {
    let plugin = SoapWsSecurity::new(&timestamp_only_config()).unwrap();
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/ws".to_string(),
    );
    let mut headers = HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
}

#[tokio::test]
async fn test_application_soap_xml_is_processed() {
    let plugin = SoapWsSecurity::new(&timestamp_only_config()).unwrap();
    let body = wrap_soap(&fresh_timestamp());
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/ws".to_string(),
    );
    ctx.metadata.insert("request_body".to_string(), body);
    let mut headers = HashMap::new();
    headers.insert(
        "content-type".to_string(),
        "application/soap+xml; charset=utf-8".to_string(),
    );
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
}

// ── Missing security header tests ───────────────────────────────────────────

#[tokio::test]
async fn test_missing_security_header_rejects() {
    let plugin = SoapWsSecurity::new(&timestamp_only_config()).unwrap();
    let body = r#"<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
      <soap:Header></soap:Header>
      <soap:Body><Test/></soap:Body>
    </soap:Envelope>"#;
    let mut ctx = make_ctx_with_soap_body(body);
    let mut headers = soap_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(is_reject(&result));
    assert_eq!(reject_status(&result), 401);
    assert!(reject_body(&result).contains("Security header is missing"));
}

#[tokio::test]
async fn test_missing_security_header_allowed_when_not_required() {
    let config = json!({
        "timestamp": { "require": true, "max_age_seconds": 300 },
        "reject_missing_security_header": false
    });
    let plugin = SoapWsSecurity::new(&config).unwrap();
    let body = r#"<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
      <soap:Header></soap:Header>
      <soap:Body><Test/></soap:Body>
    </soap:Envelope>"#;
    let mut ctx = make_ctx_with_soap_body(body);
    let mut headers = soap_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
}

// ── Timestamp validation tests ──────────────────────────────────────────────

#[tokio::test]
async fn test_valid_timestamp_passes() {
    let plugin = SoapWsSecurity::new(&timestamp_only_config()).unwrap();
    let body = wrap_soap(&fresh_timestamp());
    let mut ctx = make_ctx_with_soap_body(&body);
    let mut headers = soap_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
}

#[tokio::test]
async fn test_missing_timestamp_rejects() {
    let plugin = SoapWsSecurity::new(&timestamp_only_config()).unwrap();
    let body = wrap_soap("<!-- no timestamp -->");
    let mut ctx = make_ctx_with_soap_body(&body);
    let mut headers = soap_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(is_reject(&result));
    assert!(reject_body(&result).contains("missing Timestamp"));
}

#[tokio::test]
async fn test_expired_timestamp_rejects() {
    let plugin = SoapWsSecurity::new(&timestamp_only_config()).unwrap();
    let old_time = "2020-01-01T00:00:00.000Z";
    let ts = format!(
        r#"<wsu:Timestamp wsu:Id="TS-1">
            <wsu:Created>{}</wsu:Created>
            <wsu:Expires>{}</wsu:Expires>
        </wsu:Timestamp>"#,
        old_time, old_time
    );
    let body = wrap_soap(&ts);
    let mut ctx = make_ctx_with_soap_body(&body);
    let mut headers = soap_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(is_reject(&result));
    assert!(reject_body(&result).contains("too old"));
}

#[tokio::test]
async fn test_future_timestamp_rejects() {
    let plugin = SoapWsSecurity::new(&json!({
        "timestamp": {
            "require": true,
            "max_age_seconds": 300,
            "clock_skew_seconds": 5  // very small skew
        }
    }))
    .unwrap();

    let future = (chrono::Utc::now() + chrono::Duration::hours(1))
        .format("%Y-%m-%dT%H:%M:%S%.3fZ")
        .to_string();
    let ts = format!(
        r#"<wsu:Timestamp wsu:Id="TS-1">
            <wsu:Created>{}</wsu:Created>
        </wsu:Timestamp>"#,
        future
    );
    let body = wrap_soap(&ts);
    let mut ctx = make_ctx_with_soap_body(&body);
    let mut headers = soap_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(is_reject(&result));
    assert!(reject_body(&result).contains("in the future"));
}

#[tokio::test]
async fn test_timestamp_expires_past_rejects() {
    let plugin = SoapWsSecurity::new(&json!({
        "timestamp": {
            "require": true,
            "max_age_seconds": 86400,
            "clock_skew_seconds": 5
        }
    }))
    .unwrap();

    let now = chrono::Utc::now();
    let created = (now - chrono::Duration::minutes(1)).format("%Y-%m-%dT%H:%M:%S%.3fZ");
    let expires = (now - chrono::Duration::minutes(30)).format("%Y-%m-%dT%H:%M:%S%.3fZ");
    let ts = format!(
        r#"<wsu:Timestamp wsu:Id="TS-1">
            <wsu:Created>{}</wsu:Created>
            <wsu:Expires>{}</wsu:Expires>
        </wsu:Timestamp>"#,
        created, expires
    );
    let body = wrap_soap(&ts);
    let mut ctx = make_ctx_with_soap_body(&body);
    let mut headers = soap_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(is_reject(&result));
    assert!(reject_body(&result).contains("expired"));
}

#[tokio::test]
async fn test_timestamp_require_expires_missing_rejects() {
    let config = json!({
        "timestamp": {
            "require": true,
            "max_age_seconds": 300,
            "require_expires": true
        }
    });
    let plugin = SoapWsSecurity::new(&config).unwrap();

    let now = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ");
    let ts = format!(
        r#"<wsu:Timestamp wsu:Id="TS-1">
            <wsu:Created>{}</wsu:Created>
        </wsu:Timestamp>"#,
        now
    );
    let body = wrap_soap(&ts);
    let mut ctx = make_ctx_with_soap_body(&body);
    let mut headers = soap_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(is_reject(&result));
    assert!(reject_body(&result).contains("missing required Expires"));
}

// ── UsernameToken tests ─────────────────────────────────────────────────────

#[tokio::test]
async fn test_username_token_password_text_valid() {
    let plugin = SoapWsSecurity::new(&username_token_config()).unwrap();
    let ut = r#"<wsse:UsernameToken>
        <wsse:Username>alice</wsse:Username>
        <wsse:Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText">secret123</wsse:Password>
    </wsse:UsernameToken>"#;
    let body = wrap_soap(ut);
    let mut ctx = make_ctx_with_soap_body(&body);
    let mut headers = soap_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
    assert_eq!(ctx.metadata.get("soap_ws_username").unwrap(), "alice");
}

#[tokio::test]
async fn test_username_token_wrong_password_rejects() {
    let plugin = SoapWsSecurity::new(&username_token_config()).unwrap();
    let ut = r#"<wsse:UsernameToken>
        <wsse:Username>alice</wsse:Username>
        <wsse:Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText">wrongpass</wsse:Password>
    </wsse:UsernameToken>"#;
    let body = wrap_soap(ut);
    let mut ctx = make_ctx_with_soap_body(&body);
    let mut headers = soap_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(is_reject(&result));
    assert_eq!(reject_status(&result), 401);
    assert!(reject_body(&result).contains("invalid password"));
}

#[tokio::test]
async fn test_username_token_unknown_user_rejects() {
    let plugin = SoapWsSecurity::new(&username_token_config()).unwrap();
    let ut = r#"<wsse:UsernameToken>
        <wsse:Username>eve</wsse:Username>
        <wsse:Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText">anything</wsse:Password>
    </wsse:UsernameToken>"#;
    let body = wrap_soap(ut);
    let mut ctx = make_ctx_with_soap_body(&body);
    let mut headers = soap_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(is_reject(&result));
    assert!(reject_body(&result).contains("unknown username"));
}

#[tokio::test]
async fn test_username_token_missing_password_rejects() {
    let plugin = SoapWsSecurity::new(&username_token_config()).unwrap();
    let ut = r#"<wsse:UsernameToken>
        <wsse:Username>alice</wsse:Username>
    </wsse:UsernameToken>"#;
    let body = wrap_soap(ut);
    let mut ctx = make_ctx_with_soap_body(&body);
    let mut headers = soap_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(is_reject(&result));
    assert!(reject_body(&result).contains("missing Password"));
}

#[tokio::test]
async fn test_username_token_missing_username_rejects() {
    let plugin = SoapWsSecurity::new(&username_token_config()).unwrap();
    let ut = r#"<wsse:UsernameToken>
        <wsse:Password>secret123</wsse:Password>
    </wsse:UsernameToken>"#;
    let body = wrap_soap(ut);
    let mut ctx = make_ctx_with_soap_body(&body);
    let mut headers = soap_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(is_reject(&result));
    assert!(reject_body(&result).contains("missing Username"));
}

// ── PasswordDigest tests ────────────────────────────────────────────────────

#[tokio::test]
async fn test_password_digest_valid() {
    let plugin = SoapWsSecurity::new(&username_token_digest_config()).unwrap();

    // Compute a valid PasswordDigest: Base64(SHA-1(nonce + created + password))
    let nonce_bytes = b"test-nonce-12345";
    let nonce_b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, nonce_bytes);
    let created = chrono::Utc::now()
        .format("%Y-%m-%dT%H:%M:%S%.3fZ")
        .to_string();

    let mut data = Vec::new();
    data.extend_from_slice(nonce_bytes);
    data.extend_from_slice(created.as_bytes());
    data.extend_from_slice(b"secret123");

    let digest = ring::digest::digest(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY, &data);
    let digest_b64 =
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, digest.as_ref());

    let ut = format!(
        r#"<wsse:UsernameToken>
        <wsse:Username>alice</wsse:Username>
        <wsse:Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest">{}</wsse:Password>
        <wsse:Nonce EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary">{}</wsse:Nonce>
        <wsu:Created>{}</wsu:Created>
    </wsse:UsernameToken>"#,
        digest_b64, nonce_b64, created
    );
    let body = wrap_soap(&ut);
    let mut ctx = make_ctx_with_soap_body(&body);
    let mut headers = soap_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(
        matches!(result, PluginResult::Continue),
        "Expected Continue, got {:?}",
        result
    );
    assert_eq!(ctx.metadata.get("soap_ws_username").unwrap(), "alice");
}

#[tokio::test]
async fn test_password_digest_wrong_password_rejects() {
    let plugin = SoapWsSecurity::new(&username_token_digest_config()).unwrap();

    let nonce_bytes = b"wrong-nonce-test";
    let nonce_b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, nonce_bytes);
    let created = chrono::Utc::now()
        .format("%Y-%m-%dT%H:%M:%S%.3fZ")
        .to_string();

    // Use wrong password for digest
    let mut data = Vec::new();
    data.extend_from_slice(nonce_bytes);
    data.extend_from_slice(created.as_bytes());
    data.extend_from_slice(b"wrongpassword");

    let digest = ring::digest::digest(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY, &data);
    let digest_b64 =
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, digest.as_ref());

    let ut = format!(
        r#"<wsse:UsernameToken>
        <wsse:Username>alice</wsse:Username>
        <wsse:Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest">{}</wsse:Password>
        <wsse:Nonce>{}</wsse:Nonce>
        <wsu:Created>{}</wsu:Created>
    </wsse:UsernameToken>"#,
        digest_b64, nonce_b64, created
    );
    let body = wrap_soap(&ut);
    let mut ctx = make_ctx_with_soap_body(&body);
    let mut headers = soap_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(is_reject(&result));
    assert!(reject_body(&result).contains("PasswordDigest verification failed"));
}

#[tokio::test]
async fn test_password_digest_missing_nonce_rejects() {
    let plugin = SoapWsSecurity::new(&username_token_digest_config()).unwrap();
    let ut = r#"<wsse:UsernameToken>
        <wsse:Username>alice</wsse:Username>
        <wsse:Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest">dGVzdA==</wsse:Password>
        <wsu:Created>2026-01-01T00:00:00Z</wsu:Created>
    </wsse:UsernameToken>"#;
    let body = wrap_soap(ut);
    let mut ctx = make_ctx_with_soap_body(&body);
    let mut headers = soap_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(is_reject(&result));
    assert!(reject_body(&result).contains("requires Nonce"));
}

// ── Nonce replay protection tests ───────────────────────────────────────────

#[tokio::test]
async fn test_nonce_replay_detected() {
    let plugin = SoapWsSecurity::new(&username_token_digest_config()).unwrap();

    let nonce_bytes = b"replay-nonce-001";
    let nonce_b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, nonce_bytes);
    let created = chrono::Utc::now()
        .format("%Y-%m-%dT%H:%M:%S%.3fZ")
        .to_string();

    let mut data = Vec::new();
    data.extend_from_slice(nonce_bytes);
    data.extend_from_slice(created.as_bytes());
    data.extend_from_slice(b"secret123");

    let digest = ring::digest::digest(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY, &data);
    let digest_b64 =
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, digest.as_ref());

    let ut = format!(
        r#"<wsse:UsernameToken>
        <wsse:Username>alice</wsse:Username>
        <wsse:Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest">{}</wsse:Password>
        <wsse:Nonce>{}</wsse:Nonce>
        <wsu:Created>{}</wsu:Created>
    </wsse:UsernameToken>"#,
        digest_b64, nonce_b64, created
    );
    let body = wrap_soap(&ut);

    // First request succeeds
    let mut ctx = make_ctx_with_soap_body(&body);
    let mut headers = soap_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));

    // Second request with same nonce is replay
    let mut ctx2 = make_ctx_with_soap_body(&body);
    let mut headers2 = soap_headers();
    let result2 = plugin.before_proxy(&mut ctx2, &mut headers2).await;
    assert!(is_reject(&result2));
    assert!(reject_body(&result2).contains("nonce replay"));
}

// ── SAML assertion tests ────────────────────────────────────────────────────

#[tokio::test]
async fn test_saml_valid_assertion() {
    let config = json!({
        "timestamp": { "require": false },
        "saml": {
            "enabled": true,
            "trusted_issuers": ["https://idp.example.com"],
            "audience": "https://service.example.com",
            "clock_skew_seconds": 300
        },
        "reject_missing_security_header": true
    });
    let plugin = SoapWsSecurity::new(&config).unwrap();

    let now = chrono::Utc::now();
    let not_before = (now - chrono::Duration::minutes(5)).format("%Y-%m-%dT%H:%M:%SZ");
    let not_after = (now + chrono::Duration::minutes(25)).format("%Y-%m-%dT%H:%M:%SZ");

    let assertion = format!(
        r#"<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Version="2.0">
        <saml:Issuer>https://idp.example.com</saml:Issuer>
        <saml:Conditions NotBefore="{}" NotOnOrAfter="{}">
            <saml:AudienceRestriction>
                <saml:Audience>https://service.example.com</saml:Audience>
            </saml:AudienceRestriction>
        </saml:Conditions>
    </saml:Assertion>"#,
        not_before, not_after
    );
    let body = wrap_soap(&assertion);
    let mut ctx = make_ctx_with_soap_body(&body);
    let mut headers = soap_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
}

#[tokio::test]
async fn test_saml_untrusted_issuer_rejects() {
    let config = json!({
        "timestamp": { "require": false },
        "saml": {
            "enabled": true,
            "trusted_issuers": ["https://idp.example.com"]
        },
        "reject_missing_security_header": true
    });
    let plugin = SoapWsSecurity::new(&config).unwrap();

    let assertion = r#"<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
        <saml:Issuer>https://evil.example.com</saml:Issuer>
    </saml:Assertion>"#;
    let body = wrap_soap(assertion);
    let mut ctx = make_ctx_with_soap_body(&body);
    let mut headers = soap_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(is_reject(&result));
    assert!(reject_body(&result).contains("not trusted"));
}

#[tokio::test]
async fn test_saml_expired_assertion_rejects() {
    let config = json!({
        "timestamp": { "require": false },
        "saml": {
            "enabled": true,
            "trusted_issuers": ["https://idp.example.com"],
            "clock_skew_seconds": 5
        },
        "reject_missing_security_header": true
    });
    let plugin = SoapWsSecurity::new(&config).unwrap();

    let assertion = r#"<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
        <saml:Issuer>https://idp.example.com</saml:Issuer>
        <saml:Conditions NotBefore="2020-01-01T00:00:00Z" NotOnOrAfter="2020-01-01T01:00:00Z">
        </saml:Conditions>
    </saml:Assertion>"#;
    let body = wrap_soap(assertion);
    let mut ctx = make_ctx_with_soap_body(&body);
    let mut headers = soap_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(is_reject(&result));
    assert!(reject_body(&result).contains("expired"));
}

#[tokio::test]
async fn test_saml_not_yet_valid_rejects() {
    let config = json!({
        "timestamp": { "require": false },
        "saml": {
            "enabled": true,
            "trusted_issuers": ["https://idp.example.com"],
            "clock_skew_seconds": 5
        },
        "reject_missing_security_header": true
    });
    let plugin = SoapWsSecurity::new(&config).unwrap();

    let future = (chrono::Utc::now() + chrono::Duration::hours(2)).format("%Y-%m-%dT%H:%M:%SZ");
    let assertion = format!(
        r#"<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
        <saml:Issuer>https://idp.example.com</saml:Issuer>
        <saml:Conditions NotBefore="{}">
        </saml:Conditions>
    </saml:Assertion>"#,
        future
    );
    let body = wrap_soap(&assertion);
    let mut ctx = make_ctx_with_soap_body(&body);
    let mut headers = soap_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(is_reject(&result));
    assert!(reject_body(&result).contains("not yet valid"));
}

#[tokio::test]
async fn test_saml_wrong_audience_rejects() {
    let config = json!({
        "timestamp": { "require": false },
        "saml": {
            "enabled": true,
            "trusted_issuers": ["https://idp.example.com"],
            "audience": "https://service.example.com",
            "clock_skew_seconds": 300
        },
        "reject_missing_security_header": true
    });
    let plugin = SoapWsSecurity::new(&config).unwrap();

    let now = chrono::Utc::now();
    let not_before = (now - chrono::Duration::minutes(5)).format("%Y-%m-%dT%H:%M:%SZ");
    let not_after = (now + chrono::Duration::minutes(25)).format("%Y-%m-%dT%H:%M:%SZ");

    let assertion = format!(
        r#"<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
        <saml:Issuer>https://idp.example.com</saml:Issuer>
        <saml:Conditions NotBefore="{}" NotOnOrAfter="{}">
            <saml:AudienceRestriction>
                <saml:Audience>https://wrong-service.example.com</saml:Audience>
            </saml:AudienceRestriction>
        </saml:Conditions>
    </saml:Assertion>"#,
        not_before, not_after
    );
    let body = wrap_soap(&assertion);
    let mut ctx = make_ctx_with_soap_body(&body);
    let mut headers = soap_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(is_reject(&result));
    assert!(reject_body(&result).contains("Audience"));
}

#[tokio::test]
async fn test_saml_missing_assertion_rejects() {
    let config = json!({
        "timestamp": { "require": false },
        "saml": {
            "enabled": true,
            "trusted_issuers": ["https://idp.example.com"]
        },
        "reject_missing_security_header": true
    });
    let plugin = SoapWsSecurity::new(&config).unwrap();
    let body = wrap_soap("<!-- no assertion -->");
    let mut ctx = make_ctx_with_soap_body(&body);
    let mut headers = soap_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(is_reject(&result));
    assert!(reject_body(&result).contains("missing SAML Assertion"));
}

// ── Body buffering flag tests ───────────────────────────────────────────────

#[test]
fn test_requires_body_buffering() {
    let plugin = SoapWsSecurity::new(&timestamp_only_config()).unwrap();
    assert!(plugin.requires_request_body_before_before_proxy());
}

#[test]
fn test_should_buffer_soap_content_type() {
    let plugin = SoapWsSecurity::new(&timestamp_only_config()).unwrap();

    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/ws".to_string(),
    );
    ctx.headers
        .insert("content-type".to_string(), "text/xml".to_string());
    assert!(plugin.should_buffer_request_body(&ctx));

    ctx.headers.insert(
        "content-type".to_string(),
        "application/soap+xml; charset=utf-8".to_string(),
    );
    assert!(plugin.should_buffer_request_body(&ctx));
}

#[test]
fn test_should_not_buffer_non_soap() {
    let plugin = SoapWsSecurity::new(&timestamp_only_config()).unwrap();

    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/api".to_string(),
    );
    ctx.headers
        .insert("content-type".to_string(), "application/json".to_string());
    assert!(!plugin.should_buffer_request_body(&ctx));
}

// ── Non-envelope request tests ──────────────────────────────────────────────

#[tokio::test]
async fn test_non_envelope_soap_body_rejects() {
    let plugin = SoapWsSecurity::new(&timestamp_only_config()).unwrap();
    let mut ctx = make_ctx_with_soap_body("<notasoap>hello</notasoap>");
    let mut headers = soap_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(is_reject(&result));
    assert!(reject_body(&result).contains("not a SOAP envelope"));
}

// ── Plugin metadata tests ───────────────────────────────────────────────────

#[test]
fn test_plugin_name() {
    let plugin = SoapWsSecurity::new(&timestamp_only_config()).unwrap();
    assert_eq!(plugin.name(), "soap_ws_security");
}

#[test]
fn test_plugin_priority() {
    let plugin = SoapWsSecurity::new(&timestamp_only_config()).unwrap();
    assert_eq!(
        plugin.priority(),
        ferrum_edge::plugins::priority::SOAP_WS_SECURITY
    );
}

// ── Namespace prefix agnostic tests ─────────────────────────────────────────

#[tokio::test]
async fn test_handles_different_namespace_prefixes() {
    let plugin = SoapWsSecurity::new(&timestamp_only_config()).unwrap();

    let now = chrono::Utc::now();
    let created = now.format("%Y-%m-%dT%H:%M:%S%.3fZ");
    let expires = (now + chrono::Duration::minutes(5)).format("%Y-%m-%dT%H:%M:%S%.3fZ");

    // Use non-standard prefixes (s: instead of soap:, sec: instead of wsse:)
    let body = format!(
        r#"<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
  <s:Header>
    <sec:Security xmlns:sec="{}" xmlns:u="{}">
      <u:Timestamp u:Id="TS-1">
        <u:Created>{}</u:Created>
        <u:Expires>{}</u:Expires>
      </u:Timestamp>
    </sec:Security>
  </s:Header>
  <s:Body><Test/></s:Body>
</s:Envelope>"#,
        "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd",
        "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd",
        created,
        expires
    );
    let mut ctx = make_ctx_with_soap_body(&body);
    let mut headers = soap_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
}

#[tokio::test]
async fn test_empty_body_rejects() {
    let plugin = SoapWsSecurity::new(&timestamp_only_config()).unwrap();
    let mut ctx = make_ctx_with_soap_body("");
    let mut headers = soap_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(is_reject(&result));
}

// ── Nonce cache cap enforcement tests ───────────────────────────────────────

#[test]
fn test_nonce_cache_enforces_max_size_by_evicting_oldest() {
    let max_size: usize = 20;
    let plugin = SoapWsSecurity::new(&json!({
        "timestamp": { "require": true },
        "nonce": { "max_cache_size": max_size, "ttl_seconds": 300 },
        "reject_missing_security_header": false
    }))
    .unwrap();

    // Insert nonces well past the cap
    for i in 0..(max_size + 50) {
        let nonce = format!("nonce-{}", i);
        let _ = plugin.check_nonce_replay(&nonce);
    }

    // The oldest nonces should have been evicted to enforce the cap.
    // Verify by checking that the first nonce is no longer tracked as a replay.
    assert!(
        plugin.check_nonce_replay("nonce-0").is_ok(),
        "nonce-0 should have been evicted by cap enforcement"
    );

    // But recent nonces should still be detected as replays
    let last_nonce = format!("nonce-{}", max_size + 49);
    assert!(
        plugin.check_nonce_replay(&last_nonce).is_err(),
        "most recent nonce should still be in cache"
    );
}

#[test]
fn test_nonce_replay_detected_via_direct_api() {
    let plugin = SoapWsSecurity::new(&json!({
        "timestamp": { "require": true },
        "nonce": { "max_cache_size": 100, "ttl_seconds": 300 },
        "reject_missing_security_header": false
    }))
    .unwrap();

    assert!(plugin.check_nonce_replay("unique-nonce").is_ok());
    assert!(plugin.check_nonce_replay("unique-nonce").is_err());
}
