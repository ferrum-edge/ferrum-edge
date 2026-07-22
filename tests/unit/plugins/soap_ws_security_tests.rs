use ferrum_edge::_test_support::{
    soap_count_wsu_id_occurrences_for_test, soap_decode_xml_body_for_test,
    soap_exclusive_canonicalize_element_for_test,
};
use ferrum_edge::plugins::soap_ws_security::SoapWsSecurity;
use ferrum_edge::plugins::{HTTP_ONLY_PROTOCOLS, Plugin, PluginResult, RequestContext, priority};
use serde_json::{Value, json};
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
    // Mirror the proxy handoff: plugins that opt into bytes receive the wire
    // representation even when it is not UTF-8.
    ctx.request_body_bytes = Some(bytes::Bytes::copy_from_slice(body.as_bytes()));
    ctx
}

fn make_ctx_with_soap_bytes(body: Vec<u8>, content_type: &str) -> RequestContext {
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/ws".to_string(),
    );
    ctx.headers
        .insert("content-type".to_string(), content_type.to_string());
    ctx.request_body_bytes = Some(bytes::Bytes::from(body));
    ctx
}

fn soap_headers_with_content_type(content_type: &str) -> HashMap<String, String> {
    let mut h = HashMap::new();
    h.insert("content-type".to_string(), content_type.to_string());
    h
}

fn encode_utf16_le(text: &str) -> Vec<u8> {
    let mut out = vec![0xFF, 0xFE]; // BOM
    for unit in text.encode_utf16() {
        out.extend_from_slice(&unit.to_le_bytes());
    }
    out
}

fn encode_utf16_be(text: &str) -> Vec<u8> {
    let mut out = vec![0xFE, 0xFF]; // BOM
    for unit in text.encode_utf16() {
        out.extend_from_slice(&unit.to_be_bytes());
    }
    out
}

fn encode_utf16_le_no_bom(text: &str) -> Vec<u8> {
    let mut out = Vec::new();
    for unit in text.encode_utf16() {
        out.extend_from_slice(&unit.to_le_bytes());
    }
    out
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

fn reject_headers(result: &PluginResult) -> &HashMap<String, String> {
    match result {
        PluginResult::Reject { headers, .. } => headers,
        _ => panic!("Expected Reject, got {:?}", result),
    }
}

/// Public UsernameToken invalid-credential body (GHSA-jp56 / issue #2642).
const USERNAME_TOKEN_INVALID_CREDENTIALS_BODY: &str =
    r#"{"error":"WS-Security: invalid credentials"}"#;

fn assert_username_token_invalid_credentials(result: &PluginResult, candidate_usernames: &[&str]) {
    assert!(is_reject(result));
    assert_eq!(reject_status(result), 401);
    assert_eq!(reject_body(result), USERNAME_TOKEN_INVALID_CREDENTIALS_BODY);
    assert!(
        reject_headers(result).is_empty(),
        "invalid-credential rejects must not add distinguishing headers: {:?}",
        reject_headers(result)
    );
    let body = reject_body(result);
    for candidate in candidate_usernames {
        assert!(
            !body.contains(candidate),
            "client body must not leak candidate username {:?}: {}",
            candidate,
            body
        );
    }
    assert!(
        !body.to_ascii_lowercase().contains("unknown"),
        "client body must not disclose unknown-username: {}",
        body
    );
    assert!(
        !body.contains("invalid password"),
        "client body must not disclose password-verification detail: {}",
        body
    );
    assert!(
        !body.contains("PasswordDigest verification failed"),
        "client body must not disclose digest-verification detail: {}",
        body
    );
}

fn assert_username_token_structural(
    result: &PluginResult,
    expected_fragment: &str,
    candidate_usernames: &[&str],
) {
    assert!(is_reject(result));
    assert_eq!(reject_status(result), 401);
    assert!(
        reject_headers(result).is_empty(),
        "structural rejects must not add distinguishing headers: {:?}",
        reject_headers(result)
    );
    let body = reject_body(result);
    assert_ne!(
        body, USERNAME_TOKEN_INVALID_CREDENTIALS_BODY,
        "structural failures must remain distinct from invalid-credential rejects"
    );
    assert!(
        body.contains(expected_fragment),
        "expected structural fragment {:?}, got: {}",
        expected_fragment,
        body
    );
    for candidate in candidate_usernames {
        assert!(
            !body.contains(candidate),
            "structural body must not leak candidate username {:?}: {}",
            candidate,
            body
        );
    }
}

fn password_digest_token(username: &str, password: &str, nonce_bytes: &[u8]) -> String {
    let created = chrono::Utc::now()
        .format("%Y-%m-%dT%H:%M:%S%.3fZ")
        .to_string();
    password_digest_token_with_created(username, password, nonce_bytes, &created)
}

fn password_digest_token_with_created(
    username: &str,
    password: &str,
    nonce_bytes: &[u8],
    created: &str,
) -> String {
    let nonce_b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, nonce_bytes);

    let mut data = Vec::new();
    data.extend_from_slice(nonce_bytes);
    data.extend_from_slice(created.as_bytes());
    data.extend_from_slice(password.as_bytes());

    let digest = ring::digest::digest(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY, &data);
    let digest_b64 =
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, digest.as_ref());

    format!(
        r#"<wsse:UsernameToken>
        <wsse:Username>{}</wsse:Username>
        <wsse:Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest">{}</wsse:Password>
        <wsse:Nonce EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary">{}</wsse:Nonce>
        <wsu:Created>{}</wsu:Created>
    </wsse:UsernameToken>"#,
        username, digest_b64, nonce_b64, created
    )
}

// ── Constructor validation tests ────────────────────────────────────────────

#[test]
fn test_non_object_config_is_error() {
    let result = SoapWsSecurity::new(&json!(null));
    assert!(result.is_err());
    assert!(result.err().unwrap().contains("config must be an object"));
}

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

/// Material that loads successfully and then fails to parse, whose configured
/// source string is *not* its safe display label.
///
/// `CertSource::parse` routes anything starting with `-----BEGIN ` to
/// `CertSource::InlinePem`, which always materializes (no filesystem, no
/// provider feature) and stamps `display_source_id` as the fixed
/// `inline-pem:<redacted>`. That makes it the one source kind that reaches the
/// post-fetch decode/parse errors hermetically *and* has a configured string
/// worth withholding — here a sentinel standing in for the private material a
/// real inline blob would carry. A `vault://`/`aws://` source has the same
/// identity/display split but cannot reach these arms without its backend
/// feature compiled in.
const MALFORMED_INLINE_PEM: &str =
    "-----BEGIN CERTIFICATE-----\nSOAP-INLINE-SOURCE-SENTINEL\n-----END CERTIFICATE-----\n";

/// The plugin's operator-facing label for the fixture above.
const INLINE_PEM_DISPLAY: &str = "inline-pem:<redacted>";

/// A successful fetch followed by a failed PEM decode must name the material by
/// its redacted display label, never by the configured source.
///
/// The UTF-8 arm already did this; the decode/parse/key arms interpolated the
/// raw configured string, so a `vault://…` path — or, as here, inline private
/// material — was disclosed on exactly the paths most likely to fire.
#[test]
fn test_x509_malformed_pem_error_withholds_configured_source() {
    let config = json!({
        "timestamp": { "require": false },
        "x509_signature": {
            "enabled": true,
            "trusted_certs": [MALFORMED_INLINE_PEM]
        }
    });
    let err = SoapWsSecurity::new(&config)
        .err()
        .expect("malformed PEM must fail");
    assert!(
        err.contains("failed to decode PEM"),
        "must fail on the decode arm, not an earlier one: {err}"
    );
    assert!(
        !err.contains("SOAP-INLINE-SOURCE-SENTINEL"),
        "the configured source must not be echoed: {err}"
    );
    assert!(
        err.contains(INLINE_PEM_DISPLAY),
        "the redacted display label must identify the material: {err}"
    );
}

/// The SAML `trusted_signing_certs` loop carries the same rule.
#[test]
fn test_saml_malformed_pem_error_withholds_configured_source() {
    let config = json!({
        "timestamp": { "require": false },
        "saml": {
            "enabled": true,
            "trusted_issuers": ["urn:test:idp"],
            "trusted_signing_certs": [MALFORMED_INLINE_PEM],
            "allowed_algorithms": ["rsa-sha256"]
        }
    });
    let err = SoapWsSecurity::new(&config)
        .err()
        .expect("malformed PEM must fail");
    assert!(
        err.contains("failed to decode PEM"),
        "must fail on the SAML decode arm: {err}"
    );
    assert!(
        !err.contains("SOAP-INLINE-SOURCE-SENTINEL"),
        "the configured source must not be echoed: {err}"
    );
    assert!(
        err.contains(INLINE_PEM_DISPLAY),
        "the redacted display label must identify the material: {err}"
    );
}

/// Past the PEM decode: a well-formed PEM envelope whose body is not a valid
/// X.509 certificate reaches the `X509Certificate::from_der` arm, which was the
/// second of the three raw-source interpolations.
#[test]
fn test_x509_unparsable_cert_error_withholds_configured_source() {
    // Valid base64 inside a valid envelope, so `extract_pem_der` succeeds and
    // the DER parse is what fails.
    let source = "-----BEGIN CERTIFICATE-----\nU09BUC1ERVItU0VOVElORUw=\n\
                  -----END CERTIFICATE-----\n";
    let config = json!({
        "timestamp": { "require": false },
        "x509_signature": {
            "enabled": true,
            "trusted_certs": [source]
        }
    });
    let err = SoapWsSecurity::new(&config)
        .err()
        .expect("unparsable cert must fail");
    assert!(
        err.contains("failed to parse X.509 cert"),
        "must fail on the DER-parse arm: {err}"
    );
    assert!(
        !err.contains("U09BUC1ERVItU0VOVElORUw"),
        "the configured source must not be echoed: {err}"
    );
    assert!(
        err.contains(INLINE_PEM_DISPLAY),
        "the redacted display label must identify the material: {err}"
    );
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
fn test_plugin_contract() {
    let plugin = SoapWsSecurity::new(&timestamp_only_config()).unwrap();

    assert_eq!(plugin.priority(), priority::SOAP_WS_SECURITY);
    assert_eq!(plugin.priority(), 1500);
    assert_eq!(plugin.supported_protocols(), HTTP_ONLY_PROTOCOLS);
    // SOAP WS-Security validates in before_proxy after SOAP bodies are buffered;
    // enrolling it in the generic auth phase rejects before it can inspect the
    // UsernameToken.
    assert!(!plugin.is_auth_plugin());
    assert!(!plugin.modifies_request_headers());
    assert!(!plugin.modifies_request_body());
    assert!(plugin.requires_request_body_before_before_proxy());
    assert!(!plugin.requires_request_body_before_authenticate());
    assert!(plugin.needs_request_body_bytes());
    assert!(!plugin.needs_request_body_text());
    assert!(plugin.requires_request_body_buffering());
    assert!(!plugin.requires_response_body_buffering());
    assert!(!plugin.applies_after_proxy_on_reject());
}

/// OpenAPI must advertise the same exclusive-c14n contract as the runtime and
/// `docs/plugins.md` (issue #2328). Guards against reintroducing the pre-#2033
/// wire-byte / no-`xml-exc-c14n#` schema wording.
#[test]
fn openapi_soap_ws_security_describes_exclusive_c14n_contract() {
    let spec: Value =
        serde_yaml::from_str(include_str!("../../../openapi.yaml")).expect("openapi.yaml parses");
    let root = spec["components"]["schemas"]["SoapWsSecurityConfig"]["description"]
        .as_str()
        .expect("SoapWsSecurityConfig description");
    let saml =
        spec["components"]["schemas"]["SoapWsSecurityConfig"]["properties"]["saml"]["description"]
            .as_str()
            .expect("SoapWsSecurityConfig.saml description");
    let plugins_doc = include_str!("../../../docs/plugins.md");

    for (label, text) in [("root", root), ("saml", saml)] {
        assert!(
            text.contains("xml-exc-c14n#"),
            "{label} OpenAPI description must name exclusive c14n: {text}"
        );
        assert!(
            text.contains("InclusiveNamespaces PrefixList"),
            "{label} OpenAPI description must name InclusiveNamespaces PrefixList: {text}"
        );
        assert!(
            !text.contains("wire bytes of")
                && !text.contains("do not yet apply")
                && !text.contains("do not currently apply"),
            "{label} OpenAPI description must not claim wire-byte / missing-c14n verification: {text}"
        );
    }

    assert!(
        root.contains("Original wire bytes are preserved"),
        "root OpenAPI description must state that original wire bytes are preserved: {root}"
    );

    assert!(
        root.contains("enveloped-signature") && root.contains("exclusive c14n"),
        "root OpenAPI description must name the supported reference-transform chain: {root}"
    );
    assert!(
        saml.contains("enveloped-signature") && saml.contains("xml-exc-c14n#"),
        "saml OpenAPI description must name the supported reference-transform chain: {saml}"
    );

    assert!(
        plugins_doc.contains("Exclusive XML Canonicalization (`xml-exc-c14n#`)")
            && plugins_doc.contains("InclusiveNamespaces PrefixList")
            && plugins_doc.contains("enveloped-signature transform followed by exclusive c14n"),
        "docs/plugins.md must retain the exclusive-c14n contract that OpenAPI mirrors"
    );
}

#[test]
fn count_wsu_id_occurrences_counts_mixed_id_spellings_once_each() {
    let xml = r#"
        <Envelope>
            <a:Timestamp a:Id='TS-1'/>
            <Header Id="TS-1"/>
            <Assertion xml:id='TS-1'/>
            <Legacy ID="TS-1"/>
            <Lower id='TS-1'/>
            <Business CorrelationId="TS-1" Message_Id='TS-1' Audit-Id="TS-1" Trace.Id='TS-1'/>
            <Body>literal Id="TS-1" and wsu:Id='TS-1' text must not count</Body>
        </Envelope>
    "#;

    assert_eq!(
        soap_count_wsu_id_occurrences_for_test(xml, "TS-1")
            .expect("well-formed XML should count id occurrences"),
        5
    );
}

#[test]
fn count_wsu_id_occurrences_counts_ids_after_gt_in_quoted_attribute() {
    let xml = r#"
        <Envelope>
            <wsu:Timestamp wsu:Id="TS-1"/>
            <Injected pad=">" Id="TS-1">attacker</Injected>
            <Other pad='>' xml:id='TS-1'>attacker</Other>
        </Envelope>
    "#;

    assert_eq!(
        soap_count_wsu_id_occurrences_for_test(xml, "TS-1")
            .expect("well-formed XML should count id occurrences"),
        3
    );
}

#[test]
fn count_wsu_id_occurrences_fails_closed_after_unbalanced_quote() {
    let xml = r#"<a Id="X"/><b z="><c Id="X"/>"#;

    let err = soap_count_wsu_id_occurrences_for_test(xml, "X")
        .expect_err("unterminated quoted start tag must reject instead of undercounting");

    assert!(
        err.contains("malformed XML start tag"),
        "unexpected error: {err}"
    );
}

#[test]
fn count_wsu_id_occurrences_skips_comment_content() {
    let xml = r#"
        <Envelope>
            <First Id="X"/>
            <!-- <debug note=" Id="X" -->
            <Second Id="X"/>
        </Envelope>
    "#;

    assert_eq!(
        soap_count_wsu_id_occurrences_for_test(xml, "X")
            .expect("comment content should not be scanned as start tags"),
        2
    );
}

#[test]
fn count_wsu_id_occurrences_skips_cdata_content() {
    let xml = r#"
        <Envelope>
            <First Id="X"/>
            <![CDATA[<debug note=" Id="X">]]>
            <Second Id="X"/>
        </Envelope>
    "#;

    assert_eq!(
        soap_count_wsu_id_occurrences_for_test(xml, "X")
            .expect("CDATA content should not be scanned as start tags"),
        2
    );
}

#[test]
fn count_wsu_id_occurrences_fails_closed_on_unterminated_comment() {
    let xml = r#"<a Id="X"/><!-- <b Id="X"/>"#;

    let err = soap_count_wsu_id_occurrences_for_test(xml, "X")
        .expect_err("unterminated comments must reject instead of hiding ids");

    assert!(
        err.contains("malformed XML comment"),
        "unexpected error: {err}"
    );
}

#[test]
fn exclusive_c14n_reemits_inherited_namespaces_and_orders_attributes() {
    let xml = r#"<outer xmlns="urn:default" xmlns:p="urn:payload" xmlns:keep="urn:inclusive">
        <p:Payload z="last" p:qualified="third" a="first"><Child/><p:Empty/></p:Payload>
    </outer>"#;

    let canonical = soap_exclusive_canonicalize_element_for_test(xml, "Payload", "keep #default")
        .expect("fixture must canonicalize");

    assert_eq!(
        canonical,
        "<p:Payload xmlns=\"urn:default\" xmlns:keep=\"urn:inclusive\" xmlns:p=\"urn:payload\" a=\"first\" z=\"last\" p:qualified=\"third\"><Child></Child><p:Empty></p:Empty></p:Payload>"
    );
}

#[test]
fn exclusive_c14n_rejects_excessive_element_depth() {
    let mut xml = String::from("<Root>");
    for _ in 0..257 {
        xml.push_str("<Nested>");
    }
    for _ in 0..257 {
        xml.push_str("</Nested>");
    }
    xml.push_str("</Root>");

    let error = soap_exclusive_canonicalize_element_for_test(&xml, "Root", "")
        .expect_err("excessive c14n depth must fail closed");

    assert!(error.contains("depth exceeds"), "unexpected error: {error}");
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
    assert_username_token_invalid_credentials(&result, &["alice"]);
}

#[tokio::test]
async fn test_password_digest_config_rejects_passwordtext_type_downgrade() {
    // finding #19: with password_type=PasswordDigest configured, a client must
    // not be able to downgrade to plain PasswordText by sending
    // `Type="...#PasswordText"` — that bypasses the Nonce/Created/replay
    // protections the operator selected. Even presenting the correct plaintext
    // password must be rejected because the wire Type disagrees with the policy.
    let plugin = SoapWsSecurity::new(&username_token_digest_config()).unwrap();
    let ut = r#"<wsse:UsernameToken>
        <wsse:Username>alice</wsse:Username>
        <wsse:Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText">secret123</wsse:Password>
    </wsse:UsernameToken>"#;
    let body = wrap_soap(ut);
    let mut ctx = make_ctx_with_soap_body(&body);
    let mut headers = soap_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(is_reject(&result));
    assert_eq!(reject_status(&result), 401);
    assert!(
        reject_body(&result).contains("Password Type does not match"),
        "expected password-type-mismatch rejection, got: {}",
        reject_body(&result)
    );
}

#[tokio::test]
async fn test_password_text_config_rejects_passworddigest_type() {
    // finding #19 (converse): a PasswordText-configured plugin must reject a
    // wire Type of PasswordDigest rather than silently switching verification
    // modes based on the attacker-supplied attribute.
    let plugin = SoapWsSecurity::new(&username_token_config()).unwrap();
    let ut = r#"<wsse:UsernameToken>
        <wsse:Username>alice</wsse:Username>
        <wsse:Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest">secret123</wsse:Password>
    </wsse:UsernameToken>"#;
    let body = wrap_soap(ut);
    let mut ctx = make_ctx_with_soap_body(&body);
    let mut headers = soap_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(is_reject(&result));
    assert_eq!(reject_status(&result), 401);
    assert!(
        reject_body(&result).contains("Password Type does not match"),
        "expected password-type-mismatch rejection, got: {}",
        reject_body(&result)
    );
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
    assert_username_token_invalid_credentials(&result, &["eve", "alice"]);
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
async fn test_password_digest_valid_over_utf16le_wire_bytes() {
    let plugin = SoapWsSecurity::new(&username_token_digest_config()).unwrap();

    let nonce_bytes = b"utf16-nonce-bytes";
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
    let bytes = encode_utf16_le(&body);
    let mut ctx = make_ctx_with_soap_bytes(bytes, "application/soap+xml; charset=utf-16");
    let mut headers = soap_headers_with_content_type("application/soap+xml; charset=utf-16");
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(
        matches!(result, PluginResult::Continue),
        "UTF-16LE PasswordDigest should validate after decode, got {:?}",
        result
    );
    assert_eq!(ctx.metadata.get("soap_ws_username").unwrap(), "alice");
}

#[tokio::test]
async fn test_password_digest_wrong_password_rejects() {
    let plugin = SoapWsSecurity::new(&username_token_digest_config()).unwrap();
    let ut = password_digest_token("alice", "wrongpassword", b"wrong-nonce-test");
    let body = wrap_soap(&ut);
    let mut ctx = make_ctx_with_soap_body(&body);
    let mut headers = soap_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_username_token_invalid_credentials(&result, &["alice"]);
}

#[tokio::test]
async fn test_username_token_credential_failures_are_indistinguishable() {
    // GHSA-jp56-p5h6-f45q / issue #2642: unknown user, wrong PasswordText, and
    // wrong PasswordDigest must expose identical public status/headers/body and
    // must not echo the attacker-supplied candidate username.
    let text_plugin = SoapWsSecurity::new(&username_token_config()).unwrap();
    let digest_plugin = SoapWsSecurity::new(&username_token_digest_config()).unwrap();

    let unknown_text = r#"<wsse:UsernameToken>
        <wsse:Username>eve-candidate</wsse:Username>
        <wsse:Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText">anything</wsse:Password>
    </wsse:UsernameToken>"#;
    let wrong_text = r#"<wsse:UsernameToken>
        <wsse:Username>alice</wsse:Username>
        <wsse:Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText">wrongpass</wsse:Password>
    </wsse:UsernameToken>"#;
    let wrong_digest = password_digest_token("alice", "wrongpassword", b"oracle-digest-nonce");
    let unknown_digest =
        password_digest_token("eve-candidate", "anything", b"oracle-unknown-digest");

    let mut outcomes = Vec::new();
    for (plugin, token) in [
        (&text_plugin, unknown_text.to_string()),
        (&text_plugin, wrong_text.to_string()),
        (&digest_plugin, wrong_digest),
        (&digest_plugin, unknown_digest),
    ] {
        let body = wrap_soap(&token);
        let mut ctx = make_ctx_with_soap_body(&body);
        let mut headers = soap_headers();
        let result = plugin.before_proxy(&mut ctx, &mut headers).await;
        assert_username_token_invalid_credentials(&result, &["eve-candidate", "alice"]);
        outcomes.push((
            reject_status(&result),
            reject_body(&result).to_string(),
            reject_headers(&result).clone(),
        ));
    }

    let (status0, body0, headers0) = &outcomes[0];
    for (idx, (status, body, headers)) in outcomes.iter().enumerate().skip(1) {
        assert_eq!(status, status0, "status mismatch at outcome {}", idx);
        assert_eq!(body, body0, "body mismatch at outcome {}", idx);
        assert_eq!(headers, headers0, "headers mismatch at outcome {}", idx);
    }
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

#[tokio::test]
async fn test_username_token_missing_token_is_structural() {
    // Security header present but no UsernameToken: fail closed as structural,
    // not as the generic invalid-credential body.
    let plugin = SoapWsSecurity::new(&username_token_config()).unwrap();
    let body = wrap_soap("");
    let mut ctx = make_ctx_with_soap_body(&body);
    let mut headers = soap_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_username_token_structural(&result, "missing UsernameToken", &["alice", "eve"]);
}

#[tokio::test]
async fn test_username_token_empty_password_element_is_structural() {
    // Self-closing Password has no text content and must fail closed before any
    // known/unknown credential comparison.
    let plugin = SoapWsSecurity::new(&username_token_config()).unwrap();
    let ut = r#"<wsse:UsernameToken>
        <wsse:Username>alice</wsse:Username>
        <wsse:Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText"/>
    </wsse:UsernameToken>"#;
    let body = wrap_soap(ut);
    let mut ctx = make_ctx_with_soap_body(&body);
    let mut headers = soap_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_username_token_structural(&result, "Password element has no content", &["alice"]);
}

#[tokio::test]
async fn test_password_digest_invalid_nonce_base64_is_structural() {
    let plugin = SoapWsSecurity::new(&username_token_digest_config()).unwrap();
    let ut = r#"<wsse:UsernameToken>
        <wsse:Username>alice</wsse:Username>
        <wsse:Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest">dGVzdA==</wsse:Password>
        <wsse:Nonce>!!!not-valid-base64!!!</wsse:Nonce>
        <wsu:Created>2026-01-01T00:00:00Z</wsu:Created>
    </wsse:UsernameToken>"#;
    let body = wrap_soap(ut);
    let mut ctx = make_ctx_with_soap_body(&body);
    let mut headers = soap_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_username_token_structural(&result, "invalid Nonce base64 encoding", &["alice"]);
}

#[tokio::test]
async fn test_password_digest_missing_created_is_structural_for_known_and_unknown() {
    // Nonce/Created structural checks run before the known/unknown credential
    // branch so a missing Created cannot become a username oracle.
    let plugin = SoapWsSecurity::new(&username_token_digest_config()).unwrap();
    let mut bodies = Vec::new();
    for username in ["alice", "eve-candidate"] {
        let ut = format!(
            r#"<wsse:UsernameToken>
        <wsse:Username>{}</wsse:Username>
        <wsse:Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest">dGVzdA==</wsse:Password>
        <wsse:Nonce>dGVzdC1ub25jZQ==</wsse:Nonce>
    </wsse:UsernameToken>"#,
            username
        );
        let body = wrap_soap(&ut);
        let mut ctx = make_ctx_with_soap_body(&body);
        let mut headers = soap_headers();
        let result = plugin.before_proxy(&mut ctx, &mut headers).await;
        assert_username_token_structural(
            &result,
            "PasswordDigest requires Created",
            &["alice", "eve-candidate"],
        );
        bodies.push(reject_body(&result).to_string());
    }
    assert_eq!(
        bodies[0], bodies[1],
        "known and unknown principals must share the same missing-Created structural body"
    );
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

#[tokio::test]
async fn failed_digest_attempts_do_not_poison_a_valid_principals_nonce() {
    // Failed pre-auth attempts must do the dummy digest work but must not
    // reserve the nonce. Otherwise an attacker can race either an unknown
    // username or a known username with a wrong digest ahead of the victim.
    for (attempt_username, attempt_password, nonce_bytes) in [
        ("eve-candidate", "anything", b"unknown-user-race".as_slice()),
        ("alice", "wrongpassword", b"wrong-password-race".as_slice()),
    ] {
        let plugin = SoapWsSecurity::new(&username_token_digest_config()).unwrap();
        let created = chrono::Utc::now()
            .format("%Y-%m-%dT%H:%M:%S%.3fZ")
            .to_string();

        let failed_token = password_digest_token_with_created(
            attempt_username,
            attempt_password,
            nonce_bytes,
            &created,
        );
        let failed_body = wrap_soap(&failed_token);
        let mut failed_ctx = make_ctx_with_soap_body(&failed_body);
        let mut failed_headers = soap_headers();
        let failed = plugin
            .before_proxy(&mut failed_ctx, &mut failed_headers)
            .await;
        assert_username_token_invalid_credentials(
            &failed,
            &[attempt_username, "alice", "eve-candidate"],
        );

        let valid_token =
            password_digest_token_with_created("alice", "secret123", nonce_bytes, &created);
        let valid_body = wrap_soap(&valid_token);
        let mut valid_ctx = make_ctx_with_soap_body(&valid_body);
        let mut valid_headers = soap_headers();
        let valid = plugin
            .before_proxy(&mut valid_ctx, &mut valid_headers)
            .await;
        assert!(
            matches!(valid, PluginResult::Continue),
            "failed attempt for {attempt_username} poisoned the legitimate nonce: {valid:?}"
        );

        let mut replay_ctx = make_ctx_with_soap_body(&valid_body);
        let mut replay_headers = soap_headers();
        let replay = plugin
            .before_proxy(&mut replay_ctx, &mut replay_headers)
            .await;
        assert!(is_reject(&replay));
        assert!(reject_body(&replay).contains("nonce replay"));
    }
}

// ── SAML config tests ───────────────────────────────────────────────────────
//
// SAML assertions are cryptographically verified before any other field is
// trusted. The verifier:
//   1. Locates `<Signature>` inside the assertion.
//   2. Confirms the signing cert (from `KeyInfo/X509Data/X509Certificate`)
//      matches one of `saml.trusted_signing_certs` by SHA-256 fingerprint.
//   3. Applies the declared enveloped-signature and exclusive-c14n transforms
//      before verifying each `<Reference>` digest.
//   4. Verifies `<SignatureValue>` over exclusive-canonicalized `<SignedInfo>`
//      using the cert's public key.
//   5. THEN checks Issuer / NotBefore / NotOnOrAfter / Audience.
//
// Tests below construct SAML assertions and sign them with a bundled test
// RSA keypair so every signature path is exercised end-to-end.

#[test]
fn test_saml_enabled_without_trusted_issuers_is_error() {
    let config = json!({
        "timestamp": { "require": false },
        "saml": {
            "enabled": true,
            "trusted_issuers": [],
            "trusted_signing_certs": []
        }
    });
    let err = SoapWsSecurity::new(&config)
        .err()
        .expect("saml.enabled must require trusted_issuers");
    assert!(err.contains("no trusted_issuers"), "got: {err}");
}

#[test]
fn test_saml_enabled_without_trusted_signing_certs_is_error() {
    let config = json!({
        "timestamp": { "require": false },
        "saml": {
            "enabled": true,
            "trusted_issuers": ["https://idp.example.com"],
            "trusted_signing_certs": []
        }
    });
    let err = SoapWsSecurity::new(&config)
        .err()
        .expect("saml.enabled must require trusted_signing_certs");
    assert!(err.contains("no trusted_signing_certs"), "got: {err}");
}

#[test]
fn test_saml_disabled_construction_still_succeeds() {
    // Disabled SAML config alongside another feature still constructs cleanly.
    let config = json!({
        "timestamp": { "require": true },
        "saml": { "enabled": false }
    });
    assert!(SoapWsSecurity::new(&config).is_ok());
}

#[test]
fn test_saml_unreadable_signing_cert_is_error() {
    let config = json!({
        "timestamp": { "require": false },
        "saml": {
            "enabled": true,
            "trusted_issuers": ["https://idp.example.com"],
            "trusted_signing_certs": ["/nonexistent/path/to/cert.pem"]
        }
    });
    let err = SoapWsSecurity::new(&config)
        .err()
        .expect("missing trusted signing cert must fail construction");
    assert!(
        err.contains("failed to load SAML trusted signing cert"),
        "got: {err}"
    );
}

// ── SAML signature verification tests ───────────────────────────────────────
//
// `tests::saml_fixtures` writes the bundled test IDP cert+key to a temp dir
// and lets each test load it the same way an operator would (a path on disk).

mod saml_fixtures {
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD as B64;
    use ring::rand::SystemRandom;
    use ring::signature::{RSA_PKCS1_SHA256, RsaKeyPair};
    use std::path::PathBuf;
    use tempfile::TempDir;

    // ────────────────────────────────────────────────────────────────────
    // DO NOT USE IN PRODUCTION.
    // The RSA private keys below are committed test fixtures generated for
    // the SOAP WS-Security SAML signature tests. Anyone reading them has
    // the corresponding private key — they MUST NOT appear in any operator
    // config, any deployed IdP signing cert list, or any production
    // trusted_signing_certs path. They live in the test crate and are not
    // linked into the `ferrum-edge` production binary.
    // ────────────────────────────────────────────────────────────────────

    // 2048-bit RSA test key (PKCS#8 DER, base64) — committed test fixture,
    // never used outside this test suite. Generated with:
    //   openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048
    pub const TEST_IDP_KEY_PKCS8_B64: &str = "\
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCnAFvS4Ts5L4nl\
GC7XVelbsO/DmJS/MWlGzgWws5Lo4H72W1pCclOF7nvMBvHsiTiM6l+30bU3oI3c\
RwQJux6haITy484hUQEJRVu2a5bUrkCQCpZSKwfhM5OSEiw2qDYci7QB0aoqUFR3\
2dXPAyNZ5bBWRo/SsTHtkwnAoj2CE8ngq3ESvgk56OKVtP6brk/xBm/Pk3413daB\
byUUGbFFaB1vaNVL6nMjUtbqF2b9zc51eR6Y0LiXNY3NOMoEwS9M+35zEuPRswxT\
vdM46lQys5au4fQj/pWzZbHx1LNUt6MHsrDxbCQyN5juBG+LzGaOhgahfaVo5GEh\
sCV6a5dHAgMBAAECggEAEdCA+xLZrXT7wbt9q6zXcteCDBxnqamMsGfjxYCyaDMi\
eAcwrqvhawUQoagQAIp2xNlvkn1FVoTC/T96F8ulLdSncf2JDJbGhIWojeIWOePI\
sVTfyi4a7hQBZvCXVNFGzG6+qf8Cpvbgu9Q58ZZFHB7bW6i1SOVsDQrFXI4x/4EO\
x1SnXlkL/Rpv4NgB1NzYhPFnKWe6CSfyvGaNU1fr1HYAvnXtknLpaHTKEYTTOYRr\
dXyn/NGCU2xhE7Dwc8lXaIDrc1DCzpiZV8DJ23zgeNSj7GyKX4gKP3MG9SFK2p0I\
jbmLYXjsm2imcfOyLo2Z2rPqpxOfkOY8A2igsSKgIQKBgQDQ6pxj8mECrqtd4XId\
IRpjVUhz8ABnPzHnEDVvZzNeZmq5lCRt3PKCA1RbRSxkLaMa0vxn8hQPjX+1/gn9\
tAabrIBHi5saXUuU5HwtPxMvPPzeZkFXbHjfX/ThnsRvKijHBdc4aVGF0RX/ItGr\
kpJgAw470GUN4jd0lE7GM2360QKBgQDMo3fdTXZRDpynaIByySxHplPlbudLzvDt\
tVynXINWaLfYERJhx8mNLfmhUDkqDj+J2z3b1p2jnvEJbMBstubqIB8Vf93NNp0m\
yamov7MvvILzRhVuwg2l8IYlv+vU2XPBblq3Xk+jrUnQL9If1xstiEpfThn/GceD\
JAFkMV/GlwKBgFpUFipgsfEm9JEy2NQfa/lm9lyqeIIroLf3GiOAy4UVYy+6DcYy\
sefk6KRN1FO8J7mBYADRejr/Qyi9HjTDkdfdTdmhUv6jN/q4j7hAfVr/U5YVQEs8\
a0aphofGzcgCwn7K17NcVhM1w/z8YQt95Cv/JjhWclr+ZFvTg/vOYM8BAoGBAMOe\
IB70xX2Gskl1pBQWKrXzUY+pDIFzOOyCyidSUFpxkAyDhUbjbNAAevixb3O8WxC0\
+9UCu36FmXSg+PDzhpmYSx6KNMTOyDsj24LsfaXMVoGnJSXTaqiN3C6J4C6AEB+A\
FkfjZ83XARB6Jis5vUkxV6bzSfaJ9iZubMYSTLPRAoGBAMk48YTI1qzabQAkZVQg\
7eAq5OOOOZEPh9QTcTJWRzyDYT9H+S9C6nZ3D1ztfwt27DQrRCQn/JUX1/OWDD/5\
V4CKFQiVEz0CeB2/ZWvXMy8fRr59Mam4/ud+M0UF3ZtEizIvolKiElZobVGCRj91\
fkToWGXpRwg0Bav/16XULUNu";

    // Matching self-signed X.509 certificate (PEM). CN=ferrum-test-saml-idp,
    // 10-year validity. Operators in tests load the file path to mirror the
    // production code path.
    pub const TEST_IDP_CERT_PEM: &str = "\
-----BEGIN CERTIFICATE-----
MIIDHzCCAgegAwIBAgIUYSizg6IjbHWwMlIcmMfy6Cp6qLUwDQYJKoZIhvcNAQEL
BQAwHzEdMBsGA1UEAwwUZmVycnVtLXRlc3Qtc2FtbC1pZHAwHhcNMjYwNTE4MDgw
NjEyWhcNMzYwNTE1MDgwNjEyWjAfMR0wGwYDVQQDDBRmZXJydW0tdGVzdC1zYW1s
LWlkcDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKcAW9LhOzkvieUY
LtdV6Vuw78OYlL8xaUbOBbCzkujgfvZbWkJyU4Xue8wG8eyJOIzqX7fRtTegjdxH
BAm7HqFohPLjziFRAQlFW7ZrltSuQJAKllIrB+Ezk5ISLDaoNhyLtAHRqipQVHfZ
1c8DI1nlsFZGj9KxMe2TCcCiPYITyeCrcRK+CTno4pW0/puuT/EGb8+TfjXd1oFv
JRQZsUVoHW9o1UvqcyNS1uoXZv3NznV5HpjQuJc1jc04ygTBL0z7fnMS49GzDFO9
0zjqVDKzlq7h9CP+lbNlsfHUs1S3oweysPFsJDI3mO4Eb4vMZo6GBqF9pWjkYSGw
JXprl0cCAwEAAaNTMFEwHQYDVR0OBBYEFH4oqBABlq3HGxerUxsspSs++7siMB8G
A1UdIwQYMBaAFH4oqBABlq3HGxerUxsspSs++7siMA8GA1UdEwEB/wQFMAMBAf8w
DQYJKoZIhvcNAQELBQADggEBAIORtR6MY7nWEfwab/vgdzIA/EWiZ+auAPyBuKaS
bayLTEQvL6Ev/BUB6Pi9h/PBZ4agNtgX+E7vIdq9B2Qcp9jKyXvlaHIYLObHTTjp
0e8Qk+IzS+bRZpQZh7MSz4UVsargU8M8sGiVkXxe8WfhHu4tQ7rpBx0UhanX10GC
v7HWtLj09+I5gu3XZ9vYoVqDRFzLJFqZSwSy4xlROVhG9oil4nCDemREOQJX6zUa
VGcUUl86na4jECXuKaBn4sAwOQDG+LUaumQ6XcrTSJ2Zv3jYRSNwPhHocMoPLCX6
wupTEoP8ySU223pQqBOX1E1WVEDcYuvNI+9KTJQUCYlw9bU=
-----END CERTIFICATE-----
";

    /// A second untrusted RSA keypair + cert. Used to drive
    /// "signing cert is not in the trust list" assertions.
    ///
    /// DO NOT USE IN PRODUCTION — same warning as `TEST_IDP_KEY_PKCS8_B64`.
    pub const UNTRUSTED_IDP_KEY_PKCS8_B64: &str = "\
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCdBCN5lkzAC6gM\
1JA0/uqZd2efAVyJf6xtVQyCOrjryP313oR4kHJy1mbxTSvUM+cIXqLL2ZLsh3HX\
qJ2j9a6EGl5pnXdix2EPEBY3BAJQxsfO2P53Dwcjx/MpFcYhFqkSFmLy00v4UdbZ\
ayNCITwfWN7QDDj7N6VtOwIDGpQSFi0FAZcGi20YmWvCk/055LiJxSv4jalHGVg+\
/cDkSVCY67D5rutqMrS3NdEDMmVrtJTSLhYse4NbdLF2QVSyrasmKkmMkSqFojnw\
q4IJSwDbFsCOKSaAy9oDn4Ekgwt+cBgmOtioq4sFTtI9i5fKZJ7hpi62vqPRKtOC\
3L24hAIBAgMBAAECggEAGiKQtxHF56dpCu2srS2LJg1Ccax71yUpsa8Y3Gpi0lhL\
sUue+CRu8F9wlhSWyYT0HSgHZ+/orTckQ1W9G4fuyu1KrsC3mPj/1k6CrBiePAzC\
QFNNE8ssEJAdEMcfie1oKesRAEMcX5JbtSfIoB7BD6SuvalzKJmMDwDl5ldbsyC8\
Dl5Utgr4K+wgPxqcor3dxLU8kCdIvxzFdaXLxJPK4/KrKSUK+qvIId/D2zh0jvm5\
bFLTAVdvPiniWKdM3kqa7G4HfJFLBU/GrooL/s47NwsFo9k4JylSusE2jAfJQltk\
d6ZBctYwCPHowT+SlG6WXafNKQxSHKVXanHihXjEmwKBgQDM2/QARyfTp9fFQAAm\
arr6Wzj7N6Aw2c2Ea9vXl040gwKdpUvnQONxPZnFvrOrY4cUEfzcqASfg8Nghn7A\
Iu5vHL7iN7g9jiW5tShtb0h/TL/eshXPZlD6IzXKGE5wu/oNBcctxLLqp95XZDzc\
APCL0WANdNvrTjAHLUp2PHgSuwKBgQDENqfId6eyw9BxaJENci7b0fFpvIHrURBY\
pLf3oX/PVvxUEgDAyqhFNT/2T5+NQbnp+tg2/aF7enOYYkG3pNhmGi1AMkXEk3KA\
89vq5Au6fpk7yrZrPeHFskC7oUQZKpKzsiu2aT4PMHDfx9/7C236QJQqRcgguMfx\
FA24rH1IcwKBgDt0KmBaRki7EXgBlwmPOCyohOUDw83pqCeiVe8/zkaXLw8phdnb\
jyayRgqJygMXo4BDqCsx6AWTbAR7hBWnDaPZp9xnZ2UV+ATpeo4oGdY4JAcxj/rd\
KusthNLeMwWsyGk3IBM8XuCTT4f1Y2RGMYmifknpfFnSG0Y58r5V1lM5AoGBAIGT\
EmQZWJ5+H5X1Fu1JPVafIwzPlwBeTSwswux+M1gqOoIOTX8DlfH2Q2IWnOf8wpiY\
tdZC0jQn3lSAdqOe8eUjXkSprlcthA1SfSV2KaSj2++XY7YYbJNQrtz5l24DJlQS\
0jko8Pm45KFzbh9sIdmEchQkdw/c1vUGaDVPe4CvAoGAJaXKVoH7oZd8K7/BVrmp\
U1Oqwnm19SiSVKRTkj1SH+YQdfK9Ew8OqC68YXd46JcN6mdWESEicWb7AtFT4eOP\
MoBlGGmQjV2L06HsoDiLTG5RKcloqBWTzM9AplJT9pMgoM+J/stXa0AIuqOGS0Z9\
Wgj5Rnm3QRZWXCPzHCC231g=";

    pub const UNTRUSTED_IDP_CERT_PEM: &str = "\
-----BEGIN CERTIFICATE-----
MIIDITCCAgmgAwIBAgIUVUiKUdYC97nzeC35QDdMDIZBmEUwDQYJKoZIhvcNAQEL
BQAwIDEeMBwGA1UEAwwVZmVycnVtLXVudHJ1c3RlZC1zYW1sMB4XDTI2MDUxODA4
MTg1MFoXDTM2MDUxNTA4MTg1MFowIDEeMBwGA1UEAwwVZmVycnVtLXVudHJ1c3Rl
ZC1zYW1sMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnQQjeZZMwAuo
DNSQNP7qmXdnnwFciX+sbVUMgjq468j99d6EeJByctZm8U0r1DPnCF6iy9mS7Idx
16ido/WuhBpeaZ13YsdhDxAWNwQCUMbHztj+dw8HI8fzKRXGIRapEhZi8tNL+FHW
2WsjQiE8H1je0Aw4+zelbTsCAxqUEhYtBQGXBottGJlrwpP9OeS4icUr+I2pRxlY
Pv3A5ElQmOuw+a7rajK0tzXRAzJla7SU0i4WLHuDW3SxdkFUsq2rJipJjJEqhaI5
8KuCCUsA2xbAjikmgMvaA5+BJIMLfnAYJjrYqKuLBU7SPYuXymSe4aYutr6j0SrT
gty9uIQCAQIDAQABo1MwUTAdBgNVHQ4EFgQU6VLraFIn4HTB/6dnya9/ZBIgGHAw
HwYDVR0jBBgwFoAU6VLraFIn4HTB/6dnya9/ZBIgGHAwDwYDVR0TAQH/BAUwAwEB
/zANBgkqhkiG9w0BAQsFAAOCAQEAMMKIxW0XuCDFnu6daoD7l8se2/nxsS/vyJv3
4hjiH/1L7d2PdnPy80bMaTKwdxd8Fnca4cZh0Vy7Eiom53Fj994UmeOkfyobBOv5
E2OkFXcDHpbQyggGwE1oUp9PUPkEAa0pVfbAxl50ObOtfBf3xtjxJ2TFWR9vh+51
fcDotZi5I30E/Q+d27JhRccjR+j7itAUQikkvGbeUcNsMzu3MHg6g210UWWc9Qff
mM1FlqKLfE2mDF3E31qqiqco5N1HgyU1PII+BBO6RrjOJQDVuloxecRFuBStykUq
RiLyj1MbQGDtoeJVlV4qwHDVyoumjb4+S0KQL68geIlE70lPpQ==
-----END CERTIFICATE-----
";

    /// A temp-dir bundle: the trusted IDP cert PEM is written to disk so the
    /// plugin can be configured with a real file path, matching production
    /// deployments.
    pub struct IdpBundle {
        pub _tempdir: TempDir,
        pub trusted_cert_path: PathBuf,
    }

    impl IdpBundle {
        pub fn new() -> Self {
            let dir = tempfile::tempdir().expect("create tempdir");
            let trusted = dir.path().join("trusted-idp.pem");
            std::fs::write(&trusted, TEST_IDP_CERT_PEM).expect("write trusted PEM");
            IdpBundle {
                _tempdir: dir,
                trusted_cert_path: trusted,
            }
        }
    }

    fn decode_b64(s: &str) -> Vec<u8> {
        B64.decode(s.as_bytes())
            .expect("test fixture is valid base64")
    }

    fn pem_to_der_b64(pem: &str) -> String {
        pem.lines()
            .filter(|l| !l.starts_with("-----"))
            .collect::<String>()
    }

    pub struct AssertionBuilder<'a> {
        pub assertion_id: &'a str,
        pub issuer: &'a str,
        pub subject_name_id: &'a str,
        pub not_before: Option<&'a str>,
        pub not_on_or_after: Option<&'a str>,
        pub audience: Option<&'a str>,
        pub sign_with_untrusted_key: bool,
        pub use_sha1_digest: bool,
        /// Insert junk bytes into the assertion AFTER signing to simulate a
        /// tampered payload.
        pub corrupt_subject_after_signing: bool,
        /// Mutate the SignatureValue bytes after signing to simulate a
        /// forged or randomly damaged signature.
        pub corrupt_signature_value: bool,
    }

    impl<'a> AssertionBuilder<'a> {
        pub fn new(assertion_id: &'a str, issuer: &'a str, subject_name_id: &'a str) -> Self {
            Self {
                assertion_id,
                issuer,
                subject_name_id,
                not_before: None,
                not_on_or_after: None,
                audience: None,
                sign_with_untrusted_key: false,
                use_sha1_digest: false,
                corrupt_subject_after_signing: false,
                corrupt_signature_value: false,
            }
        }

        pub fn build(self) -> String {
            // Body of the assertion that lives OUTSIDE the Signature
            // element. Anything in here is part of the digested content
            // (after envelope-signature transform removes the Signature).
            let mut conditions = String::new();
            if self.not_before.is_some()
                || self.not_on_or_after.is_some()
                || self.audience.is_some()
            {
                conditions.push_str("<Conditions");
                if let Some(nb) = self.not_before {
                    conditions.push_str(&format!(" NotBefore=\"{}\"", nb));
                }
                if let Some(noa) = self.not_on_or_after {
                    conditions.push_str(&format!(" NotOnOrAfter=\"{}\"", noa));
                }
                if let Some(aud) = self.audience {
                    conditions.push_str(&format!(
                        "><AudienceRestriction><Audience>{}</Audience></AudienceRestriction></Conditions>",
                        aud
                    ));
                } else {
                    conditions.push_str("/>");
                }
            }

            let subject_inner = if self.corrupt_subject_after_signing {
                // Final subject text differs from what was signed — should
                // make the assertion's digest mismatch what's in SignedInfo.
                format!("evil-{}", self.subject_name_id)
            } else {
                self.subject_name_id.to_string()
            };

            let body_after_issuer = format!(
                "<Subject><NameID>{}</NameID></Subject>{}",
                subject_inner, conditions
            );

            // The bytes we actually sign use the ORIGINAL (untampered) subject.
            let signed_body_after_issuer = format!(
                "<Subject><NameID>{}</NameID></Subject>{}",
                self.subject_name_id, conditions
            );

            // The assertion as it looks after enveloped-signature transform —
            // this is what XMLDSIG digests for the Reference.
            let assertion_no_sig = format!(
                "<Assertion ID=\"{}\"><Issuer>{}</Issuer>{}</Assertion>",
                self.assertion_id, self.issuer, signed_body_after_issuer
            );
            let canonical_assertion = super::soap_exclusive_canonicalize_element_for_test(
                &assertion_no_sig,
                "Assertion",
                "",
            )
            .expect("test assertion must canonicalize");

            let (digest_method_uri, asserted_digest) = if self.use_sha1_digest {
                (
                    "http://www.w3.org/2000/09/xmldsig#sha1",
                    ring::digest::digest(
                        &ring::digest::SHA1_FOR_LEGACY_USE_ONLY,
                        canonical_assertion.as_bytes(),
                    ),
                )
            } else {
                (
                    "http://www.w3.org/2001/04/xmlenc#sha256",
                    ring::digest::digest(&ring::digest::SHA256, canonical_assertion.as_bytes()),
                )
            };
            let digest_b64 = B64.encode(asserted_digest.as_ref());

            // SignedInfo bytes — exactly these bytes are what
            // `<SignatureValue>` covers.
            let signed_info = format!(
                "<SignedInfo>\
<CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\
<SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256\"/>\
<Reference URI=\"#{}\">\
<Transforms>\
<Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/>\
<Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\
</Transforms>\
<DigestMethod Algorithm=\"{}\"/>\
<DigestValue>{}</DigestValue>\
</Reference>\
</SignedInfo>",
                self.assertion_id, digest_method_uri, digest_b64
            );
            let canonical_signed_info =
                super::soap_exclusive_canonicalize_element_for_test(&signed_info, "SignedInfo", "")
                    .expect("test SignedInfo must canonicalize");

            // Pick the signing key + matching cert.
            let (key_pkcs8_b64, cert_pem) = if self.sign_with_untrusted_key {
                (UNTRUSTED_IDP_KEY_PKCS8_B64, UNTRUSTED_IDP_CERT_PEM)
            } else {
                (TEST_IDP_KEY_PKCS8_B64, TEST_IDP_CERT_PEM)
            };

            let pkcs8 = decode_b64(key_pkcs8_b64);
            let key_pair =
                RsaKeyPair::from_pkcs8(&pkcs8).expect("test fixture RSA key is valid PKCS#8");
            let mut sig_bytes = vec![0u8; key_pair.public().modulus_len()];
            let rng = SystemRandom::new();
            key_pair
                .sign(
                    &RSA_PKCS1_SHA256,
                    &rng,
                    canonical_signed_info.as_bytes(),
                    &mut sig_bytes,
                )
                .expect("test signing must succeed");
            if self.corrupt_signature_value {
                // Flip a byte in the middle of the signature.
                let mid = sig_bytes.len() / 2;
                sig_bytes[mid] ^= 0xFF;
            }
            let sig_value_b64 = B64.encode(&sig_bytes);
            let cert_b64 = pem_to_der_b64(cert_pem);

            let signature = format!(
                "<Signature>{}<SignatureValue>{}</SignatureValue>\
<KeyInfo><X509Data><X509Certificate>{}</X509Certificate></X509Data></KeyInfo>\
</Signature>",
                signed_info, sig_value_b64, cert_b64
            );

            // Final assertion: Signature follows Issuer, then the body
            // (Subject + Conditions). Envelope-signature transform at
            // verification time removes the first <Signature> element, so
            // the digested view matches `assertion_no_sig`.
            format!(
                "<Assertion ID=\"{}\"><Issuer>{}</Issuer>{}{}</Assertion>",
                self.assertion_id, self.issuer, signature, body_after_issuer
            )
        }
    }
}

fn saml_config(bundle: &saml_fixtures::IdpBundle, audience: Option<&str>) -> serde_json::Value {
    let mut saml = serde_json::Map::new();
    saml.insert("enabled".into(), json!(true));
    saml.insert(
        "trusted_issuers".into(),
        json!(["https://idp.example.com/metadata"]),
    );
    saml.insert(
        "trusted_signing_certs".into(),
        json!([bundle.trusted_cert_path.to_str().unwrap()]),
    );
    if let Some(aud) = audience {
        saml.insert("audience".into(), json!(aud));
    }
    json!({
        "timestamp": { "require": false },
        "saml": Value::Object(saml),
        "reject_missing_security_header": true
    })
}

fn wrap_saml_assertion(assertion_xml: &str) -> String {
    wrap_soap(assertion_xml)
}

fn far_future() -> String {
    (chrono::Utc::now() + chrono::Duration::days(7))
        .format("%Y-%m-%dT%H:%M:%SZ")
        .to_string()
}

fn long_past() -> String {
    (chrono::Utc::now() - chrono::Duration::days(7))
        .format("%Y-%m-%dT%H:%M:%SZ")
        .to_string()
}

#[tokio::test]
async fn test_saml_valid_signed_assertion_accepted() {
    let bundle = saml_fixtures::IdpBundle::new();
    let plugin = SoapWsSecurity::new(&saml_config(&bundle, None)).unwrap();

    let assertion = saml_fixtures::AssertionBuilder::new(
        "_assertion-001",
        "https://idp.example.com/metadata",
        "alice@example.com",
    )
    .build();

    let body = wrap_saml_assertion(&assertion);
    let mut ctx = make_ctx_with_soap_body(&body);
    let mut headers = soap_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(
        matches!(result, PluginResult::Continue),
        "valid signed SAML should pass, got {:?}",
        result
    );
    assert_eq!(
        ctx.metadata.get("soap_ws_saml_subject").map(String::as_str),
        Some("alice@example.com"),
        "Subject NameID must be exported as metadata"
    );
}

#[tokio::test]
async fn test_saml_valid_signed_assertion_accepted_over_utf16le() {
    let bundle = saml_fixtures::IdpBundle::new();
    let plugin = SoapWsSecurity::new(&saml_config(&bundle, None)).unwrap();

    let assertion = saml_fixtures::AssertionBuilder::new(
        "_assertion-utf16",
        "https://idp.example.com/metadata",
        "alice@example.com",
    )
    .build();

    let body = wrap_saml_assertion(&assertion);
    let bytes = encode_utf16_le(&body);
    let mut ctx = make_ctx_with_soap_bytes(bytes, "application/soap+xml; charset=utf-16");
    let mut headers = soap_headers_with_content_type("application/soap+xml; charset=utf-16");
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(
        matches!(result, PluginResult::Continue),
        "UTF-16LE signed SAML should validate after decode, got {:?}",
        result
    );
    assert_eq!(
        ctx.metadata.get("soap_ws_saml_subject").map(String::as_str),
        Some("alice@example.com"),
        "Subject NameID must be exported as metadata after UTF-16 decode"
    );
}

#[tokio::test]
async fn test_saml_decodes_signed_authorization_fields_from_verified_dom() {
    let bundle = saml_fixtures::IdpBundle::new();
    let plugin = SoapWsSecurity::new(&saml_config(&bundle, None)).unwrap();

    let assertion = saml_fixtures::AssertionBuilder::new(
        "_assertion-entities",
        "https://idp.example.com&#x2f;metadata",
        "alice&#x40;example.com",
    )
    .build();
    let body = wrap_saml_assertion(&assertion);
    let mut ctx = make_ctx_with_soap_body(&body);
    let mut headers = soap_headers();

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;

    assert!(
        matches!(result, PluginResult::Continue),
        "signed entity-encoded SAML fields should pass, got {result:?}"
    );
    assert_eq!(
        ctx.metadata.get("soap_ws_saml_subject").map(String::as_str),
        Some("alice@example.com")
    );
}

#[tokio::test]
async fn test_saml_missing_signature_rejects() {
    let bundle = saml_fixtures::IdpBundle::new();
    let plugin = SoapWsSecurity::new(&saml_config(&bundle, None)).unwrap();

    // Assertion with no Signature element — i.e. exactly the spoofable XML
    // the previous behaviour silently accepted.
    let unsigned = r#"<Assertion ID="_a"><Issuer>https://idp.example.com/metadata</Issuer><Subject><NameID>alice</NameID></Subject></Assertion>"#;
    let body = wrap_saml_assertion(unsigned);
    let mut ctx = make_ctx_with_soap_body(&body);
    let mut headers = soap_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(is_reject(&result));
    assert!(
        reject_body(&result).contains("missing Signature"),
        "expected missing Signature rejection, got: {}",
        reject_body(&result)
    );
}

#[tokio::test]
async fn test_saml_tampered_assertion_rejects() {
    let bundle = saml_fixtures::IdpBundle::new();
    let plugin = SoapWsSecurity::new(&saml_config(&bundle, None)).unwrap();

    let mut builder = saml_fixtures::AssertionBuilder::new(
        "_assertion-tamper",
        "https://idp.example.com/metadata",
        "alice@example.com",
    );
    builder.corrupt_subject_after_signing = true;
    let assertion = builder.build();

    let body = wrap_saml_assertion(&assertion);
    let mut ctx = make_ctx_with_soap_body(&body);
    let mut headers = soap_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(is_reject(&result));
    assert!(
        reject_body(&result).contains("digest mismatch"),
        "expected digest mismatch, got: {}",
        reject_body(&result)
    );
}

#[tokio::test]
async fn test_saml_corrupted_signature_rejects() {
    let bundle = saml_fixtures::IdpBundle::new();
    let plugin = SoapWsSecurity::new(&saml_config(&bundle, None)).unwrap();

    let mut builder = saml_fixtures::AssertionBuilder::new(
        "_assertion-corrupt",
        "https://idp.example.com/metadata",
        "alice@example.com",
    );
    builder.corrupt_signature_value = true;
    let assertion = builder.build();

    let body = wrap_saml_assertion(&assertion);
    let mut ctx = make_ctx_with_soap_body(&body);
    let mut headers = soap_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(is_reject(&result));
    assert!(
        reject_body(&result).contains("signature verification failed"),
        "expected signature verification failure, got: {}",
        reject_body(&result)
    );
}

#[tokio::test]
async fn test_saml_untrusted_signing_cert_rejects() {
    let bundle = saml_fixtures::IdpBundle::new();
    let plugin = SoapWsSecurity::new(&saml_config(&bundle, None)).unwrap();

    // Signed by a different (real, valid) keypair whose cert is NOT in
    // `trusted_signing_certs`. Signature math succeeds; trust check fails.
    let mut builder = saml_fixtures::AssertionBuilder::new(
        "_assertion-untrusted",
        "https://idp.example.com/metadata",
        "alice@example.com",
    );
    builder.sign_with_untrusted_key = true;
    let assertion = builder.build();

    let body = wrap_saml_assertion(&assertion);
    let mut ctx = make_ctx_with_soap_body(&body);
    let mut headers = soap_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(is_reject(&result));
    assert!(
        reject_body(&result).contains("signing certificate is not trusted"),
        "expected untrusted cert rejection, got: {}",
        reject_body(&result)
    );
}

#[tokio::test]
async fn test_saml_untrusted_issuer_rejects() {
    let bundle = saml_fixtures::IdpBundle::new();
    let plugin = SoapWsSecurity::new(&saml_config(&bundle, None)).unwrap();

    // Signature valid, but the (signed) Issuer string is not in the
    // configured trust list.
    let assertion = saml_fixtures::AssertionBuilder::new(
        "_assertion-bad-issuer",
        "https://attacker.example.com/idp",
        "alice@example.com",
    )
    .build();

    let body = wrap_saml_assertion(&assertion);
    let mut ctx = make_ctx_with_soap_body(&body);
    let mut headers = soap_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(is_reject(&result));
    assert!(
        reject_body(&result).contains("not trusted"),
        "expected untrusted issuer rejection, got: {}",
        reject_body(&result)
    );
}

#[tokio::test]
async fn test_saml_expired_assertion_rejects() {
    let bundle = saml_fixtures::IdpBundle::new();
    let plugin = SoapWsSecurity::new(&saml_config(&bundle, None)).unwrap();

    let nb = "2020-01-01T00:00:00Z";
    let noa = "2020-01-02T00:00:00Z";
    let mut builder = saml_fixtures::AssertionBuilder::new(
        "_assertion-expired",
        "https://idp.example.com/metadata",
        "alice@example.com",
    );
    builder.not_before = Some(nb);
    builder.not_on_or_after = Some(noa);
    let assertion = builder.build();

    let body = wrap_saml_assertion(&assertion);
    let mut ctx = make_ctx_with_soap_body(&body);
    let mut headers = soap_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(is_reject(&result));
    assert!(
        reject_body(&result).contains("expired"),
        "expected SAML expired rejection, got: {}",
        reject_body(&result)
    );
}

#[tokio::test]
async fn test_saml_not_yet_valid_rejects() {
    let bundle = saml_fixtures::IdpBundle::new();
    // Pull clock_skew_seconds down so the future NotBefore actually trips it.
    let cfg = {
        let mut v = saml_config(&bundle, None);
        v["saml"]["clock_skew_seconds"] = json!(5u64);
        v
    };
    let plugin = SoapWsSecurity::new(&cfg).unwrap();

    let nb = far_future();
    let mut builder = saml_fixtures::AssertionBuilder::new(
        "_assertion-future",
        "https://idp.example.com/metadata",
        "alice@example.com",
    );
    builder.not_before = Some(&nb);
    let assertion = builder.build();

    let body = wrap_saml_assertion(&assertion);
    let mut ctx = make_ctx_with_soap_body(&body);
    let mut headers = soap_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(is_reject(&result));
    assert!(
        reject_body(&result).contains("not yet valid"),
        "expected SAML not-yet-valid rejection, got: {}",
        reject_body(&result)
    );
}

#[tokio::test]
async fn test_saml_wrong_audience_rejects() {
    let bundle = saml_fixtures::IdpBundle::new();
    let plugin = SoapWsSecurity::new(&saml_config(
        &bundle,
        Some("https://my-service.example.com"),
    ))
    .unwrap();

    let mut builder = saml_fixtures::AssertionBuilder::new(
        "_assertion-aud",
        "https://idp.example.com/metadata",
        "alice@example.com",
    );
    let nb = long_past();
    let noa = far_future();
    builder.not_before = Some(&nb);
    builder.not_on_or_after = Some(&noa);
    builder.audience = Some("https://other-service.example.com");
    let assertion = builder.build();

    let body = wrap_saml_assertion(&assertion);
    let mut ctx = make_ctx_with_soap_body(&body);
    let mut headers = soap_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(is_reject(&result));
    assert!(
        reject_body(&result).contains("does not match expected"),
        "expected audience mismatch rejection, got: {}",
        reject_body(&result)
    );
}

#[tokio::test]
async fn test_saml_configured_audience_requires_conditions() {
    let bundle = saml_fixtures::IdpBundle::new();
    let plugin = SoapWsSecurity::new(&saml_config(
        &bundle,
        Some("https://my-service.example.com"),
    ))
    .unwrap();

    let assertion = saml_fixtures::AssertionBuilder::new(
        "_assertion-no-conditions",
        "https://idp.example.com/metadata",
        "alice@example.com",
    )
    .build();

    let body = wrap_saml_assertion(&assertion);
    let mut ctx = make_ctx_with_soap_body(&body);
    let mut headers = soap_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(is_reject(&result));
    assert!(
        reject_body(&result).contains("Conditions are required"),
        "expected missing Conditions rejection, got: {}",
        reject_body(&result)
    );
}

#[tokio::test]
async fn test_saml_configured_audience_requires_audience_restriction() {
    let bundle = saml_fixtures::IdpBundle::new();
    let plugin = SoapWsSecurity::new(&saml_config(
        &bundle,
        Some("https://my-service.example.com"),
    ))
    .unwrap();

    let nb = long_past();
    let noa = far_future();
    let mut builder = saml_fixtures::AssertionBuilder::new(
        "_assertion-no-audience-restriction",
        "https://idp.example.com/metadata",
        "alice@example.com",
    );
    builder.not_before = Some(&nb);
    builder.not_on_or_after = Some(&noa);
    let assertion = builder.build();

    let body = wrap_saml_assertion(&assertion);
    let mut ctx = make_ctx_with_soap_body(&body);
    let mut headers = soap_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(is_reject(&result));
    assert!(
        reject_body(&result).contains("AudienceRestriction is required"),
        "expected missing AudienceRestriction rejection, got: {}",
        reject_body(&result)
    );
}

#[tokio::test]
async fn test_saml_sha1_digest_rejected_by_default() {
    let bundle = saml_fixtures::IdpBundle::new();
    let plugin = SoapWsSecurity::new(&saml_config(&bundle, None)).unwrap();

    let mut builder = saml_fixtures::AssertionBuilder::new(
        "_assertion-sha1-digest",
        "https://idp.example.com/metadata",
        "alice@example.com",
    );
    builder.use_sha1_digest = true;
    let assertion = builder.build();

    let body = wrap_saml_assertion(&assertion);
    let mut ctx = make_ctx_with_soap_body(&body);
    let mut headers = soap_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(is_reject(&result));
    assert!(
        reject_body(&result).contains("digest algorithm")
            && reject_body(&result).contains("not allowed"),
        "expected SHA-1 digest rejection, got: {}",
        reject_body(&result)
    );
}

#[tokio::test]
async fn test_saml_signature_must_cover_enclosing_assertion() {
    // Reference URI that doesn't match the Assertion's ID must reject — an
    // attacker who can choose Reference URIs could otherwise point the
    // signature at a stable subtree they control.
    let bundle = saml_fixtures::IdpBundle::new();
    let plugin = SoapWsSecurity::new(&saml_config(&bundle, None)).unwrap();

    // Build a valid assertion, then surgically rewrite its Reference URI.
    let assertion = saml_fixtures::AssertionBuilder::new(
        "_assertion-real-id",
        "https://idp.example.com/metadata",
        "alice@example.com",
    )
    .build();
    let tampered = assertion.replace("URI=\"#_assertion-real-id\"", "URI=\"#somewhere-else\"");

    let body = wrap_saml_assertion(&tampered);
    let mut ctx = make_ctx_with_soap_body(&body);
    let mut headers = soap_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(is_reject(&result));
    assert!(
        reject_body(&result).contains("does not target Assertion ID"),
        "expected Reference URI mismatch, got: {}",
        reject_body(&result)
    );
}

#[tokio::test]
async fn test_saml_signature_wrapping_values_inside_signature_are_ignored() {
    let bundle = saml_fixtures::IdpBundle::new();
    let plugin = SoapWsSecurity::new(&saml_config(
        &bundle,
        Some("https://my-service.example.com"),
    ))
    .unwrap();

    let nb = long_past();
    let noa = far_future();
    let mut builder = saml_fixtures::AssertionBuilder::new(
        "_assertion-wrapping",
        "https://idp.example.com/metadata",
        "alice@example.com",
    );
    builder.not_before = Some(&nb);
    builder.not_on_or_after = Some(&noa);
    builder.audience = Some("https://my-service.example.com");
    let assertion = builder.build();

    let wrapped = assertion.replace(
        "<SignedInfo>",
        "<Subject><NameID>admin@example.com</NameID></Subject><Conditions NotBefore=\"2099-01-01T00:00:00Z\"><AudienceRestriction><Audience>https://evil-service.example.com</Audience></AudienceRestriction></Conditions><SignedInfo>",
    );

    let body = wrap_saml_assertion(&wrapped);
    let mut ctx = make_ctx_with_soap_body(&body);
    let mut headers = soap_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(
        matches!(result, PluginResult::Continue),
        "wrapped values inside Signature must be ignored, got {:?}",
        result
    );
    assert_eq!(
        ctx.metadata.get("soap_ws_saml_subject").map(String::as_str),
        Some("alice@example.com"),
        "must export signed Subject NameID, not unsigned Signature-subtree content"
    );
}

#[tokio::test]
async fn test_saml_multiple_assertions_rejected() {
    // Defense in depth: even when the first Assertion verifies cleanly, a
    // second Assertion in the same WS-Security block is rejected outright
    // so downstream consumers that walk all assertions can never see an
    // identity that wasn't validated against the configured trust list.
    let bundle = saml_fixtures::IdpBundle::new();
    let plugin = SoapWsSecurity::new(&saml_config(&bundle, None)).unwrap();

    let valid = saml_fixtures::AssertionBuilder::new(
        "_assertion-valid",
        "https://idp.example.com/metadata",
        "alice@example.com",
    )
    .build();
    // Second assertion: also signed correctly (so the test fails ONLY because
    // of the multi-assertion rule, not because the second one's signature is
    // bad). Different ID so URI rewriting picks the right Reference.
    let second = saml_fixtures::AssertionBuilder::new(
        "_assertion-second",
        "https://idp.example.com/metadata",
        "mallory@example.com",
    )
    .build();

    let body = wrap_saml_assertion(&format!("{}{}", valid, second));
    let mut ctx = make_ctx_with_soap_body(&body);
    let mut headers = soap_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(is_reject(&result));
    assert!(
        reject_body(&result).contains("multiple SAML Assertion elements"),
        "expected multi-assertion rejection, got: {}",
        reject_body(&result)
    );
}

#[tokio::test]
async fn test_saml_assertion_in_body_is_rejected() {
    let bundle = saml_fixtures::IdpBundle::new();
    let plugin = SoapWsSecurity::new(&saml_config(&bundle, None)).unwrap();

    let valid = saml_fixtures::AssertionBuilder::new(
        "_assertion-valid",
        "https://idp.example.com/metadata",
        "alice@example.com",
    )
    .build();

    let body = wrap_saml_assertion(&valid).replace(
        "<soap:Body>",
        "<soap:Body><Assertion ID=\"body-assertion\"><Issuer>https://evil.example.com</Issuer>\
         <Subject><NameID>mallory@example.com</NameID></Subject></Assertion>",
    );
    let mut ctx = make_ctx_with_soap_body(&body);
    let mut headers = soap_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;

    assert!(is_reject(&result));
    assert!(
        reject_body(&result).contains("multiple SAML Assertion elements"),
        "expected envelope-wide multi-assertion rejection, got: {}",
        reject_body(&result)
    );
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

// ── UTF-16 / charset hostile-input boundary tests ───────────────────────────

#[test]
fn decode_utf16le_with_bom_and_matching_charset() {
    let xml = wrap_soap(&fresh_timestamp());
    let bytes = encode_utf16_le(&xml);
    let decoded = soap_decode_xml_body_for_test(&bytes, "application/soap+xml; charset=utf-16")
        .expect("UTF-16LE with BOM should decode");
    assert!(decoded.contains("Envelope"));
    assert!(decoded.contains("Timestamp"));
}

#[test]
fn decode_utf16be_with_bom_and_matching_charset() {
    let xml = wrap_soap(&fresh_timestamp());
    let bytes = encode_utf16_be(&xml);
    let decoded =
        soap_decode_xml_body_for_test(&bytes, "text/xml; charset=utf-16be").expect("UTF-16BE");
    assert!(decoded.contains("Envelope"));
}

#[test]
fn decode_utf8_with_bom_strips_bom() {
    let xml = wrap_soap(&fresh_timestamp());
    let mut bytes = vec![0xEF, 0xBB, 0xBF];
    bytes.extend_from_slice(xml.as_bytes());
    let decoded =
        soap_decode_xml_body_for_test(&bytes, "text/xml; charset=utf-8").expect("UTF-8 BOM");
    assert!(!decoded.starts_with('\u{feff}'));
    assert!(decoded.contains("Envelope"));
}

#[test]
fn decode_rejects_utf16_charset_without_bom_or_endian() {
    let xml = wrap_soap(&fresh_timestamp());
    let bytes = encode_utf16_le_no_bom(&xml);
    let err = soap_decode_xml_body_for_test(&bytes, "text/xml; charset=utf-16")
        .expect_err("ambiguous utf-16 without BOM must fail closed");
    assert!(
        err.contains("conflicting or ambiguous"),
        "unexpected error: {err}"
    );
}

#[test]
fn decode_accepts_explicit_utf16le_charset_without_bom() {
    let xml = wrap_soap(&fresh_timestamp());
    let bytes = encode_utf16_le_no_bom(&xml);
    let decoded = soap_decode_xml_body_for_test(&bytes, "text/xml; charset=utf-16le")
        .expect("explicit utf-16le does not require BOM");
    assert!(decoded.contains("Envelope"));
}

#[test]
fn decode_unicodefffe_label_uses_utf16be() {
    let xml = wrap_soap(&fresh_timestamp());
    let mut bytes = Vec::new();
    for unit in xml.encode_utf16() {
        bytes.extend_from_slice(&unit.to_be_bytes());
    }
    let decoded = soap_decode_xml_body_for_test(&bytes, "text/xml; charset=unicodeFFFE")
        .expect("unicodeFFFE is a UTF-16BE label");
    assert!(decoded.contains("Envelope"));
}

#[test]
fn decode_rejects_bom_charset_conflict() {
    let xml = wrap_soap(&fresh_timestamp());
    let bytes = encode_utf16_le(&xml);
    let err = soap_decode_xml_body_for_test(&bytes, "text/xml; charset=utf-8")
        .expect_err("UTF-16 BOM vs utf-8 charset must conflict");
    assert!(
        err.contains("conflicting or ambiguous"),
        "unexpected error: {err}"
    );
}

#[test]
fn decode_rejects_utf16le_bom_with_utf16be_charset() {
    let xml = wrap_soap(&fresh_timestamp());
    let bytes = encode_utf16_le(&xml);
    let err = soap_decode_xml_body_for_test(&bytes, "text/xml; charset=utf-16be")
        .expect_err("endian mismatch must conflict");
    assert!(err.contains("conflicting or ambiguous"), "got: {err}");
}

#[test]
fn decode_rejects_xml_declaration_encoding_conflict() {
    let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Header>
    <wsse:Security xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
                   xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
      <wsu:Timestamp wsu:Id="TS-1">
        <wsu:Created>2099-01-01T00:00:00Z</wsu:Created>
      </wsu:Timestamp>
    </wsse:Security>
  </soap:Header>
  <soap:Body><GetPrice/></soap:Body>
</soap:Envelope>"#;
    let bytes = encode_utf16_le(xml);
    let err = soap_decode_xml_body_for_test(&bytes, "text/xml; charset=utf-16")
        .expect_err("UTF-16 wire with UTF-8 XML declaration must conflict");
    assert!(err.contains("conflicting or ambiguous"), "got: {err}");
}

#[test]
fn decode_rejects_unsupported_charset() {
    let xml = wrap_soap(&fresh_timestamp());
    let err = soap_decode_xml_body_for_test(xml.as_bytes(), "text/xml; charset=iso-8859-1")
        .expect_err("latin-1 is unsupported");
    assert!(err.contains("unsupported character encoding"), "got: {err}");
}

#[test]
fn decode_rejects_truncated_utf16() {
    let mut bytes = encode_utf16_le("<Envelope/>");
    bytes.pop(); // leave an odd trailing byte after the BOM+payload
    let err = soap_decode_xml_body_for_test(&bytes, "text/xml; charset=utf-16")
        .expect_err("truncated UTF-16 must fail closed");
    assert!(
        err.contains("not valid for its character encoding"),
        "got: {err}"
    );
}

#[test]
fn decode_rejects_malformed_utf16_surrogate() {
    // Lone high surrogate U+D800 — invalid UTF-16.
    let bytes = vec![0xFF, 0xFE, 0x00, 0xD8];
    let err = soap_decode_xml_body_for_test(&bytes, "text/xml; charset=utf-16le")
        .expect_err("lone surrogate must fail");
    assert!(
        err.contains("not valid for its character encoding"),
        "got: {err}"
    );
}

#[test]
fn decode_rejects_duplicate_charset_parameters() {
    let xml = wrap_soap(&fresh_timestamp());
    let err =
        soap_decode_xml_body_for_test(xml.as_bytes(), "text/xml; charset=utf-8; charset=utf-16")
            .expect_err("duplicate charset is ambiguous");
    assert!(err.contains("conflicting or ambiguous"), "got: {err}");
}

#[test]
fn decode_rejects_unbalanced_charset_quotes() {
    let xml = wrap_soap(&fresh_timestamp());
    for content_type in [
        "text/xml; charset=\"utf-8",
        "text/xml; charset=utf-8\"",
        "text/xml; charset='utf-8",
    ] {
        let err = soap_decode_xml_body_for_test(xml.as_bytes(), content_type)
            .expect_err("unbalanced charset quotes must fail closed");
        assert!(err.contains("conflicting or ambiguous"), "got: {err}");
    }
}

#[test]
fn decode_accepts_charset_after_quoted_parameter_containing_semicolon() {
    let xml = wrap_soap(&fresh_timestamp());
    let decoded = soap_decode_xml_body_for_test(
        xml.as_bytes(),
        "text/xml; boundary=\"part;boundary\"; charset=utf-8",
    )
    .expect("semicolon inside a quoted parameter must not split charset");
    assert!(decoded.contains("Envelope"));
}

#[test]
fn decode_accepts_quoted_charset_when_sibling_parameter_contains_semicolon() {
    let xml = wrap_soap(&fresh_timestamp());
    let decoded = soap_decode_xml_body_for_test(
        xml.as_bytes(),
        "application/soap+xml; foo=\"a;b;c\"; charset=\"utf-8\"",
    )
    .expect("quoted charset after quoted semicolon-bearing param");
    assert!(decoded.contains("Envelope"));
}

#[test]
fn decode_rejects_quoted_pair_escape_in_charset() {
    let xml = wrap_soap(&fresh_timestamp());
    let err = soap_decode_xml_body_for_test(xml.as_bytes(), r#"text/xml; charset="utf\-8""#)
        .expect_err("quoted-pair escapes in charset must fail closed");
    assert!(err.contains("unsupported character encoding"), "got: {err}");
}

#[test]
fn decode_rejects_trailing_garbage_after_quoted_charset() {
    let xml = wrap_soap(&fresh_timestamp());
    let err = soap_decode_xml_body_for_test(
        xml.as_bytes(),
        r#"text/xml; charset="utf-8"garbage; boundary=x"#,
    )
    .expect_err("trailing bytes after a quoted charset must fail closed");
    assert!(err.contains("conflicting or ambiguous"), "got: {err}");
}

#[test]
fn decode_rejects_semicolon_bearing_quoted_charset_label() {
    let xml = wrap_soap(&fresh_timestamp());
    let err = soap_decode_xml_body_for_test(xml.as_bytes(), r#"text/xml; charset="utf-8;x""#)
        .expect_err("semicolon inside quoted charset label is not a utf-8 label");
    assert!(err.contains("unsupported character encoding"), "got: {err}");
}

#[test]
fn decode_rejects_bomless_charsetless_utf16le_xml() {
    let xml = r#"<?xml version="1.0"?><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body/></soap:Envelope>"#;
    let bytes = encode_utf16_le_no_bom(xml);
    assert_eq!(
        &bytes[..2],
        &[0x3c, 0x00],
        "fixture must be BOM-less UTF-16LE '<'"
    );
    let err = soap_decode_xml_body_for_test(&bytes, "text/xml")
        .expect_err("BOM-less charset-less UTF-16LE XML must fail closed");
    assert!(err.contains("conflicting or ambiguous"), "got: {err}");
}

#[test]
fn decode_rejects_bomless_charsetless_utf16be_xml() {
    let xml = r#"<?xml version="1.0"?><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body/></soap:Envelope>"#;
    let mut bytes = Vec::new();
    for unit in xml.encode_utf16() {
        bytes.extend_from_slice(&unit.to_be_bytes());
    }
    assert_eq!(
        &bytes[..2],
        &[0x00, 0x3c],
        "fixture must be BOM-less UTF-16BE '<'"
    );
    let err = soap_decode_xml_body_for_test(&bytes, "application/soap+xml")
        .expect_err("BOM-less charset-less UTF-16BE XML must fail closed");
    assert!(err.contains("conflicting or ambiguous"), "got: {err}");
}

#[test]
fn decode_rejects_bomless_utf16_xml_declared_as_utf8() {
    let xml = r#"<?xml version="1.0"?><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body/></soap:Envelope>"#;
    let le = encode_utf16_le_no_bom(xml);
    let le_err = soap_decode_xml_body_for_test(&le, "text/xml; charset=utf-8")
        .expect_err("UTF-16LE bytes declared as UTF-8 must fail closed");
    assert!(le_err.contains("conflicting or ambiguous"), "got: {le_err}");

    let mut be = Vec::new();
    for unit in xml.encode_utf16() {
        be.extend_from_slice(&unit.to_be_bytes());
    }
    let be_err = soap_decode_xml_body_for_test(&be, "application/soap+xml; charset=utf-8")
        .expect_err("UTF-16BE bytes declared as UTF-8 must fail closed");
    assert!(be_err.contains("conflicting or ambiguous"), "got: {be_err}");
}

#[test]
fn decode_utf8_without_charset_still_accepts_ordinary_xml() {
    let xml = wrap_soap(&fresh_timestamp());
    assert_eq!(xml.as_bytes()[0], b'<');
    assert_ne!(xml.as_bytes().get(1).copied(), Some(0x00));
    let decoded = soap_decode_xml_body_for_test(xml.as_bytes(), "text/xml")
        .expect("ordinary UTF-8 without charset must remain accepted");
    assert!(decoded.contains("Envelope"));
}

#[test]
fn xml_declaration_finds_encoding_after_misleading_attribute_value() {
    let xml = r#"<?xml version="encoding" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body><GetPrice/></soap:Body>
</soap:Envelope>"#;
    let bytes = encode_utf16_le(xml);
    let err = soap_decode_xml_body_for_test(&bytes, "text/xml; charset=utf-16")
        .expect_err("the real XML declaration encoding must still be checked");
    assert!(err.contains("conflicting or ambiguous"), "got: {err}");
}

#[test]
fn xml_stylesheet_processing_instruction_is_not_an_xml_declaration() {
    let xml = r#"<?xml-stylesheet type="text/xsl" href="style.xsl"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body><GetPrice/></soap:Body>
</soap:Envelope>"#;
    let decoded = soap_decode_xml_body_for_test(xml.as_bytes(), "text/xml; charset=utf-8")
        .expect("xml-stylesheet processing instruction is not an XML declaration");
    assert_eq!(decoded, xml);
}

#[tokio::test]
async fn utf16le_username_token_validates_over_decoded_text() {
    let plugin = SoapWsSecurity::new(&username_token_config()).unwrap();
    let body = wrap_soap(
        r#"<wsse:UsernameToken>
      <wsse:Username>alice</wsse:Username>
      <wsse:Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText">secret123</wsse:Password>
    </wsse:UsernameToken>"#,
    );
    let bytes = encode_utf16_le(&body);
    let mut ctx = make_ctx_with_soap_bytes(bytes.clone(), "application/soap+xml; charset=utf-16");
    // Simulate H1/H2/H3 handoff: non-UTF-8 bytes must not populate request_body.
    assert!(!ctx.metadata.contains_key("request_body"));
    let mut headers = soap_headers_with_content_type("application/soap+xml; charset=utf-16");
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(
        matches!(result, PluginResult::Continue),
        "UTF-16LE UsernameToken should validate, got {:?}",
        result
    );
    assert_eq!(
        ctx.metadata.get("soap_ws_username").map(String::as_str),
        Some("alice")
    );
    // Backend-visible representation stays the original UTF-16 bytes.
    assert_eq!(
        ctx.request_body_bytes.as_ref().map(|b| b.as_ref()),
        Some(bytes.as_slice())
    );
}

#[tokio::test]
async fn utf16be_timestamp_validates_over_decoded_text() {
    let plugin = SoapWsSecurity::new(&timestamp_only_config()).unwrap();
    let body = wrap_soap(&fresh_timestamp());
    let bytes = encode_utf16_be(&body);
    let mut ctx = make_ctx_with_soap_bytes(bytes, "text/xml; charset=utf-16be");
    let mut headers = soap_headers_with_content_type("text/xml; charset=utf-16be");
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(
        matches!(result, PluginResult::Continue),
        "UTF-16BE timestamp envelope should validate, got {:?}",
        result
    );
}

#[tokio::test]
async fn utf16_missing_security_still_rejects_after_decode() {
    let plugin = SoapWsSecurity::new(&timestamp_only_config()).unwrap();
    let body = r#"<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
      <soap:Header></soap:Header>
      <soap:Body><Test/></soap:Body>
    </soap:Envelope>"#;
    let mut ctx = make_ctx_with_soap_bytes(encode_utf16_le(body), "text/xml; charset=utf-16");
    let mut headers = soap_headers_with_content_type("text/xml; charset=utf-16");
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(is_reject(&result));
    assert_eq!(reject_status(&result), 401);
    assert!(reject_body(&result).contains("Security header is missing"));
}

#[tokio::test]
async fn conflicting_charset_rejects_with_415_without_treating_as_empty() {
    let plugin = SoapWsSecurity::new(&timestamp_only_config()).unwrap();
    let body = wrap_soap(&fresh_timestamp());
    let mut ctx = make_ctx_with_soap_bytes(encode_utf16_le(&body), "text/xml; charset=utf-8");
    let mut headers = soap_headers_with_content_type("text/xml; charset=utf-8");
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(is_reject(&result));
    assert_eq!(reject_status(&result), 415);
    let body = reject_body(&result);
    assert!(
        body.contains("conflicting or ambiguous"),
        "must not misclassify as empty body: {body}"
    );
    assert!(!body.contains("empty"));
}

#[tokio::test]
async fn empty_request_body_bytes_still_reports_empty() {
    let plugin = SoapWsSecurity::new(&timestamp_only_config()).unwrap();
    let mut ctx = make_ctx_with_soap_bytes(Vec::new(), "text/xml");
    let mut headers = soap_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(is_reject(&result));
    assert_eq!(reject_status(&result), 400);
    assert!(reject_body(&result).contains("SOAP request body is empty"));
}

#[tokio::test]
async fn metadata_text_fallback_validates_utf8_xml_declaration() {
    let plugin = SoapWsSecurity::new(&timestamp_only_config()).unwrap();
    let body = r#"<?xml version="1.0" encoding="UTF-16"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Header>
    <wsse:Security xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
      <wsu:Timestamp xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
        <wsu:Created>2000-01-01T00:00:00Z</wsu:Created>
        <wsu:Expires>2099-01-01T00:00:00Z</wsu:Expires>
      </wsu:Timestamp>
    </wsse:Security>
  </soap:Header>
  <soap:Body><GetPrice/></soap:Body>
</soap:Envelope>"#;
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/ws".to_string(),
    );
    // Fixture-only path: metadata text without raw bytes.
    ctx.metadata
        .insert("request_body".to_string(), body.to_string());
    let mut headers = HashMap::new();
    headers.insert(
        "content-type".to_string(),
        "text/xml; charset=utf-8".to_string(),
    );
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(is_reject(&result));
    assert_eq!(reject_status(&result), 415);
    assert!(
        reject_body(&result).contains("conflicting or ambiguous"),
        "metadata fallback must still validate the XML declaration: {}",
        reject_body(&result)
    );
}

#[tokio::test]
async fn metadata_text_fallback_accepts_matching_utf8_declaration() {
    let plugin = SoapWsSecurity::new(&timestamp_only_config()).unwrap();
    let body = wrap_soap(&fresh_timestamp());
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/ws".to_string(),
    );
    ctx.metadata.insert("request_body".to_string(), body);
    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "text/xml".to_string());
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(
        matches!(result, PluginResult::Continue),
        "UTF-8 metadata fallback with a compatible declaration must still validate: {result:?}"
    );
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

#[tokio::test]
async fn test_doctype_entity_payload_rejected() {
    let plugin = SoapWsSecurity::new(&timestamp_only_config()).unwrap();
    let body = format!(
        r#"<?xml version="1.0"?>
<!DOCTYPE soap:Envelope [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
{}"#,
        wrap_soap(&fresh_timestamp())
    );
    let mut ctx = make_ctx_with_soap_body(&body);
    let mut headers = soap_headers();

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(is_reject(&result));
    assert_eq!(reject_status(&result), 400);
    assert!(reject_body(&result).contains("forbidden XML declaration"));
}

// ── Plugin metadata tests ───────────────────────────────────────────────────

#[test]
fn test_soap_ws_security_is_security_plugin() {
    assert_eq!(
        ferrum_edge::plugins::plugin_failure_policy("soap_ws_security"),
        Some(ferrum_edge::plugins::PluginFailurePolicy::FailClosed)
    );
}

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

#[test]
fn test_nonce_cache_refreshes_occupied_entry_after_ttl() {
    // cache_ttl_seconds=0 means every Occupied hit is already expired, so the
    // atomic entry path must refresh inserted_at instead of treating reuse as
    // a live replay. This covers the post-TTL Occupied insert branch used by
    // successful PasswordDigest authentication.
    let plugin = SoapWsSecurity::new(&json!({
        "timestamp": { "require": true },
        "nonce": { "max_cache_size": 100, "cache_ttl_seconds": 0 },
        "reject_missing_security_header": false
    }))
    .unwrap();

    assert!(plugin.check_nonce_replay("ttl-expired-nonce").is_ok());
    assert!(
        plugin.check_nonce_replay("ttl-expired-nonce").is_ok(),
        "expired Occupied nonce must be refreshed, not rejected as a live replay"
    );
}

// ── X.509 signature verification — end-to-end roundtrip ─────────────────────
//
// PR #844 fixed `cert.public_key().raw` → `cert.public_key().subject_public_key.data`
// so the bytes passed to `ring::signature::UnparsedPublicKey::new(&RSA_PKCS1_*, ...)`
// are the bare RFC 8017 `RSAPublicKey` (modulus + exponent) instead of the full
// RFC 5280 `SubjectPublicKeyInfo`. Without these tests, the only existing X.509
// coverage was `test_x509_no_trusted_certs_is_error`, which only exercises the
// empty-list error path — every signed-envelope flow was silently broken since
// the feature was added because *no* test ever loaded an RSA cert and ran the
// plugin against a real signature.
//
// These tests lock in the fix by minting a self-signed RSA cert with rcgen,
// signing a deterministic `<SignedInfo>` block with ring's `RSA_PKCS1_SHA256`,
// and feeding the resulting SOAP envelope through the public `before_proxy`
// path. If a future refactor re-introduces the SPKI/RSAPublicKey mismatch the
// happy-path test will start rejecting valid signatures; the
// tampered-signature test makes sure we are not accidentally "verifying" by
// returning Ok for anything.

mod x509_roundtrip {
    use super::*;
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD as B64;
    use rcgen::{
        CertificateParams, DistinguishedName, DnType, KeyPair, PKCS_ECDSA_P256_SHA256,
        PKCS_RSA_SHA256,
    };
    use ring::rand::SystemRandom;
    use ring::signature::{RSA_PKCS1_SHA256, RsaKeyPair};

    /// rcgen-minted self-signed RSA cert + the same PKCS#8 key material that
    /// signed it, so we can both (a) hand the cert PEM to `SoapWsSecurity` for
    /// trust-store loading and (b) hand the same private key to ring for
    /// signing the `<SignedInfo>` block.
    struct TestRsaCert {
        cert_pem: String,
        cert_der_b64: String,
        signing_key: RsaKeyPair,
    }

    fn mint_rsa_cert() -> TestRsaCert {
        let key_pair = KeyPair::generate_for(&PKCS_RSA_SHA256)
            .expect("rcgen RSA keypair (requires aws_lc_rs feature on rcgen)");
        let mut params = CertificateParams::new(vec!["soap-ws-security-test".to_string()])
            .expect("rcgen CertificateParams");
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "soap-ws-security-test");
        params.distinguished_name = dn;
        let cert = params
            .self_signed(&key_pair)
            .expect("rcgen self-sign RSA cert");
        let cert_pem = cert.pem();
        let cert_der_b64 = B64.encode(cert.der().as_ref());

        // rcgen `KeyPair::serialize_der` exposes the key as a PKCS#8 DER, which
        // is the input format ring's `RsaKeyPair::from_pkcs8` expects.
        let pkcs8_der = key_pair.serialize_der();
        let signing_key =
            RsaKeyPair::from_pkcs8(&pkcs8_der).expect("ring RsaKeyPair from rcgen PKCS#8 DER");

        TestRsaCert {
            cert_pem,
            cert_der_b64,
            signing_key,
        }
    }

    /// rcgen-minted self-signed ECDSA P-256 cert PEM, used to drive the
    /// non-RSA SPKI rejection path at constructor time.
    fn mint_ecdsa_cert_pem() -> String {
        let key_pair =
            KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("rcgen ECDSA P-256 keypair");
        let mut params = CertificateParams::new(vec!["soap-ws-security-ecdsa-test".to_string()])
            .expect("rcgen CertificateParams");
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "soap-ws-security-ecdsa-test");
        params.distinguished_name = dn;
        let cert = params
            .self_signed(&key_pair)
            .expect("rcgen self-sign ECDSA cert");
        cert.pem()
    }

    fn write_pem_to_tempfile(pem: &str) -> tempfile::NamedTempFile {
        use std::io::Write;
        let mut file = tempfile::NamedTempFile::with_suffix(".pem").expect("tempfile");
        file.write_all(pem.as_bytes()).expect("write pem");
        file.flush().expect("flush pem");
        file
    }

    /// Construct a SOAP envelope whose `<wsse:Security>` block contains a
    /// `<Timestamp wsu:Id="TS-1">` and a `<Signature>` covering that Timestamp.
    /// The signed bytes are exclusive-canonicalized rather than copied from
    /// the wire. Namespace declarations are intentionally inherited and then
    /// re-emitted by c14n, making this a regression fixture for the old
    /// wire-byte verifier.
    fn build_signed_soap_envelope(cert: &TestRsaCert) -> String {
        build_signed_soap_envelope_with_timestamp_prefix(cert, "wsu")
    }

    fn build_signed_soap_envelope_with_timestamp_prefix(
        cert: &TestRsaCert,
        timestamp_prefix: &str,
    ) -> String {
        let now = chrono::Utc::now();
        let created = now.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();
        let expires = (now + chrono::Duration::minutes(5))
            .format("%Y-%m-%dT%H:%M:%S%.3fZ")
            .to_string();

        let timestamp_xml = format!(
            r#"<{prefix}:Timestamp {prefix}:Id="TS-1"><{prefix}:Created>{created}</{prefix}:Created><{prefix}:Expires>{expires}</{prefix}:Expires></{prefix}:Timestamp>"#,
            prefix = timestamp_prefix,
            created = created,
            expires = expires,
        );

        let timestamp_context = format!(
            r#"<root xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:{prefix}="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">{timestamp}</root>"#,
            prefix = timestamp_prefix,
            timestamp = timestamp_xml,
        );
        let canonical_timestamp =
            soap_exclusive_canonicalize_element_for_test(&timestamp_context, "Timestamp", "soap")
                .expect("test Timestamp must canonicalize");
        assert_ne!(
            canonical_timestamp, timestamp_xml,
            "fixture must differ from wire bytes to regress raw-byte verification"
        );
        let ts_digest = ring::digest::digest(&ring::digest::SHA256, canonical_timestamp.as_bytes());
        let ts_digest_b64 = B64.encode(ts_digest.as_ref());

        let signed_info = format!(
            r##"<SignedInfo><CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"><ec:InclusiveNamespaces xmlns:ec="http://www.w3.org/2001/10/xml-exc-c14n#" PrefixList="soap"/></CanonicalizationMethod><SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><Reference URI="#TS-1"><Transforms><Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"><ec:InclusiveNamespaces xmlns:ec="http://www.w3.org/2001/10/xml-exc-c14n#" PrefixList="soap"/></Transform></Transforms><DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><DigestValue>{}</DigestValue></Reference></SignedInfo>"##,
            ts_digest_b64
        );
        let signed_info_context = format!(
            r#"<Signature xmlns="http://www.w3.org/2000/09/xmldsig#" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">{signed_info}</Signature>"#,
        );
        let canonical_signed_info = soap_exclusive_canonicalize_element_for_test(
            &signed_info_context,
            "SignedInfo",
            "soap",
        )
        .expect("test SignedInfo must canonicalize");
        assert_ne!(
            canonical_signed_info, signed_info,
            "fixture must sign canonical form rather than wire bytes"
        );

        // Sign the exclusive-canonicalized SignedInfo with RSA-PKCS1-v1_5.
        let rng = SystemRandom::new();
        let mut signature = vec![0u8; cert.signing_key.public().modulus_len()];
        cert.signing_key
            .sign(
                &RSA_PKCS1_SHA256,
                &rng,
                canonical_signed_info.as_bytes(),
                &mut signature,
            )
            .expect("ring RSA sign");
        let signature_b64 = B64.encode(&signature);

        format!(
            r#"<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Header>
    <wsse:Security xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
                   xmlns:{timestamp_prefix}="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
      {timestamp}
      <wsse:BinarySecurityToken EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary" ValueType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3">{cert_b64}</wsse:BinarySecurityToken>
      <Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
        {signed_info}
        <SignatureValue>{sig_b64}</SignatureValue>
      </Signature>
    </wsse:Security>
  </soap:Header>
  <soap:Body><GetPrice xmlns="http://example.com/prices"><Item>Widget</Item></GetPrice></soap:Body>
</soap:Envelope>"#,
            timestamp = timestamp_xml,
            timestamp_prefix = timestamp_prefix,
            cert_b64 = cert.cert_der_b64,
            signed_info = signed_info,
            sig_b64 = signature_b64,
        )
    }

    fn x509_plugin_config(cert_path: &std::path::Path) -> serde_json::Value {
        json!({
            "timestamp": { "require": true, "max_age_seconds": 300 },
            "x509_signature": {
                "enabled": true,
                "trusted_certs": [cert_path.to_str().unwrap()],
                "allowed_algorithms": ["rsa-sha256"],
                "require_signed_timestamp": true,
            },
            "reject_missing_security_header": true
        })
    }

    #[tokio::test]
    async fn valid_rsa_signature_is_accepted() {
        let cert = mint_rsa_cert();
        let cert_file = write_pem_to_tempfile(&cert.cert_pem);
        let plugin = SoapWsSecurity::new(&x509_plugin_config(cert_file.path()))
            .expect("plugin should construct with valid RSA cert");

        let body = build_signed_soap_envelope(&cert);
        let mut ctx = make_ctx_with_soap_body(&body);
        let mut headers = soap_headers();
        let result = plugin.before_proxy(&mut ctx, &mut headers).await;

        assert!(
            matches!(result, PluginResult::Continue),
            "expected Continue with valid RSA signature, got {:?}",
            result,
        );
    }

    #[tokio::test]
    async fn valid_rsa_signature_is_accepted_over_utf16be() {
        let cert = mint_rsa_cert();
        let cert_file = write_pem_to_tempfile(&cert.cert_pem);
        let plugin = SoapWsSecurity::new(&x509_plugin_config(cert_file.path()))
            .expect("plugin should construct with valid RSA cert");

        let body = build_signed_soap_envelope(&cert);
        let bytes = encode_utf16_be(&body);
        let mut ctx = make_ctx_with_soap_bytes(bytes, "text/xml; charset=utf-16be");
        let mut headers = soap_headers_with_content_type("text/xml; charset=utf-16be");
        let result = plugin.before_proxy(&mut ctx, &mut headers).await;

        assert!(
            matches!(result, PluginResult::Continue),
            "UTF-16BE signed X.509 envelope should validate after decode, got {:?}",
            result,
        );
    }

    #[tokio::test]
    async fn unsupported_signed_info_canonicalization_is_rejected() {
        let cert = mint_rsa_cert();
        let cert_file = write_pem_to_tempfile(&cert.cert_pem);
        let plugin = SoapWsSecurity::new(&x509_plugin_config(cert_file.path())).unwrap();
        let body = build_signed_soap_envelope(&cert).replacen(
            "http://www.w3.org/2001/10/xml-exc-c14n#",
            "urn:unsupported:canonicalization",
            1,
        );

        let mut ctx = make_ctx_with_soap_body(&body);
        let mut headers = soap_headers();
        let result = plugin.before_proxy(&mut ctx, &mut headers).await;

        assert!(is_reject(&result));
        assert!(
            reject_body(&result).contains("unsupported CanonicalizationMethod"),
            "unexpected rejection: {}",
            reject_body(&result)
        );
    }

    #[tokio::test]
    async fn unsupported_reference_transform_is_rejected() {
        let cert = mint_rsa_cert();
        let cert_file = write_pem_to_tempfile(&cert.cert_pem);
        let plugin = SoapWsSecurity::new(&x509_plugin_config(cert_file.path())).unwrap();
        let body = build_signed_soap_envelope(&cert).replace(
            "<Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\">",
            "<Transform Algorithm=\"urn:unsupported:transform\">",
        );

        let mut ctx = make_ctx_with_soap_body(&body);
        let mut headers = soap_headers();
        let result = plugin.before_proxy(&mut ctx, &mut headers).await;

        assert!(is_reject(&result));
        assert!(
            reject_body(&result).contains("unsupported Transform algorithm"),
            "unexpected rejection: {}",
            reject_body(&result)
        );
    }

    #[tokio::test]
    async fn oversized_inclusive_namespace_prefix_list_is_rejected() {
        let cert = mint_rsa_cert();
        let cert_file = write_pem_to_tempfile(&cert.cert_pem);
        let plugin = SoapWsSecurity::new(&x509_plugin_config(cert_file.path())).unwrap();
        let prefix_list = (0..65)
            .map(|index| format!("p{index}"))
            .collect::<Vec<_>>()
            .join(" ");
        let body = build_signed_soap_envelope(&cert).replacen(
            "PrefixList=\"soap\"",
            &format!("PrefixList=\"{prefix_list}\""),
            1,
        );
        let mut ctx = make_ctx_with_soap_body(&body);
        let mut headers = soap_headers();

        let result = plugin.before_proxy(&mut ctx, &mut headers).await;

        assert!(is_reject(&result));
        assert!(
            reject_body(&result).contains("more than 64 prefixes"),
            "unexpected rejection: {}",
            reject_body(&result)
        );
    }

    #[tokio::test]
    async fn overly_complex_soap_dom_is_rejected_before_signature_verification() {
        let cert = mint_rsa_cert();
        let cert_file = write_pem_to_tempfile(&cert.cert_pem);
        let plugin = SoapWsSecurity::new(&x509_plugin_config(cert_file.path())).unwrap();
        let many_nodes = "<N/>".repeat(66_000);
        let body = build_signed_soap_envelope(&cert)
            .replace("<soap:Body>", &format!("<soap:Body>{many_nodes}"));
        let mut ctx = make_ctx_with_soap_body(&body);
        let mut headers = soap_headers();

        let result = plugin.before_proxy(&mut ctx, &mut headers).await;

        assert!(is_reject(&result));
        assert!(
            reject_body(&result).contains("overly complex"),
            "unexpected rejection: {}",
            reject_body(&result)
        );
    }

    #[tokio::test]
    async fn valid_rsa_signature_with_arbitrary_wsu_prefix_is_accepted() {
        let cert = mint_rsa_cert();
        let cert_file = write_pem_to_tempfile(&cert.cert_pem);
        let plugin = SoapWsSecurity::new(&x509_plugin_config(cert_file.path()))
            .expect("plugin should construct with valid RSA cert");

        let body = build_signed_soap_envelope_with_timestamp_prefix(&cert, "u");
        let mut ctx = make_ctx_with_soap_body(&body);
        let mut headers = soap_headers();
        let result = plugin.before_proxy(&mut ctx, &mut headers).await;

        assert!(
            matches!(result, PluginResult::Continue),
            "expected Continue with non-wsu WSU namespace prefix, got {:?}",
            result,
        );
    }

    #[tokio::test]
    async fn rsa_signature_with_non_wsu_prefixed_id_is_rejected() {
        let cert = mint_rsa_cert();
        let cert_file = write_pem_to_tempfile(&cert.cert_pem);
        let plugin = SoapWsSecurity::new(&x509_plugin_config(cert_file.path()))
            .expect("plugin should construct with valid RSA cert");

        let body = build_signed_soap_envelope_with_timestamp_prefix(&cert, "evil")
            .replace(
                r#"xmlns:evil="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd""#,
                r#"xmlns:evil="urn:not-wsu""#,
            );
        let mut ctx = make_ctx_with_soap_body(&body);
        let mut headers = soap_headers();
        let result = plugin.before_proxy(&mut ctx, &mut headers).await;

        assert!(
            matches!(
                result,
                PluginResult::Reject {
                    status_code: 401,
                    ..
                }
            ),
            "expected Reject for non-WSU prefixed Id, got {:?}",
            result,
        );
    }

    #[tokio::test]
    async fn duplicate_wsu_id_is_rejected_as_signature_wrapping() {
        // finding #2 (XML Signature Wrapping): the signed Reference targets
        // `#TS-1`. If an attacker injects a SECOND element bearing
        // wsu:Id="TS-1" elsewhere in the envelope, the substring resolver would
        // digest the first (legitimately signed) element while a backend might
        // consume the injected duplicate. The uniqueness guard must reject the
        // envelope before trusting the signature.
        let cert = mint_rsa_cert();
        let cert_file = write_pem_to_tempfile(&cert.cert_pem);
        let plugin = SoapWsSecurity::new(&x509_plugin_config(cert_file.path())).unwrap();

        let valid = build_signed_soap_envelope(&cert);
        // Inject a duplicate wsu:Id="TS-1" element into the SOAP body.
        let wrapped = valid.replace(
            "<soap:Body>",
            "<soap:Body><Injected wsu:Id=\"TS-1\" \
             xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\">\
             attacker-controlled</Injected>",
        );
        assert_ne!(
            valid, wrapped,
            "duplicate-id injection must modify the envelope"
        );

        let mut ctx = make_ctx_with_soap_body(&wrapped);
        let mut headers = soap_headers();
        let result = plugin.before_proxy(&mut ctx, &mut headers).await;

        match result {
            PluginResult::Reject {
                status_code, body, ..
            } => {
                assert_eq!(status_code, 401);
                assert!(
                    body.contains("signature wrapping") || body.contains("not unique"),
                    "expected XML-signature-wrapping rejection, got: {body}"
                );
            }
            other => panic!("expected Reject for duplicate wsu:Id, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn entity_encoded_timestamp_id_is_recognized_as_signed() {
        let cert = mint_rsa_cert();
        let cert_file = write_pem_to_tempfile(&cert.cert_pem);
        let plugin = SoapWsSecurity::new(&x509_plugin_config(cert_file.path())).unwrap();
        let body =
            build_signed_soap_envelope(&cert).replace("wsu:Id=\"TS-1\"", "wsu:Id=\"TS&#x2D;1\"");
        let mut ctx = make_ctx_with_soap_body(&body);
        let mut headers = soap_headers();

        let result = plugin.before_proxy(&mut ctx, &mut headers).await;

        assert!(
            matches!(result, PluginResult::Continue),
            "entity-equivalent timestamp ID should remain signed, got {result:?}"
        );
    }

    #[tokio::test]
    async fn entity_encoded_id_and_raw_duplicate_are_rejected_as_wrapping() {
        let cert = mint_rsa_cert();
        let cert_file = write_pem_to_tempfile(&cert.cert_pem);
        let plugin = SoapWsSecurity::new(&x509_plugin_config(cert_file.path())).unwrap();

        let entity_encoded =
            build_signed_soap_envelope(&cert).replace("wsu:Id=\"TS-1\"", "wsu:Id=\"TS&#x2D;1\"");
        let wrapped = entity_encoded.replace(
            "<soap:Body>",
            "<soap:Body><Injected wsu:Id=\"TS-1\" \
             xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\">attacker</Injected>",
        );
        let mut ctx = make_ctx_with_soap_body(&wrapped);
        let mut headers = soap_headers();

        let result = plugin.before_proxy(&mut ctx, &mut headers).await;

        assert!(is_reject(&result));
        assert!(
            reject_body(&result).contains("not unique"),
            "decoded duplicate ID must fail the XSW guard: {}",
            reject_body(&result)
        );
    }

    #[tokio::test]
    async fn x509_verification_is_scoped_to_selected_soap_header_security() {
        let cert = mint_rsa_cert();
        let cert_file = write_pem_to_tempfile(&cert.cert_pem);
        let mut config = x509_plugin_config(cert_file.path());
        config["x509_signature"]["require_signed_timestamp"] = json!(false);
        let plugin = SoapWsSecurity::new(&config).unwrap();

        let valid = build_signed_soap_envelope(&cert);
        let security_start = valid.find("<wsse:Security").expect("Security start");
        let security_end = valid[security_start..]
            .find("</wsse:Security>")
            .map(|offset| security_start + offset + "</wsse:Security>".len())
            .expect("Security end");
        let signed_security = &valid[security_start..security_end];
        let signature_start = signed_security
            .find("<Signature ")
            .expect("Signature start");
        let signature_end = signed_security[signature_start..]
            .find("</Signature>")
            .map(|offset| signature_start + offset + "</Signature>".len())
            .expect("Signature end");
        let mut unsigned_security = signed_security.to_string();
        unsigned_security.replace_range(signature_start..signature_end, "");
        unsigned_security = unsigned_security.replace("wsu:Id=\"TS-1\"", "wsu:Id=\"TS-actual\"");
        let header_unsigned = valid.replacen(signed_security, &unsigned_security, 1);
        let body = header_unsigned.replacen(
            "<soap:Header>",
            &format!("{}<soap:Header>", signed_security),
            1,
        );
        let mut ctx = make_ctx_with_soap_body(&body);
        let mut headers = soap_headers();

        let result = plugin.before_proxy(&mut ctx, &mut headers).await;

        assert!(is_reject(&result));
        assert!(
            reject_body(&result).contains("missing Signature"),
            "pre-header signed Security must not satisfy header verification: {}",
            reject_body(&result)
        );
    }

    #[tokio::test]
    async fn duplicate_bare_single_quoted_id_is_rejected_as_signature_wrapping() {
        // The signed element uses wsu:Id="TS-1"; this injects a bare Id='TS-1'
        // duplicate to prove the mixed-prefix and mixed-quote count is covered
        // end-to-end, not just in the double-quoted wsu:Id case.
        let cert = mint_rsa_cert();
        let cert_file = write_pem_to_tempfile(&cert.cert_pem);
        let plugin = SoapWsSecurity::new(&x509_plugin_config(cert_file.path())).unwrap();

        let valid = build_signed_soap_envelope(&cert);
        let wrapped = valid.replace(
            "<soap:Body>",
            "<soap:Body><Injected Id='TS-1'>attacker-controlled</Injected>",
        );
        assert_ne!(
            valid, wrapped,
            "bare duplicate-id injection must modify the envelope"
        );

        let mut ctx = make_ctx_with_soap_body(&wrapped);
        let mut headers = soap_headers();
        let result = plugin.before_proxy(&mut ctx, &mut headers).await;

        match result {
            PluginResult::Reject {
                status_code, body, ..
            } => {
                assert_eq!(status_code, 401);
                assert!(
                    body.contains("signature wrapping") || body.contains("not unique"),
                    "expected XML-signature-wrapping rejection, got: {body}"
                );
            }
            other => panic!("expected Reject for duplicate bare Id, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn business_attribute_ending_in_id_is_not_treated_as_duplicate() {
        // The signed wsu:Id is "TS-1". A legitimate, correctly-signed envelope
        // that also carries an unrelated business attribute whose NAME ends in
        // "Id" with the same value (e.g. `CorrelationId="TS-1"`) must NOT be
        // rejected as wrapping — the uniqueness count is anchored on the XML
        // name boundary, so `CorrelationId` is not counted as a `wsu:Id`/`Id`.
        let cert = mint_rsa_cert();
        let cert_file = write_pem_to_tempfile(&cert.cert_pem);
        let plugin = SoapWsSecurity::new(&x509_plugin_config(cert_file.path())).unwrap();

        let valid = build_signed_soap_envelope(&cert);
        let with_business_attr = valid.replace(
            "<GetPrice xmlns=\"http://example.com/prices\">",
            "<GetPrice xmlns=\"http://example.com/prices\" CorrelationId=\"TS-1\">",
        );
        assert_ne!(
            valid, with_business_attr,
            "business attribute injection must modify the envelope"
        );

        let mut ctx = make_ctx_with_soap_body(&with_business_attr);
        let mut headers = soap_headers();
        let result = plugin.before_proxy(&mut ctx, &mut headers).await;
        assert!(
            matches!(result, PluginResult::Continue),
            "valid signature with an unrelated *Id business attribute must be accepted, got {:?}",
            result,
        );
    }

    #[tokio::test]
    async fn tampered_signature_is_rejected() {
        let cert = mint_rsa_cert();
        let cert_file = write_pem_to_tempfile(&cert.cert_pem);
        let plugin = SoapWsSecurity::new(&x509_plugin_config(cert_file.path())).unwrap();

        // Flip the first character of the base64-encoded SignatureValue so
        // ring's verify fails. Replacing with another valid base64 digit keeps
        // the payload decodable — we want the *cryptographic* check to reject,
        // not the base64 decoder.
        let original = build_signed_soap_envelope(&cert);
        let open = original
            .find("<SignatureValue>")
            .expect("envelope must have <SignatureValue>")
            + "<SignatureValue>".len();
        let first_char = original.as_bytes()[open];
        let replacement = if first_char == b'A' { 'B' } else { 'A' };
        let mut body = String::with_capacity(original.len());
        body.push_str(&original[..open]);
        body.push(replacement);
        body.push_str(&original[open + 1..]);

        let mut ctx = make_ctx_with_soap_body(&body);
        let mut headers = soap_headers();
        let result = plugin.before_proxy(&mut ctx, &mut headers).await;

        match result {
            PluginResult::Reject {
                status_code, body, ..
            } => {
                assert_eq!(status_code, 401);
                assert!(
                    body.contains("signature verification failed"),
                    "expected signature failure message, got: {body}"
                );
            }
            other => panic!("expected Reject on tampered signature, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn tampered_digest_value_breaks_reference_check() {
        let cert = mint_rsa_cert();
        let cert_file = write_pem_to_tempfile(&cert.cert_pem);
        let plugin = SoapWsSecurity::new(&x509_plugin_config(cert_file.path())).unwrap();

        // Flip the first character of the Reference DigestValue in SignedInfo.
        // The recomputed digest of the (untouched) Timestamp will no longer
        // match the (tampered) base64 in SignedInfo, so `verify_reference_digests`
        // must reject. We can't tamper with the Timestamp text itself here
        // because `validate_timestamp` runs first in the pipeline and would
        // fail on the parse before signature checks even run.
        let original = build_signed_soap_envelope(&cert);
        let dv_open = original
            .find("<DigestValue>")
            .expect("envelope must have <DigestValue>")
            + "<DigestValue>".len();
        let first_char = original.as_bytes()[dv_open];
        let replacement = if first_char == b'A' { 'B' } else { 'A' };
        let mut body = String::with_capacity(original.len());
        body.push_str(&original[..dv_open]);
        body.push(replacement);
        body.push_str(&original[dv_open + 1..]);

        let mut ctx = make_ctx_with_soap_body(&body);
        let mut headers = soap_headers();
        let result = plugin.before_proxy(&mut ctx, &mut headers).await;

        match result {
            PluginResult::Reject { body, .. } => assert!(
                body.contains("digest mismatch"),
                "expected digest mismatch, got: {body}"
            ),
            other => panic!("expected Reject on tampered DigestValue, got {:?}", other),
        }
    }

    #[test]
    fn non_rsa_cert_is_rejected_at_load_time() {
        // Defense-in-depth: an ECDSA cert should fail with a precise error
        // mentioning RSA, not silently load and only fail later at request
        // time with a generic "signature verification failed" message.
        let ecdsa_pem = mint_ecdsa_cert_pem();
        let cert_file = write_pem_to_tempfile(&ecdsa_pem);

        let result = SoapWsSecurity::new(&x509_plugin_config(cert_file.path()));
        let err = match result {
            Err(e) => e,
            Ok(_) => panic!("ECDSA cert must be rejected at constructor time"),
        };
        assert!(
            err.contains("not an RSA public key"),
            "error should name the RSA constraint, got: {err}"
        );
        // The error must include the canonical RSA OID so operators can
        // cross-reference with their cert tooling.
        assert!(
            err.contains("1.2.840.113549.1.1.1"),
            "error should include canonical RSA OID, got: {err}"
        );
    }

    #[test]
    fn unreadable_cert_path_is_rejected_at_load_time() {
        // A non-existent path must fail at constructor time with the
        // "failed to load trusted cert" surface, not panic.
        let result = SoapWsSecurity::new(&x509_plugin_config(std::path::Path::new(
            "/this/path/does/not/exist/cert.pem",
        )));
        let err = match result {
            Err(e) => e,
            Ok(_) => panic!("missing cert file must fail load"),
        };
        assert!(err.contains("failed to load trusted cert"), "got: {err}");
    }
}
