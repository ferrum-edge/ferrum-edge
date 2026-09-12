use ferrum_edge::_test_support::{
    MAX_NONCE_REPLAY_SCOPES_FOR_TESTS, SoapNonceReplayHarness, SoapNonceReplayScopeLease,
    soap_count_wsu_id_occurrences_for_test, soap_decode_xml_body_for_test,
    soap_exclusive_canonicalize_element_for_test, soap_nonce_inconsistent_state_outcome_for_test,
    soap_nonce_replay_registry_contains_for_test, soap_nonce_replay_scope_key_for_test,
    soap_poison_process_replay_scope_for_test, soap_remove_nonce_replay_scope_for_test,
    soap_retire_inconsistent_process_replay_scope_for_test,
    soap_retire_same_cardinality_drift_scope_for_test,
    soap_shared_claim_retention_seconds_for_test, soap_username_token_created_outcome_for_test,
};
use ferrum_edge::consumer_index::ConsumerIndex;
use ferrum_edge::plugins::soap_ws_security::SoapWsSecurity;
use ferrum_edge::plugins::{
    HTTP_ONLY_PROTOCOLS, Plugin, PluginHttpClient, PluginResult, RequestContext, priority,
};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Barrier, Mutex};
use std::time::Duration;

/// The fixed PasswordDigest nonce claim retention, in seconds, on both the
/// process and the shared path:
/// `MAX_UT_CREATED_MAX_AGE_SECONDS (86400) + 2 × MAX_CLOCK_SKEW_SECONDS (3600) + 1`.
///
/// This is the *global* maximum admissible acceptance horizon — the widest span
/// over which any configuration the schema admits can accept an unchanged
/// UsernameToken — not a value derived from the configured window. It is not
/// operator-tunable; `nonce.cache_ttl_seconds` no longer exists.
const CLAIM_RETENTION_SECONDS: u64 = 93_601;

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

/// Run the plugin's request-side policy in whichever phase its configuration
/// selects.
///
/// GHSA-gfrx-43w6-jq3c moved identity-establishing SOAP policies
/// (`username_token` / `x509_signature` / `saml`) into the `authenticate`
/// phase so the SOAP principal exists before authorization; a timestamp-only
/// policy establishes no principal and keeps validating in `before_proxy`. The
/// two are mutually exclusive by configuration, so this helper mirrors the
/// proxy's own dispatch.
async fn run_soap_request_policy(
    plugin: &SoapWsSecurity,
    ctx: &mut RequestContext,
    headers: &mut HashMap<String, String>,
) -> PluginResult {
    if plugin.is_auth_plugin() {
        let consumer_index = ConsumerIndex::new(&[]);
        plugin.authenticate(ctx, &consumer_index).await
    } else {
        plugin.before_proxy(ctx, headers).await
    }
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
        // `replay_scope` has no default: a PasswordDigest policy must state
        // which deployment shape its replay protection covers.
        "nonce": { "replay_scope": "process" },
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
    password_digest_security_block(username, password, nonce_bytes, created, Some(created))
}

/// A `wsu:Timestamp` bound to `created` (zero divergence).
fn bound_timestamp(created: &str) -> String {
    format!(
        r#"<wsu:Timestamp wsu:Id="TS-1"><wsu:Created>{}</wsu:Created></wsu:Timestamp>"#,
        created
    )
}

/// Full WS-Security content for a PasswordDigest request.
///
/// `timestamp_created` controls the outer instant independently of the token's
/// own `Created`, which is what the binding tests need. `None` omits the outer
/// Timestamp entirely.
fn password_digest_security_block(
    username: &str,
    password: &str,
    nonce_bytes: &[u8],
    created: &str,
    timestamp_created: Option<&str>,
) -> String {
    let nonce_b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, nonce_bytes);

    let mut data = Vec::new();
    data.extend_from_slice(nonce_bytes);
    data.extend_from_slice(created.as_bytes());
    data.extend_from_slice(password.as_bytes());

    let digest = ring::digest::digest(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY, &data);
    let digest_b64 =
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, digest.as_ref());

    let timestamp = timestamp_created.map(bound_timestamp).unwrap_or_default();

    format!(
        r#"{}<wsse:UsernameToken>
        <wsse:Username>{}</wsse:Username>
        <wsse:Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest">{}</wsse:Password>
        <wsse:Nonce EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary">{}</wsse:Nonce>
        <wsu:Created>{}</wsu:Created>
    </wsse:UsernameToken>"#,
        timestamp, username, digest_b64, nonce_b64, created
    )
}

fn fresh_created() -> String {
    chrono::Utc::now()
        .format("%Y-%m-%dT%H:%M:%S%.3fZ")
        .to_string()
}

// ── Constructor validation tests ────────────────────────────────────────────

#[test]
fn test_non_object_config_is_error() {
    let result = SoapWsSecurity::new(&json!(null));
    assert!(result.is_err());
    assert!(result.err().unwrap().contains("config must be an object"));
}

#[test]
fn test_non_object_config_error_is_redacted_and_bounded() {
    // A non-object root can still carry credential-like material or be
    // unbounded. The diagnostic must stay fixed/redacted.
    let secret = "super-secret-password-material-do-not-echo";
    let err = SoapWsSecurity::new(&Value::String(format!("username=alice&password={secret}")))
        .err()
        .expect("non-object must reject");
    assert_eq!(err, "soap_ws_security: config must be an object");
    assert!(!err.contains(secret));
    assert!(!err.contains("alice"));

    let huge = "X".repeat(200_000);
    let huge_err = SoapWsSecurity::new(&Value::String(huge.clone()))
        .err()
        .expect("huge non-object must reject");
    assert_eq!(huge_err, "soap_ws_security: config must be an object");
    assert!(!huge_err.contains(&huge));
    assert!(
        huge_err.len() < 128,
        "non-object diagnostic must stay bounded, got len {}",
        huge_err.len()
    );
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
    const SENTINEL: &str = "SOAP_PASSWORD_TYPE_REJECTED_VALUE_CANARY";
    let config = json!({
        "timestamp": { "require": false },
        "username_token": {
            "enabled": true,
            "password_type": SENTINEL,
            "credentials": [{"username": "a", "password": "b"}]
        }
    });
    let err = SoapWsSecurity::new(&config)
        .err()
        .expect("invalid password_type must reject");
    assert!(
        err.contains("config.username_token.password_type")
            && err.contains("PasswordText")
            && err.contains("PasswordDigest"),
        "unexpected diagnostic: {err}"
    );
    assert!(
        !err.contains(SENTINEL),
        "rejected password_type must be value-redacted: {err}"
    );
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

#[test]
fn test_x509_end_marker_before_begin_fails_without_panicking() {
    let source = "-----END CERTIFICATE-----\n\
                  -----BEGIN CERTIFICATE-----\n\
                  U09BUA==\n";
    let config = json!({
        "timestamp": { "require": false },
        "x509_signature": {
            "enabled": true,
            "trusted_certs": [source]
        }
    });

    let err = SoapWsSecurity::new(&config)
        .err()
        .expect("misordered PEM markers must fail admission");
    assert!(err.contains("failed to decode PEM"), "got: {err}");
    assert!(
        !err.contains(source) && err.contains(INLINE_PEM_DISPLAY),
        "misordered inline PEM must be rejected under a redacted source label: {err}"
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
            "audience": "https://service.example.com",
            "recipient": "https://service.example.com/ws",
            "trusted_signing_certs": [MALFORMED_INLINE_PEM],
            "allowed_signature_algorithms": ["rsa-sha256"]
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

    // Issue #4565: the shared pre-parse nesting screen (256 levels) now fires
    // before the post-parse canonicalization guard for a document this deep,
    // so either fail-closed message satisfies the contract.
    assert!(
        error.contains("depth exceeds") || error.contains("nesting exceeds the supported depth"),
        "unexpected error: {error}"
    );
}

#[test]
fn test_valid_username_token_config() {
    let plugin = SoapWsSecurity::new(&username_token_config()).unwrap();
    assert_eq!(plugin.name(), "soap_ws_security");
}

// ── Non-SOAP request handling ───────────────────────────────────────────────
//
// GHSA-435h-f785-wmm4: pass-through is no longer the consequence of a
// client-chosen header value. On the default `strict` route every request is
// governed; `mixed_route` is the explicit opt-out that restores pass-through.

fn mixed_route_timestamp_only_config() -> serde_json::Value {
    let mut config = timestamp_only_config();
    config["content_type"] = json!({ "mode": "mixed_route" });
    config
}

#[tokio::test]
async fn test_non_soap_content_type_is_rejected_on_a_strict_route() {
    let plugin = SoapWsSecurity::new(&timestamp_only_config()).unwrap();
    let mut ctx = make_ctx_non_soap();
    let mut headers = non_soap_headers();
    let result = run_soap_request_policy(&plugin, &mut ctx, &mut headers).await;
    match result {
        PluginResult::Reject { status_code, .. } => assert_eq!(status_code, 415),
        other => panic!("strict routes must govern every request, got {other:?}"),
    }
}

#[tokio::test]
async fn test_non_soap_content_type_passes_through_on_a_mixed_route() {
    let plugin = SoapWsSecurity::new(&mixed_route_timestamp_only_config()).unwrap();
    let mut ctx = make_ctx_non_soap();
    let mut headers = non_soap_headers();
    let result = run_soap_request_policy(&plugin, &mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
}

#[tokio::test]
async fn test_no_content_type_is_rejected_on_a_strict_route() {
    let plugin = SoapWsSecurity::new(&timestamp_only_config()).unwrap();
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/ws".to_string(),
    );
    let mut headers = HashMap::new();
    let result = run_soap_request_policy(&plugin, &mut ctx, &mut headers).await;
    match result {
        PluginResult::Reject { status_code, .. } => assert_eq!(status_code, 415),
        other => panic!("an absent Content-Type must not skip policy, got {other:?}"),
    }
}

#[tokio::test]
async fn test_no_content_type_passes_through_on_a_mixed_route() {
    let plugin = SoapWsSecurity::new(&mixed_route_timestamp_only_config()).unwrap();
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/ws".to_string(),
    );
    let mut headers = HashMap::new();
    let result = run_soap_request_policy(&plugin, &mut ctx, &mut headers).await;
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
    let result = run_soap_request_policy(&plugin, &mut ctx, &mut headers).await;
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
    let result = run_soap_request_policy(&plugin, &mut ctx, &mut headers).await;
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
    let result = run_soap_request_policy(&plugin, &mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
}

// ── Timestamp validation tests ──────────────────────────────────────────────

#[tokio::test]
async fn test_valid_timestamp_passes() {
    let plugin = SoapWsSecurity::new(&timestamp_only_config()).unwrap();
    let body = wrap_soap(&fresh_timestamp());
    let mut ctx = make_ctx_with_soap_body(&body);
    let mut headers = soap_headers();
    let result = run_soap_request_policy(&plugin, &mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
}

#[tokio::test]
async fn test_missing_timestamp_rejects() {
    let plugin = SoapWsSecurity::new(&timestamp_only_config()).unwrap();
    let body = wrap_soap("<!-- no timestamp -->");
    let mut ctx = make_ctx_with_soap_body(&body);
    let mut headers = soap_headers();
    let result = run_soap_request_policy(&plugin, &mut ctx, &mut headers).await;
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
    let result = run_soap_request_policy(&plugin, &mut ctx, &mut headers).await;
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
    let result = run_soap_request_policy(&plugin, &mut ctx, &mut headers).await;
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
    let result = run_soap_request_policy(&plugin, &mut ctx, &mut headers).await;
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
    let result = run_soap_request_policy(&plugin, &mut ctx, &mut headers).await;
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
    let result = run_soap_request_policy(&plugin, &mut ctx, &mut headers).await;
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
    let result = run_soap_request_policy(&plugin, &mut ctx, &mut headers).await;
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
    let result = run_soap_request_policy(&plugin, &mut ctx, &mut headers).await;
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
    let result = run_soap_request_policy(&plugin, &mut ctx, &mut headers).await;
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
    let result = run_soap_request_policy(&plugin, &mut ctx, &mut headers).await;
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
    let result = run_soap_request_policy(&plugin, &mut ctx, &mut headers).await;
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
    let result = run_soap_request_policy(&plugin, &mut ctx, &mut headers).await;
    assert!(is_reject(&result));
    assert!(reject_body(&result).contains("missing Username"));
}

// ── PasswordDigest tests ────────────────────────────────────────────────────

#[tokio::test]
async fn test_password_digest_valid() {
    let plugin = SoapWsSecurity::new(&username_token_digest_config()).unwrap();

    // Compute a valid PasswordDigest: Base64(SHA-1(nonce + created + password))
    let ut = password_digest_token("alice", "secret123", b"test-nonce-12345");
    let body = wrap_soap(&ut);
    let mut ctx = make_ctx_with_soap_body(&body);
    let mut headers = soap_headers();
    let result = run_soap_request_policy(&plugin, &mut ctx, &mut headers).await;
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

    let ut = password_digest_token("alice", "secret123", b"utf16-nonce-bytes");
    let body = wrap_soap(&ut);
    let bytes = encode_utf16_le(&body);
    let mut ctx = make_ctx_with_soap_bytes(bytes, "application/soap+xml; charset=utf-16");
    let mut headers = soap_headers_with_content_type("application/soap+xml; charset=utf-16");
    let result = run_soap_request_policy(&plugin, &mut ctx, &mut headers).await;
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
    let result = run_soap_request_policy(&plugin, &mut ctx, &mut headers).await;
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
        let result = run_soap_request_policy(plugin, &mut ctx, &mut headers).await;
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
    let result = run_soap_request_policy(&plugin, &mut ctx, &mut headers).await;
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
    let result = run_soap_request_policy(&plugin, &mut ctx, &mut headers).await;
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
    let result = run_soap_request_policy(&plugin, &mut ctx, &mut headers).await;
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
    let result = run_soap_request_policy(&plugin, &mut ctx, &mut headers).await;
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
        let result = run_soap_request_policy(&plugin, &mut ctx, &mut headers).await;
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

    let ut = password_digest_token("alice", "secret123", b"replay-nonce-001");
    let body = wrap_soap(&ut);

    // First request succeeds
    let mut ctx = make_ctx_with_soap_body(&body);
    let mut headers = soap_headers();
    let result = run_soap_request_policy(&plugin, &mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));

    // Second request with same nonce is replay
    let mut ctx2 = make_ctx_with_soap_body(&body);
    let mut headers2 = soap_headers();
    let result2 = run_soap_request_policy(&plugin, &mut ctx2, &mut headers2).await;
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
        let failed = run_soap_request_policy(&plugin, &mut failed_ctx, &mut failed_headers).await;
        assert_username_token_invalid_credentials(
            &failed,
            &[attempt_username, "alice", "eve-candidate"],
        );

        let valid_token =
            password_digest_token_with_created("alice", "secret123", nonce_bytes, &created);
        let valid_body = wrap_soap(&valid_token);
        let mut valid_ctx = make_ctx_with_soap_body(&valid_body);
        let mut valid_headers = soap_headers();
        let valid = run_soap_request_policy(&plugin, &mut valid_ctx, &mut valid_headers).await;
        assert!(
            matches!(valid, PluginResult::Continue),
            "failed attempt for {attempt_username} poisoned the legitimate nonce: {valid:?}"
        );

        let mut replay_ctx = make_ctx_with_soap_body(&valid_body);
        let mut replay_headers = soap_headers();
        let replay = run_soap_request_policy(&plugin, &mut replay_ctx, &mut replay_headers).await;
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
            // Both bindings are mandatory when SAML is enabled and are checked
            // ahead of the trust material, so they must be present for this
            // test to reach the arm it is about.
            "audience": "https://service.example.com",
            "recipient": "https://service.example.com/ws",
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
            "audience": "https://service.example.com",
            "recipient": "https://service.example.com/ws",
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
            Self::with_trusted_cert(TEST_IDP_CERT_PEM)
        }

        /// A bundle whose on-disk trust list holds `cert_pem`. Constructing a
        /// plugin from one of these is exactly what a configuration reload
        /// does, so it is how trust rotation is exercised without a restart.
        pub fn with_trusted_cert(cert_pem: &str) -> Self {
            let dir = tempfile::tempdir().expect("create tempdir");
            let trusted = dir.path().join("trusted-idp.pem");
            std::fs::write(&trusted, cert_pem).expect("write trusted PEM");
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

    pub const SAML_NS: &str = "urn:oasis:names:tc:SAML:2.0:assertion";
    pub const DSIG_NS: &str = "http://www.w3.org/2000/09/xmldsig#";
    pub const TEST_AUDIENCE: &str = "https://service.example.com";
    pub const TEST_RECIPIENT: &str = "https://service.example.com/ws";

    /// A `Conditions` window that is inside policy for a fixture built now.
    pub fn default_not_before() -> String {
        (chrono::Utc::now() - chrono::Duration::seconds(60))
            .format("%Y-%m-%dT%H:%M:%SZ")
            .to_string()
    }

    pub fn default_not_on_or_after() -> String {
        (chrono::Utc::now() + chrono::Duration::seconds(120))
            .format("%Y-%m-%dT%H:%M:%SZ")
            .to_string()
    }

    pub struct AssertionBuilder<'a> {
        pub assertion_id: &'a str,
        pub issuer: &'a str,
        pub subject_name_id: &'a str,
        pub not_before: Option<String>,
        pub not_on_or_after: Option<String>,
        pub audience: Option<String>,
        /// `SubjectConfirmationData/@Recipient`. `None` omits the whole
        /// SubjectConfirmation, which GHSA-f44p-hfqr-cvcc requires be rejected.
        pub recipient: Option<String>,
        pub confirmation_method: &'a str,
        pub confirmation_not_on_or_after: Option<String>,
        pub confirmation_in_response_to: Option<String>,
        pub one_time_use: bool,
        pub sign_with_untrusted_key: bool,
        pub use_sha1_digest: bool,
        /// Insert junk bytes into the assertion AFTER signing to simulate a
        /// tampered payload.
        pub corrupt_subject_after_signing: bool,
        /// Mutate the SignatureValue bytes after signing to simulate a
        /// forged or randomly damaged signature.
        pub corrupt_signature_value: bool,
        /// Replace the whole `<saml:NameID>…</saml:NameID>` fragment inside
        /// `<saml:Subject>`, in both the emitted and the signed view, so a
        /// Subject with no / blank / duplicate NameID still carries a fully
        /// valid IdP signature. `""` removes the NameID entirely.
        pub name_id_fragment: Option<String>,
        /// `SignedInfo/Reference/@URI`, applied **before** the SignedInfo is
        /// canonicalized and signed. Rewriting it after signing would only ever
        /// reach the signature arm: trust and `SignatureValue`-over-`SignedInfo`
        /// are settled before the first Reference is resolved
        /// (GHSA-9g4v-h9hm-846r), so a Reference-scoping test has to sign the
        /// URI it wants judged. `None` targets the enclosing assertion.
        pub reference_uri_override: Option<String>,
    }

    impl<'a> AssertionBuilder<'a> {
        /// A fixture that satisfies every binding the plugin now requires:
        /// bounded Conditions, the service Audience, and a bearer
        /// SubjectConfirmation naming the service Recipient. Negative tests
        /// clear exactly the field they are about.
        pub fn new(assertion_id: &'a str, issuer: &'a str, subject_name_id: &'a str) -> Self {
            Self {
                assertion_id,
                issuer,
                subject_name_id,
                not_before: Some(default_not_before()),
                not_on_or_after: Some(default_not_on_or_after()),
                audience: Some(TEST_AUDIENCE.to_string()),
                recipient: Some(TEST_RECIPIENT.to_string()),
                confirmation_method: "urn:oasis:names:tc:SAML:2.0:cm:bearer",
                confirmation_not_on_or_after: Some(default_not_on_or_after()),
                confirmation_in_response_to: None,
                one_time_use: false,
                sign_with_untrusted_key: false,
                use_sha1_digest: false,
                corrupt_subject_after_signing: false,
                corrupt_signature_value: false,
                name_id_fragment: None,
                reference_uri_override: None,
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
                || self.one_time_use
            {
                conditions.push_str("<saml:Conditions");
                if let Some(nb) = self.not_before.as_deref() {
                    conditions.push_str(&format!(" NotBefore=\"{}\"", nb));
                }
                if let Some(noa) = self.not_on_or_after.as_deref() {
                    conditions.push_str(&format!(" NotOnOrAfter=\"{}\"", noa));
                }
                let mut inner = String::new();
                if let Some(aud) = self.audience.as_deref() {
                    inner.push_str(&format!(
                        "<saml:AudienceRestriction><saml:Audience>{}</saml:Audience></saml:AudienceRestriction>",
                        aud
                    ));
                }
                if self.one_time_use {
                    inner.push_str("<saml:OneTimeUse/>");
                }
                if inner.is_empty() {
                    conditions.push_str("/>");
                } else {
                    conditions.push_str(&format!(">{}</saml:Conditions>", inner));
                }
            }

            let mut confirmation = String::new();
            if let Some(recipient) = self.recipient.as_deref() {
                confirmation.push_str(&format!(
                    "<saml:SubjectConfirmation Method=\"{}\"><saml:SubjectConfirmationData Recipient=\"{}\"",
                    self.confirmation_method, recipient
                ));
                if let Some(noa) = self.confirmation_not_on_or_after.as_deref() {
                    confirmation.push_str(&format!(" NotOnOrAfter=\"{}\"", noa));
                }
                if let Some(in_response_to) = self.confirmation_in_response_to.as_deref() {
                    confirmation.push_str(&format!(" InResponseTo=\"{}\"", in_response_to));
                }
                confirmation.push_str("/></saml:SubjectConfirmation>");
            }

            let subject_inner = if self.corrupt_subject_after_signing {
                // Final subject text differs from what was signed — should
                // make the assertion's digest mismatch what's in SignedInfo.
                format!("evil-{}", self.subject_name_id)
            } else {
                self.subject_name_id.to_string()
            };

            let name_id = |value: &str| match self.name_id_fragment.as_deref() {
                Some(fragment) => fragment.to_string(),
                None => format!("<saml:NameID>{}</saml:NameID>", value),
            };
            let body_after_issuer = format!(
                "<saml:Subject>{}{}</saml:Subject>{}",
                name_id(&subject_inner),
                confirmation,
                conditions
            );

            // The bytes we actually sign use the ORIGINAL (untampered) subject.
            let signed_body_after_issuer = format!(
                "<saml:Subject>{}{}</saml:Subject>{}",
                name_id(self.subject_name_id),
                confirmation,
                conditions
            );

            // The assertion as it looks after enveloped-signature transform —
            // this is what XMLDSIG digests for the Reference. Namespaces are
            // declared on the Assertion element itself so the digested view and
            // the in-envelope view canonicalize identically.
            let assertion_no_sig = format!(
                "<saml:Assertion xmlns:saml=\"{}\" xmlns:ds=\"{}\" ID=\"{}\"><saml:Issuer>{}</saml:Issuer>{}</saml:Assertion>",
                SAML_NS, DSIG_NS, self.assertion_id, self.issuer, signed_body_after_issuer
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
            let reference_uri = self
                .reference_uri_override
                .as_deref()
                .unwrap_or(self.assertion_id);
            let signed_info = format!(
                "<ds:SignedInfo xmlns:ds=\"{}\">\
<ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\
<ds:SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256\"/>\
<ds:Reference URI=\"#{}\">\
<ds:Transforms>\
<ds:Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/>\
<ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\
</ds:Transforms>\
<ds:DigestMethod Algorithm=\"{}\"/>\
<ds:DigestValue>{}</ds:DigestValue>\
</ds:Reference>\
</ds:SignedInfo>",
                DSIG_NS, reference_uri, digest_method_uri, digest_b64
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
                "<ds:Signature xmlns:ds=\"{}\">{}<ds:SignatureValue>{}</ds:SignatureValue>\
<ds:KeyInfo><ds:X509Data><ds:X509Certificate>{}</ds:X509Certificate></ds:X509Data></ds:KeyInfo>\
</ds:Signature>",
                DSIG_NS, signed_info, sig_value_b64, cert_b64
            );

            // Final assertion: Signature follows Issuer, then the body
            // (Subject + Conditions). Envelope-signature transform at
            // verification time removes the first <Signature> element, so
            // the digested view matches `assertion_no_sig`.
            format!(
                "<saml:Assertion xmlns:saml=\"{}\" xmlns:ds=\"{}\" ID=\"{}\"><saml:Issuer>{}</saml:Issuer>{}{}</saml:Assertion>",
                SAML_NS, DSIG_NS, self.assertion_id, self.issuer, signature, body_after_issuer
            )
        }
    }
}

/// SAML policy for the fixtures. `audience` overrides the default service
/// audience so cross-audience tests can bind this proxy to a different service;
/// `audience` and `recipient` are both mandatory now (GHSA-f44p-hfqr-cvcc), as
/// is a declared replay scope for assertion single-use.
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
    saml.insert(
        "audience".into(),
        json!(audience.unwrap_or(saml_fixtures::TEST_AUDIENCE)),
    );
    saml.insert("recipient".into(), json!(saml_fixtures::TEST_RECIPIENT));
    json!({
        "timestamp": { "require": false },
        "saml": Value::Object(saml),
        "nonce": { "replay_scope": "process" },
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
    let result = run_soap_request_policy(&plugin, &mut ctx, &mut headers).await;
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
    let result = run_soap_request_policy(&plugin, &mut ctx, &mut headers).await;
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

    let result = run_soap_request_policy(&plugin, &mut ctx, &mut headers).await;

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

    // Assertion with no Signature element — i.e. exactly the spoofable XML the
    // previous behaviour silently accepted. It must be namespace-qualified:
    // assertion selection is namespace-correct, so a bare `<Assertion>` is not
    // a SAML assertion at all and would be reported as an absent one.
    let unsigned = format!(
        r#"<saml:Assertion xmlns:saml="{ns}" ID="_a"><saml:Issuer>https://idp.example.com/metadata</saml:Issuer><saml:Subject><saml:NameID>alice</saml:NameID></saml:Subject></saml:Assertion>"#,
        ns = saml_fixtures::SAML_NS,
    );
    let body = wrap_saml_assertion(&unsigned);
    let mut ctx = make_ctx_with_soap_body(&body);
    let mut headers = soap_headers();
    let result = run_soap_request_policy(&plugin, &mut ctx, &mut headers).await;
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
    let result = run_soap_request_policy(&plugin, &mut ctx, &mut headers).await;
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
    let result = run_soap_request_policy(&plugin, &mut ctx, &mut headers).await;
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
    let result = run_soap_request_policy(&plugin, &mut ctx, &mut headers).await;
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
    let result = run_soap_request_policy(&plugin, &mut ctx, &mut headers).await;
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

    // The window must stay inside `saml.max_assertion_lifetime_seconds` (300 by
    // default) or the lifetime cap — which is checked first, because it is what
    // makes the fixed replay horizon sufficient — answers instead of the expiry
    // arm this test is about. One hour in the past clears the 300s clock skew.
    let expired_at = chrono::Utc::now() - chrono::Duration::seconds(3_600);
    let nb = (expired_at - chrono::Duration::seconds(60))
        .format("%Y-%m-%dT%H:%M:%SZ")
        .to_string();
    let noa = expired_at.format("%Y-%m-%dT%H:%M:%SZ").to_string();
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
    let result = run_soap_request_policy(&plugin, &mut ctx, &mut headers).await;
    assert!(is_reject(&result));
    assert!(
        reject_body(&result).contains("has expired"),
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
    let noa = (chrono::Utc::now() + chrono::Duration::days(7) + chrono::Duration::seconds(120))
        .format("%Y-%m-%dT%H:%M:%SZ")
        .to_string();
    let mut builder = saml_fixtures::AssertionBuilder::new(
        "_assertion-future",
        "https://idp.example.com/metadata",
        "alice@example.com",
    );
    builder.not_before = Some(nb.clone());
    builder.not_on_or_after = Some(noa.clone());
    builder.confirmation_not_on_or_after = Some(noa.clone());
    let assertion = builder.build();

    let body = wrap_saml_assertion(&assertion);
    let mut ctx = make_ctx_with_soap_body(&body);
    let mut headers = soap_headers();
    let result = run_soap_request_policy(&plugin, &mut ctx, &mut headers).await;
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
    let nb = saml_fixtures::default_not_before();
    let noa = saml_fixtures::default_not_on_or_after();
    builder.not_before = Some(nb.clone());
    builder.not_on_or_after = Some(noa.clone());
    builder.audience = Some("https://other-service.example.com".to_string());
    let assertion = builder.build();

    let body = wrap_saml_assertion(&assertion);
    let mut ctx = make_ctx_with_soap_body(&body);
    let mut headers = soap_headers();
    let result = run_soap_request_policy(&plugin, &mut ctx, &mut headers).await;
    assert!(is_reject(&result));
    assert!(
        reject_body(&result).contains("does not admit this service"),
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

    let mut builder = saml_fixtures::AssertionBuilder::new(
        "_assertion-no-conditions",
        "https://idp.example.com/metadata",
        "alice@example.com",
    );
    builder.not_before = None;
    builder.not_on_or_after = None;
    builder.audience = None;
    let assertion = builder.build();

    let body = wrap_saml_assertion(&assertion);
    let mut ctx = make_ctx_with_soap_body(&body);
    let mut headers = soap_headers();
    let result = run_soap_request_policy(&plugin, &mut ctx, &mut headers).await;
    assert!(is_reject(&result));
    assert!(
        reject_body(&result).contains("bounded validity window is required"),
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

    let mut builder = saml_fixtures::AssertionBuilder::new(
        "_assertion-no-audience-restriction",
        "https://idp.example.com/metadata",
        "alice@example.com",
    );
    builder.audience = None;
    let assertion = builder.build();

    let body = wrap_saml_assertion(&assertion);
    let mut ctx = make_ctx_with_soap_body(&body);
    let mut headers = soap_headers();
    let result = run_soap_request_policy(&plugin, &mut ctx, &mut headers).await;
    assert!(is_reject(&result));
    assert!(
        reject_body(&result).contains("must carry an AudienceRestriction"),
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
    let result = run_soap_request_policy(&plugin, &mut ctx, &mut headers).await;
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

    // The mis-targeted URI is *signed in*, not patched over afterwards: the IdP
    // signature and the assertion digest are both authentic, so the only thing
    // left to refuse the message is the Reference-scoping rule itself. Patching
    // the URI after signing would invalidate SignedInfo and be caught one arm
    // earlier, proving nothing about scoping.
    let mut builder = saml_fixtures::AssertionBuilder::new(
        "_assertion-real-id",
        "https://idp.example.com/metadata",
        "alice@example.com",
    );
    builder.reference_uri_override = Some("somewhere-else".to_string());
    let assertion = builder.build();

    let body = wrap_saml_assertion(&assertion);
    let mut ctx = make_ctx_with_soap_body(&body);
    let mut headers = soap_headers();
    let result = run_soap_request_policy(&plugin, &mut ctx, &mut headers).await;
    assert!(is_reject(&result));
    assert!(
        reject_body(&result).contains("does not target the enclosing Assertion"),
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

    let mut builder = saml_fixtures::AssertionBuilder::new(
        "_assertion-wrapping",
        "https://idp.example.com/metadata",
        "alice@example.com",
    );
    builder.audience = Some("https://my-service.example.com".to_string());
    let assertion = builder.build();

    // Decoy Subject/Conditions injected INSIDE the Signature element, where
    // the enveloped-signature transform excludes them from the digest and the
    // namespace-qualified child resolvers never look.
    let wrapped = assertion.replace(
        "<ds:SignedInfo",
        "<saml:Subject><saml:NameID>admin@example.com</saml:NameID></saml:Subject><ds:SignedInfo",
    );

    let body = wrap_saml_assertion(&wrapped);
    let mut ctx = make_ctx_with_soap_body(&body);
    let mut headers = soap_headers();
    let result = run_soap_request_policy(&plugin, &mut ctx, &mut headers).await;
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
    let result = run_soap_request_policy(&plugin, &mut ctx, &mut headers).await;
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

    // The decoy must be a namespace-correct SAML Assertion: that is what a
    // downstream consumer walking the Body would pick up, and it is what the
    // envelope-wide single-assertion scan is defined over.
    let decoy = format!(
        "<saml:Assertion xmlns:saml=\"{ns}\" ID=\"body-assertion\">\
         <saml:Issuer>https://evil.example.com</saml:Issuer>\
         <saml:Subject><saml:NameID>mallory@example.com</saml:NameID></saml:Subject>\
         </saml:Assertion>",
        ns = saml_fixtures::SAML_NS,
    );
    let body = wrap_saml_assertion(&valid).replace("<soap:Body>", &format!("<soap:Body>{decoy}"));
    let mut ctx = make_ctx_with_soap_body(&body);
    let mut headers = soap_headers();
    let result = run_soap_request_policy(&plugin, &mut ctx, &mut headers).await;

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
    for content_type in ["text/xml; charset=\"utf-8", "text/xml; charset=utf-8\""] {
        let err = soap_decode_xml_body_for_test(xml.as_bytes(), content_type)
            .expect_err("unbalanced charset quotes must fail closed");
        assert!(err.contains("conflicting or ambiguous"), "got: {err}");
    }
}

#[test]
fn decode_does_not_treat_single_quotes_as_parameter_delimiters() {
    let xml = wrap_soap(&fresh_timestamp());
    for content_type in ["text/xml; charset='utf-8'", "text/xml; charset='utf-8"] {
        let err = soap_decode_xml_body_for_test(xml.as_bytes(), content_type)
            .expect_err("a single quote is part of a token, not MIME quoted-string syntax");
        assert!(err.contains("unsupported character encoding"), "got: {err}");
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
    let result = run_soap_request_policy(&plugin, &mut ctx, &mut headers).await;
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
    let result = run_soap_request_policy(&plugin, &mut ctx, &mut headers).await;
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
    let result = run_soap_request_policy(&plugin, &mut ctx, &mut headers).await;
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
    let result = run_soap_request_policy(&plugin, &mut ctx, &mut headers).await;
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
    let result = run_soap_request_policy(&plugin, &mut ctx, &mut headers).await;
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
    let result = run_soap_request_policy(&plugin, &mut ctx, &mut headers).await;
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
    let result = run_soap_request_policy(&plugin, &mut ctx, &mut headers).await;
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
    let result = run_soap_request_policy(&plugin, &mut ctx, &mut headers).await;
    assert!(is_reject(&result));
    let body = reject_body(&result);
    assert!(
        body.contains("not a namespace-qualified SOAP Envelope"),
        "{body}"
    );
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

    let result = run_soap_request_policy(&plugin, &mut ctx, &mut headers).await;
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
    let result = run_soap_request_policy(&plugin, &mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
}

#[tokio::test]
async fn test_empty_body_rejects() {
    let plugin = SoapWsSecurity::new(&timestamp_only_config()).unwrap();
    let mut ctx = make_ctx_with_soap_body("");
    let mut headers = soap_headers();
    let result = run_soap_request_policy(&plugin, &mut ctx, &mut headers).await;
    assert!(is_reject(&result));
}

// ── Nonce cache cap enforcement tests ───────────────────────────────────────

#[test]
fn test_nonce_cache_enforces_max_size_without_evicting_live_entries() {
    let max_size: usize = 20;
    let plugin = SoapWsSecurity::new(&json!({
        "timestamp": { "require": true },
        "nonce": { "max_cache_size": max_size },
        "reject_missing_security_header": false
    }))
    .unwrap();

    // Fill the cache with live nonces.
    for i in 0..max_size {
        let nonce = format!("nonce-{}", i);
        assert!(
            plugin.check_nonce_replay(&nonce).is_ok(),
            "nonce {i} must fill an available slot"
        );
    }

    // Fresh nonces fail closed while every retained entry is still live.
    for i in max_size..(max_size + 50) {
        let nonce = format!("nonce-{}", i);
        let error = plugin
            .check_nonce_replay(&nonce)
            .expect_err("capacity must reject instead of evicting a live nonce");
        assert!(error.contains("at capacity"), "{error}");
    }

    // Oldest and newest retained claims remain protected for their full TTL.
    for nonce in ["nonce-0", "nonce-19"] {
        let error = plugin
            .check_nonce_replay(nonce)
            .expect_err("live nonce must remain replay-protected");
        assert!(error.contains("replay detected"), "{error}");
    }
}

#[test]
fn test_nonce_replay_detected_via_direct_api() {
    let plugin = SoapWsSecurity::new(&json!({
        "timestamp": { "require": true },
        "nonce": { "max_cache_size": 100 },
        "reject_missing_security_header": false
    }))
    .unwrap();

    assert!(plugin.check_nonce_replay("unique-nonce").is_ok());
    assert!(plugin.check_nonce_replay("unique-nonce").is_err());
}

#[test]
fn test_nonce_cache_refreshes_occupied_entry_after_ttl() {
    // Once the fixed retention horizon has elapsed, the atomic entry path must
    // refresh inserted_at instead of treating reuse as a live replay. This
    // covers the post-retention Occupied insert branch used by successful
    // PasswordDigest authentication. The external harness supplies
    // deterministic monotonic instants, so no wall-clock sleep is required.
    let harness = SoapNonceReplayHarness::new(&json!({
        "timestamp": { "require": true },
        "nonce": { "max_cache_size": 100 },
        "reject_missing_security_header": false
    }))
    .unwrap();

    assert!(
        harness
            .claim_at("ttl-expired-nonce", Duration::ZERO)
            .is_ok()
    );
    assert!(
        harness
            .claim_at(
                "ttl-expired-nonce",
                Duration::from_secs(CLAIM_RETENTION_SECONDS - 1)
            )
            .is_err(),
        "a repeat inside the retention horizon is a live replay"
    );
    assert!(
        harness
            .claim_at(
                "ttl-expired-nonce",
                Duration::from_secs(CLAIM_RETENTION_SECONDS)
            )
            .is_ok(),
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

    const WSU_NAMESPACE_URI_FOR_TESTS: &str =
        "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd";

    /// Open tag of the signed Body, used as the injection anchor by the XML
    /// Signature Wrapping fixtures.
    const SIGNED_BODY_OPEN_TAG: &str = r#"<soap:Body wsu:Id="Body-1">"#;

    /// The signed, backend-visible SOAP Body used by every X.509 fixture. Its
    /// `wsu:Id` is what the second `<Reference>` resolves to.
    const SIGNED_BODY_XML: &str = concat!(
        r#"<soap:Body wsu:Id="Body-1">"#,
        r#"<GetPrice xmlns="http://example.com/prices"><Item>Widget</Item></GetPrice>"#,
        r#"</soap:Body>"#,
    );

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
        build_signed_soap_envelope_full(cert, timestamp_prefix, SIGNED_BODY_XML, |signed_info| {
            signed_info
        })
    }

    /// Same fixture, but the `SignedInfo` is rewritten **before** it is
    /// canonicalized and signed, so the emitted envelope carries an authentic
    /// `SignatureValue` over exactly the `SignedInfo` on the wire.
    ///
    /// Trust and `SignatureValue`-over-`SignedInfo` are now settled before the
    /// first attacker-selected `<Reference>` is resolved
    /// (GHSA-9g4v-h9hm-846r). A fixture that edits `SignedInfo` after signing
    /// can therefore only ever reach the signature arm; anything that must be
    /// judged by a per-`Reference` rule has to be signed in.
    fn build_signed_soap_envelope_with_signed_info(
        cert: &TestRsaCert,
        rewrite_signed_info: impl FnOnce(String) -> String,
    ) -> String {
        build_signed_soap_envelope_full(cert, "wsu", SIGNED_BODY_XML, rewrite_signed_info)
    }

    /// Same fixture with a caller-supplied signed Body.
    ///
    /// X.509 success now requires a Reference resolving uniquely to the
    /// backend-visible Body (GHSA-3mwq-c8j6-9xhp), so a fixture that edits the
    /// Body after signing is a digest mismatch by construction. A Body variant
    /// that is meant to be *accepted* must be digested in.
    fn build_signed_soap_envelope_with_signed_body(
        cert: &TestRsaCert,
        signed_body_xml: &str,
    ) -> String {
        build_signed_soap_envelope_full(cert, "wsu", signed_body_xml, |signed_info| signed_info)
    }

    fn build_signed_soap_envelope_full(
        cert: &TestRsaCert,
        timestamp_prefix: &str,
        signed_body_xml: &str,
        rewrite_signed_info: impl FnOnce(String) -> String,
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

        // GHSA-3mwq-c8j6-9xhp: an accepted X.509 signature must cover the
        // namespace-correct, backend-visible SOAP Body, not just a header
        // fragment. The fixture therefore signs both.
        let body_context = format!(
            r#"<root xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:wsu="{wsu}">{body}</root>"#,
            wsu = WSU_NAMESPACE_URI_FOR_TESTS,
            body = signed_body_xml,
        );
        let canonical_body =
            soap_exclusive_canonicalize_element_for_test(&body_context, "Body", "soap")
                .expect("test Body must canonicalize");
        let body_digest = ring::digest::digest(&ring::digest::SHA256, canonical_body.as_bytes());
        let body_digest_b64 = B64.encode(body_digest.as_ref());

        let signed_info = format!(
            r##"<SignedInfo><CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"><ec:InclusiveNamespaces xmlns:ec="http://www.w3.org/2001/10/xml-exc-c14n#" PrefixList="soap"/></CanonicalizationMethod><SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><Reference URI="#TS-1"><Transforms><Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"><ec:InclusiveNamespaces xmlns:ec="http://www.w3.org/2001/10/xml-exc-c14n#" PrefixList="soap"/></Transform></Transforms><DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><DigestValue>{}</DigestValue></Reference><Reference URI="#Body-1"><Transforms><Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"><ec:InclusiveNamespaces xmlns:ec="http://www.w3.org/2001/10/xml-exc-c14n#" PrefixList="soap"/></Transform></Transforms><DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><DigestValue>{}</DigestValue></Reference></SignedInfo>"##,
            ts_digest_b64, body_digest_b64
        );
        let signed_info = rewrite_signed_info(signed_info);
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
            r#"<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
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
  {signed_body}
</soap:Envelope>"#,
            signed_body = signed_body_xml,
            timestamp = timestamp_xml,
            timestamp_prefix = timestamp_prefix,
            cert_b64 = cert.cert_der_b64,
            signed_info = signed_info,
            sig_b64 = signature_b64,
        )
    }

    /// A trusted-store plugin plus a certificate the store does NOT contain,
    /// shared with the advisory-regression module so the trust-before-work
    /// ordering can be pinned against a real trust store.
    pub(super) fn trusted_plugin_for_advisory_test() -> (SoapWsSecurity, tempfile::NamedTempFile) {
        let cert = mint_rsa_cert();
        let cert_file = write_pem_to_tempfile(&cert.cert_pem);
        let plugin = SoapWsSecurity::new(&x509_plugin_config(cert_file.path()))
            .expect("plugin should construct with a valid RSA trust store");
        (plugin, cert_file)
    }

    /// Base64 DER of a certificate that is never in the trust store.
    pub(super) fn untrusted_cert_der_b64() -> String {
        mint_rsa_cert().cert_der_b64
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

    // ── X.509 integrity vs MTOM/XOP attachments ─────────────────────────
    //
    // An X.509 policy claims integrity over the message the backend executes.
    // Ferrum implements no WS-Security attachment-signature transform, so for
    // a XOP representation the digest it verifies covers the `xop:Include`
    // element, not the attachment octets that element stands for: an
    // attacker-selected attachment present during validation is never
    // detected. Refusing the representation is the honest outcome.

    /// MTOM/XOP `multipart/related` is refused before dispatch, and its body is
    /// not even buffered.
    #[tokio::test]
    async fn mtom_is_refused_when_x509_claims_integrity() {
        let cert = mint_rsa_cert();
        let cert_file = write_pem_to_tempfile(&cert.cert_pem);
        let plugin = SoapWsSecurity::new(&x509_plugin_config(cert_file.path())).unwrap();

        let content_type = "multipart/related; type=\"application/xop+xml\"; \
                            boundary=MIME_boundary; start=\"<root@example.com>\"";
        let package = "--MIME_boundary\r\n\
             Content-Type: application/xop+xml; charset=utf-8; type=\"text/xml\"\r\n\
             Content-Transfer-Encoding: binary\r\n\
             Content-ID: <root@example.com>\r\n\
             \r\n\
             <soap:Envelope/>\r\n\
             --MIME_boundary--\r\n";

        let mut ctx = make_ctx_with_soap_bytes(package.as_bytes().to_vec(), content_type);
        assert!(
            !plugin.should_buffer_request_body(&ctx),
            "a refused representation must not be buffered"
        );
        let mut headers = soap_headers_with_content_type(content_type);
        match run_soap_request_policy(&plugin, &mut ctx, &mut headers).await {
            PluginResult::Reject {
                status_code, body, ..
            } => {
                assert_eq!(status_code, 415);
                assert!(body.contains("attachment octets"), "got: {body}");
            }
            other => panic!("MTOM under an X.509 policy must be refused, got {other:?}"),
        }
    }

    /// A bare `application/xop+xml` infoset is the same claim without the
    /// package, and is refused for the same reason.
    #[tokio::test]
    async fn bare_xop_infoset_is_refused_when_x509_claims_integrity() {
        let cert = mint_rsa_cert();
        let cert_file = write_pem_to_tempfile(&cert.cert_pem);
        let plugin = SoapWsSecurity::new(&x509_plugin_config(cert_file.path())).unwrap();

        let content_type = "application/xop+xml; charset=utf-8; type=\"text/xml\"";
        let body = build_signed_soap_envelope(&cert);
        let mut ctx = make_ctx_with_soap_bytes(body.into_bytes(), content_type);
        let mut headers = soap_headers_with_content_type(content_type);
        match run_soap_request_policy(&plugin, &mut ctx, &mut headers).await {
            PluginResult::Reject { status_code, .. } => assert_eq!(status_code, 415),
            other => panic!("bare XOP under an X.509 policy must be refused, got {other:?}"),
        }
    }

    /// The refusal is narrow: plain XML representations are unaffected, and a
    /// policy that authenticates identity rather than asserting message
    /// integrity keeps accepting XOP.
    #[tokio::test]
    async fn the_xop_refusal_is_narrow() {
        let cert = mint_rsa_cert();
        let cert_file = write_pem_to_tempfile(&cert.cert_pem);
        let plugin = SoapWsSecurity::new(&x509_plugin_config(cert_file.path())).unwrap();
        let body = build_signed_soap_envelope(&cert);
        let mut ctx = make_ctx_with_soap_body(&body);
        let mut headers = soap_headers();
        assert!(
            matches!(
                run_soap_request_policy(&plugin, &mut ctx, &mut headers).await,
                PluginResult::Continue
            ),
            "text/xml under an X.509 policy is still governed and still accepted"
        );

        // UsernameToken authenticates the caller; it never claimed coverage of
        // attachment octets, so MTOM/XOP stays available to it.
        let ut = SoapWsSecurity::new(&username_token_config()).unwrap();
        let xop_ctx = make_ctx_with_soap_bytes(b"x".to_vec(), "application/xop+xml");
        assert!(ut.should_buffer_request_body(&xop_ctx));

        let package = "multipart/related; type=\"application/xop+xml\"; boundary=b";
        let mtom_ctx = make_ctx_with_soap_bytes(b"x".to_vec(), package);
        assert!(ut.should_buffer_request_body(&mtom_ctx));
    }

    /// Asking for both in one configuration is asking for integrity Ferrum
    /// cannot establish, so the explicit pairing is refused at admission.
    #[test]
    fn explicit_allow_mtom_with_x509_is_refused_at_admission() {
        let cert = mint_rsa_cert();
        let cert_file = write_pem_to_tempfile(&cert.cert_pem);

        let mut config = x509_plugin_config(cert_file.path());
        config["content_type"] = json!({ "allow_mtom": true });
        let err = SoapWsSecurity::new(&config)
            .err()
            .expect("allow_mtom alongside x509_signature must be refused");
        assert!(err.contains("allow_mtom"), "got: {err}");

        // The honest pairing constructs.
        let mut config = x509_plugin_config(cert_file.path());
        config["content_type"] = json!({ "allow_mtom": false });
        assert!(SoapWsSecurity::new(&config).is_ok());
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
        let result = run_soap_request_policy(&plugin, &mut ctx, &mut headers).await;

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
        let result = run_soap_request_policy(&plugin, &mut ctx, &mut headers).await;

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
        let result = run_soap_request_policy(&plugin, &mut ctx, &mut headers).await;

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
        // The Transform is inside SignedInfo, and SignedInfo is authenticated
        // before any Reference is resolved, so the unsupported algorithm has to
        // be signed in — otherwise this only ever proves the signature check
        // works.
        let body = build_signed_soap_envelope_with_signed_info(&cert, |signed_info| {
            signed_info.replace(
                "<Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\">",
                "<Transform Algorithm=\"urn:unsupported:transform\">",
            )
        });

        let mut ctx = make_ctx_with_soap_body(&body);
        let mut headers = soap_headers();
        let result = run_soap_request_policy(&plugin, &mut ctx, &mut headers).await;

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

        let result = run_soap_request_policy(&plugin, &mut ctx, &mut headers).await;

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
        let body = build_signed_soap_envelope(&cert).replace(
            SIGNED_BODY_OPEN_TAG,
            &format!("{SIGNED_BODY_OPEN_TAG}{many_nodes}"),
        );
        let mut ctx = make_ctx_with_soap_body(&body);
        let mut headers = soap_headers();

        let result = run_soap_request_policy(&plugin, &mut ctx, &mut headers).await;

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
        let result = run_soap_request_policy(&plugin, &mut ctx, &mut headers).await;

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
        let result = run_soap_request_policy(&plugin, &mut ctx, &mut headers).await;

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
            SIGNED_BODY_OPEN_TAG,
            &format!("{SIGNED_BODY_OPEN_TAG}<Injected wsu:Id=\"TS-1\" \
             xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\">\
             attacker-controlled</Injected>"),
        );
        assert_ne!(
            valid, wrapped,
            "duplicate-id injection must modify the envelope"
        );

        let mut ctx = make_ctx_with_soap_body(&wrapped);
        let mut headers = soap_headers();
        let result = run_soap_request_policy(&plugin, &mut ctx, &mut headers).await;

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

        let result = run_soap_request_policy(&plugin, &mut ctx, &mut headers).await;

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
            SIGNED_BODY_OPEN_TAG,
            &format!("{SIGNED_BODY_OPEN_TAG}<Injected wsu:Id=\"TS-1\" \
             xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\">attacker</Injected>"),
        );
        let mut ctx = make_ctx_with_soap_body(&wrapped);
        let mut headers = soap_headers();

        let result = run_soap_request_policy(&plugin, &mut ctx, &mut headers).await;

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

        // Two `wsse:Security` header blocks: the signed one is addressed to
        // another intermediary (`soap:actor`), so it is not this receiver's to
        // enforce and must not satisfy verification. The one this gateway
        // selects — the unaddressed block — carries no Signature.
        //
        // The signed block stays a direct child of `soap:Header`. Parking it
        // outside the Header (as a sibling of it, say) is refused structurally
        // before selection ever runs, which would prove nothing about scoping.
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

        // SOAP 1.1 addresses a header block with `soap:actor`.
        let other_actor_security = signed_security.replacen(
            "<wsse:Security",
            "<wsse:Security soap:actor=\"urn:example:other-intermediary\"",
            1,
        );
        let header_unsigned = valid.replacen(signed_security, &unsigned_security, 1);
        let body = header_unsigned.replacen(
            "<soap:Header>",
            &format!("<soap:Header>{other_actor_security}"),
            1,
        );
        let mut ctx = make_ctx_with_soap_body(&body);
        let mut headers = soap_headers();

        let result = run_soap_request_policy(&plugin, &mut ctx, &mut headers).await;

        assert!(is_reject(&result));
        assert!(
            reject_body(&result).contains("missing Signature"),
            "a Security block addressed elsewhere must not satisfy header verification: {}",
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
            SIGNED_BODY_OPEN_TAG,
            &format!("{SIGNED_BODY_OPEN_TAG}<Injected Id='TS-1'>attacker-controlled</Injected>"),
        );
        assert_ne!(
            valid, wrapped,
            "bare duplicate-id injection must modify the envelope"
        );

        let mut ctx = make_ctx_with_soap_body(&wrapped);
        let mut headers = soap_headers();
        let result = run_soap_request_policy(&plugin, &mut ctx, &mut headers).await;

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

        // The attribute lives in the signed, backend-visible Body, so it has to
        // be digested in: X.509 success now requires a Reference resolving to
        // that Body, and adding the attribute afterwards would simply be a
        // digest mismatch rather than a test of the uniqueness count.
        let signed_body = SIGNED_BODY_XML.replace(
            "<GetPrice xmlns=\"http://example.com/prices\">",
            "<GetPrice xmlns=\"http://example.com/prices\" CorrelationId=\"TS-1\">",
        );
        assert_ne!(
            SIGNED_BODY_XML, signed_body,
            "business attribute injection must modify the signed Body"
        );
        let with_business_attr = build_signed_soap_envelope_with_signed_body(&cert, &signed_body);
        assert!(
            with_business_attr.contains("CorrelationId=\"TS-1\""),
            "the emitted envelope must carry the business attribute"
        );

        let mut ctx = make_ctx_with_soap_body(&with_business_attr);
        let mut headers = soap_headers();
        let result = run_soap_request_policy(&plugin, &mut ctx, &mut headers).await;
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
        let result = run_soap_request_policy(&plugin, &mut ctx, &mut headers).await;

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
        //
        // The flip is applied before signing. DigestValue lives inside
        // SignedInfo, which is authenticated before any Reference is resolved,
        // so flipping it on the wire would be caught as a signature failure and
        // the digest arm would never run.
        let body = build_signed_soap_envelope_with_signed_info(&cert, |signed_info| {
            let dv_open = signed_info
                .find("<DigestValue>")
                .expect("SignedInfo must have <DigestValue>")
                + "<DigestValue>".len();
            let first_char = signed_info.as_bytes()[dv_open];
            let replacement = if first_char == b'A' { 'B' } else { 'A' };
            let mut tampered = String::with_capacity(signed_info.len());
            tampered.push_str(&signed_info[..dv_open]);
            tampered.push(replacement);
            tampered.push_str(&signed_info[dv_open + 1..]);
            tampered
        });

        let mut ctx = make_ctx_with_soap_body(&body);
        let mut headers = soap_headers();
        let result = run_soap_request_policy(&plugin, &mut ctx, &mut headers).await;

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

// ── #2329: compressed SOAP + compression decompress_request interoperability ─

fn gzip_compress(plaintext: &[u8]) -> Vec<u8> {
    use flate2::write::GzEncoder;
    use std::io::Write;
    let mut encoder = GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(plaintext).unwrap();
    encoder.finish().unwrap()
}

fn brotli_compress(plaintext: &[u8]) -> Vec<u8> {
    let params = brotli::enc::BrotliEncoderParams::default();
    let mut compressed = Vec::new();
    brotli::BrotliCompress(&mut &plaintext[..], &mut compressed, &params).unwrap();
    compressed
}

async fn run_compressed_soap_lifecycle(
    encoding: &str,
    compressed: Vec<u8>,
    plaintext: &str,
    max_decompressed_request_size: Option<usize>,
) -> (
    PluginResult,
    Vec<u8>,
    HashMap<String, String>,
    RequestContext,
) {
    use ferrum_edge::_test_support::apply_buffered_request_body_normalization_before_before_proxy_for_test;
    use ferrum_edge::plugins::compression::CompressionPlugin;
    use std::sync::Arc;

    let mut compression_cfg = json!({ "decompress_request": true });
    if let Some(limit) = max_decompressed_request_size {
        compression_cfg["max_decompressed_request_size"] = json!(limit);
    }
    let compression = Arc::new(CompressionPlugin::new(&compression_cfg).unwrap());
    let soap = SoapWsSecurity::new(&timestamp_only_config()).unwrap();

    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/ws".to_string(),
    );
    ctx.headers
        .insert("content-type".to_string(), "text/xml".to_string());
    ctx.headers
        .insert("content-encoding".to_string(), encoding.to_string());
    ctx.request_body_bytes = Some(bytes::Bytes::copy_from_slice(&compressed));

    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "text/xml".to_string());
    headers.insert("content-encoding".to_string(), encoding.to_string());
    headers.insert("content-length".to_string(), compressed.len().to_string());

    let mut body = compressed;
    let plugins: Vec<Arc<dyn Plugin>> = vec![Arc::clone(&compression) as Arc<dyn Plugin>];
    let normalize = apply_buffered_request_body_normalization_before_before_proxy_for_test(
        &plugins,
        &mut ctx,
        &mut headers,
        &mut body,
    )
    .await;
    if !matches!(normalize, PluginResult::Continue) {
        return (normalize, body, headers, ctx);
    }

    // SOAP runs at priority 1500, before compression's before_proxy (4050).
    // After shared normalization it must see plaintext XML.
    assert_eq!(
        ctx.request_body_bytes.as_deref(),
        Some(plaintext.as_bytes()),
        "normalization must expose plaintext to soap_ws_security"
    );
    let soap_result = run_soap_request_policy(&soap, &mut ctx, &mut headers).await;
    assert!(
        matches!(soap_result, PluginResult::Continue),
        "soap_ws_security must accept decompressed SOAP, got {soap_result:?}"
    );

    assert!(matches!(
        compression.before_proxy(&mut ctx, &mut headers).await,
        PluginResult::Continue
    ));

    let transformed = compression
        .transform_request_body_with_context(&mut ctx, &body, Some("text/xml"), &headers)
        .await;
    assert!(
        transformed.is_none(),
        "already-normalized plaintext must not be decoded again"
    );
    assert_eq!(body.as_slice(), plaintext.as_bytes());
    assert!(!headers.contains_key("content-encoding"));
    assert!(!headers.contains_key("content-length"));

    (PluginResult::Continue, body, headers, ctx)
}

#[tokio::test]
async fn compressed_gzip_soap_is_visible_to_ws_security_before_validation() {
    let plaintext = wrap_soap(&fresh_timestamp());
    let compressed = gzip_compress(plaintext.as_bytes());
    let (result, body, headers, _) =
        run_compressed_soap_lifecycle("gzip", compressed, &plaintext, None).await;
    assert!(matches!(result, PluginResult::Continue));
    assert_eq!(body.as_slice(), plaintext.as_bytes());
    assert!(!headers.contains_key("content-encoding"));
}

#[tokio::test]
async fn compressed_brotli_soap_is_visible_to_ws_security_before_validation() {
    let plaintext = wrap_soap(&fresh_timestamp());
    let compressed = brotli_compress(plaintext.as_bytes());
    let (result, body, headers, _) =
        run_compressed_soap_lifecycle("br", compressed, &plaintext, None).await;
    assert!(matches!(result, PluginResult::Continue));
    assert_eq!(body.as_slice(), plaintext.as_bytes());
    assert!(!headers.contains_key("content-encoding"));
}

#[tokio::test]
async fn malformed_gzip_soap_is_rejected_before_ws_security() {
    use ferrum_edge::_test_support::apply_buffered_request_body_normalization_before_before_proxy_for_test;
    use ferrum_edge::plugins::compression::CompressionPlugin;
    use std::sync::Arc;

    let compression =
        Arc::new(CompressionPlugin::new(&json!({ "decompress_request": true })).unwrap());
    let soap = SoapWsSecurity::new(&timestamp_only_config()).unwrap();
    let corrupt = vec![0x1f, 0x8b, 0x08, 0x00, 0xde, 0xad, 0xbe, 0xef, 0x00];

    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/ws".to_string(),
    );
    ctx.headers
        .insert("content-type".to_string(), "text/xml".to_string());
    ctx.headers
        .insert("content-encoding".to_string(), "gzip".to_string());
    ctx.request_body_bytes = Some(bytes::Bytes::copy_from_slice(&corrupt));

    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "text/xml".to_string());
    headers.insert("content-encoding".to_string(), "gzip".to_string());
    headers.insert("content-length".to_string(), corrupt.len().to_string());

    let mut body = corrupt.clone();
    let plugins: Vec<Arc<dyn Plugin>> = vec![compression as Arc<dyn Plugin>];
    let normalize = apply_buffered_request_body_normalization_before_before_proxy_for_test(
        &plugins,
        &mut ctx,
        &mut headers,
        &mut body,
    )
    .await;
    match normalize {
        PluginResult::Reject { status_code, .. } => assert_eq!(status_code, 400),
        other => panic!("expected Reject for malformed gzip, got {other:?}"),
    }
    assert_eq!(
        headers.get("content-encoding").map(String::as_str),
        Some("gzip"),
        "headers must stay intact on failed decode"
    );
    assert!(headers.contains_key("content-length"));

    // SOAP must not run after a failed normalize in production ordering; pin that
    // the still-compressed bytes would not validate as SOAP XML.
    let soap_on_compressed = run_soap_request_policy(&soap, &mut ctx, &mut headers).await;
    assert!(
        is_reject(&soap_on_compressed),
        "compressed bytes must not satisfy SOAP validation"
    );
}

#[tokio::test]
async fn over_limit_gzip_soap_is_rejected_before_ws_security() {
    use ferrum_edge::_test_support::apply_buffered_request_body_normalization_before_before_proxy_for_test;
    use ferrum_edge::plugins::compression::CompressionPlugin;
    use std::sync::Arc;

    let compression = Arc::new(
        CompressionPlugin::new(&json!({
            "decompress_request": true,
            "max_decompressed_request_size": 64,
        }))
        .unwrap(),
    );
    let big = "A".repeat(500);
    let compressed = gzip_compress(big.as_bytes());

    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/ws".to_string(),
    );
    ctx.headers
        .insert("content-type".to_string(), "text/xml".to_string());
    ctx.headers
        .insert("content-encoding".to_string(), "gzip".to_string());
    ctx.request_body_bytes = Some(bytes::Bytes::copy_from_slice(&compressed));

    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "text/xml".to_string());
    headers.insert("content-encoding".to_string(), "gzip".to_string());
    headers.insert("content-length".to_string(), compressed.len().to_string());

    let mut body = compressed;
    let plugins: Vec<Arc<dyn Plugin>> = vec![compression as Arc<dyn Plugin>];
    let normalize = apply_buffered_request_body_normalization_before_before_proxy_for_test(
        &plugins,
        &mut ctx,
        &mut headers,
        &mut body,
    )
    .await;
    match normalize {
        PluginResult::Reject { status_code, .. } => assert_eq!(status_code, 400),
        other => panic!("expected Reject for over-limit gzip, got {other:?}"),
    }
    assert_eq!(
        headers.get("content-encoding").map(String::as_str),
        Some("gzip")
    );
}

#[tokio::test]
async fn compressed_soap_without_early_normalization_is_rejected_by_ws_security() {
    // Documents the pre-fix failure mode: soap_ws_security at 1500 sees gzip
    // bytes before compression's later hooks can decode them.
    let plaintext = wrap_soap(&fresh_timestamp());
    let compressed = gzip_compress(plaintext.as_bytes());
    let mut ctx = make_ctx_with_soap_bytes(compressed, "text/xml");
    ctx.headers
        .insert("content-encoding".to_string(), "gzip".to_string());
    let mut headers = soap_headers();
    headers.insert("content-encoding".to_string(), "gzip".to_string());

    let soap = SoapWsSecurity::new(&timestamp_only_config()).unwrap();
    let result = run_soap_request_policy(&soap, &mut ctx, &mut headers).await;
    assert!(
        is_reject(&result),
        "gzip bytes without early normalization must fail SOAP validation"
    );
}

// ── GHSA-xjx6-whgm-8r7r: timestamp / SAML skew bounds cannot panic ──────────

#[test]
fn test_extreme_timestamp_bounds_are_rejected_at_admission() {
    // Values that exceed chrono::TimeDelta's representable seconds range used
    // to be admitted and then panicked the request task inside
    // Duration::seconds. Admission must refuse them instead.
    for key in ["max_age_seconds", "clock_skew_seconds"] {
        let mut timestamp = serde_json::Map::new();
        timestamp.insert("require".to_string(), Value::Bool(true));
        timestamp.insert(key.to_string(), json!(10_000_000_000_000_000u64));
        let config = json!({
            "timestamp": Value::Object(timestamp),
            "reject_missing_security_header": false
        });
        let err = SoapWsSecurity::new(&config)
            .err()
            .expect("extreme value must be rejected");
        assert!(
            err.contains(key) && err.contains("must be an integer"),
            "unexpected error for {key}: {err}"
        );
    }
}

#[test]
fn test_extreme_saml_skew_is_rejected_at_admission() {
    let config = json!({
        "timestamp": { "require": true },
        "saml": {
            "enabled": false,
            "clock_skew_seconds": u64::MAX
        },
        "reject_missing_security_header": false
    });
    let err = SoapWsSecurity::new(&config)
        .err()
        .expect("extreme SAML skew must be rejected");
    assert!(
        err.contains("clock_skew_seconds"),
        "unexpected error: {err}"
    );
}

#[test]
fn test_timestamp_bound_boundaries() {
    let ok = json!({
        "timestamp": {
            "require": true,
            "max_age_seconds": 86_400,
            "clock_skew_seconds": 3_600
        },
        "reject_missing_security_header": false
    });
    assert!(
        SoapWsSecurity::new(&ok).is_ok(),
        "maximum bounds must admit"
    );

    let too_big = json!({
        "timestamp": { "require": true, "max_age_seconds": 86_401 },
        "reject_missing_security_header": false
    });
    assert!(
        SoapWsSecurity::new(&too_big).is_err(),
        "one past the maximum must be rejected"
    );

    let zero_age = json!({
        "timestamp": { "require": true, "max_age_seconds": 0 },
        "reject_missing_security_header": false
    });
    assert!(
        SoapWsSecurity::new(&zero_age).is_err(),
        "a zero freshness window must be rejected"
    );

    let zero_skew = json!({
        "timestamp": { "require": true, "clock_skew_seconds": 0 },
        "reject_missing_security_header": false
    });
    assert!(
        SoapWsSecurity::new(&zero_skew).is_ok(),
        "zero skew is stricter, not weaker, and must be permitted"
    );
}

#[tokio::test]
async fn test_out_of_range_expires_is_rejected_not_panicking() {
    // Years outside `MIN_PARSED_YEAR..=MAX_PARSED_YEAR` are invalid at parse
    // time. That clamp is what keeps later `Expires + skew` arithmetic inside
    // chrono's representable range (see the module docs), so a six-digit year
    // must reject rather than reach — or panic inside — the skew addition.
    // Year 9999 is the *upper admitted* year and is intentionally accepted when
    // the rest of the Timestamp policy holds; do not treat it as out-of-range.
    let plugin = SoapWsSecurity::new(&timestamp_only_config()).unwrap();
    let created = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
    let security = format!(
        r#"<wsu:Timestamp>
        <wsu:Created>{created}</wsu:Created>
        <wsu:Expires>262143-12-31T23:59:59Z</wsu:Expires>
    </wsu:Timestamp>"#
    );
    let mut ctx = make_ctx_with_soap_body(&wrap_soap(&security));
    let mut headers = soap_headers();
    let result = run_soap_request_policy(&plugin, &mut ctx, &mut headers).await;
    assert_eq!(reject_status(&result), 401);
}

// ── GHSA-gr7f-55c2-rpvw: strict configuration admission ────────────────────

#[test]
fn test_unknown_root_key_is_rejected() {
    let config = json!({
        "timestamp": { "require": true },
        "nonce_replay_protection": { "max_cache_size": 50 },
        "reject_missing_security_header": false
    });
    let err = SoapWsSecurity::new(&config)
        .err()
        .expect("documented alias must be rejected");
    assert!(
        err.contains("unknown configuration key") && err.contains("nonce_replay_protection"),
        "unexpected error: {err}"
    );
}

#[test]
fn test_unknown_nested_key_is_rejected_with_suggestion() {
    let config = json!({
        "timestamp": { "require": true, "clock_skew_second": 30 },
        "reject_missing_security_header": false
    });
    let err = SoapWsSecurity::new(&config)
        .err()
        .expect("misspelling must be rejected");
    assert!(
        err.contains("config.timestamp.clock_skew_second")
            && err.contains("did you mean 'clock_skew_seconds'"),
        "unexpected error: {err}"
    );
}

#[test]
fn test_string_valued_enabled_flag_is_rejected() {
    // Previously read as `false`, silently disabling credential authentication
    // and leaving the plugin timestamp-only.
    let config = json!({
        "timestamp": { "require": true },
        "username_token": {
            "enabled": "true",
            "password_type": "PasswordText",
            "credentials": [{"username": "alice", "password": "secret123"}]
        },
        "reject_missing_security_header": false
    });
    let err = SoapWsSecurity::new(&config)
        .err()
        .expect("wrong-typed enabled must be rejected");
    assert!(
        err.contains("config.username_token.enabled") && err.contains("must be a boolean"),
        "unexpected error: {err}"
    );
}

#[test]
fn test_non_string_saml_audience_is_rejected() {
    // Previously became `None`, silently removing service binding while SAML
    // stayed enabled.
    let config = json!({
        "timestamp": { "require": true },
        "saml": { "enabled": false, "audience": 123 },
        "reject_missing_security_header": false
    });
    let err = SoapWsSecurity::new(&config)
        .err()
        .expect("wrong-typed audience must be rejected");
    assert!(
        err.contains("config.saml.audience") && err.contains("must be a string"),
        "unexpected error: {err}"
    );
}

#[test]
fn test_malformed_credential_entries_are_rejected_not_dropped() {
    let missing_password = json!({
        "timestamp": { "require": false },
        "username_token": {
            "enabled": true,
            "password_type": "PasswordText",
            "credentials": [{"username": "alice"}]
        }
    });
    let err = SoapWsSecurity::new(&missing_password)
        .err()
        .expect("missing password must reject");
    assert!(
        err.contains("password") && err.contains("is required"),
        "{err}"
    );

    let wrong_type = json!({
        "timestamp": { "require": false },
        "username_token": {
            "enabled": true,
            "password_type": "PasswordText",
            "credentials": [{"username": "alice", "password": 42}]
        }
    });
    let err = SoapWsSecurity::new(&wrong_type)
        .err()
        .expect("non-string password must reject");
    assert!(err.contains("password"), "{err}");

    let unknown_field = json!({
        "timestamp": { "require": false },
        "username_token": {
            "enabled": true,
            "password_type": "PasswordText",
            "credentials": [{"username": "alice", "password": "p", "role": "admin"}]
        }
    });
    let err = SoapWsSecurity::new(&unknown_field)
        .err()
        .expect("unknown credential key must reject");
    assert!(err.contains("role"), "{err}");
}

#[test]
fn test_duplicate_credential_username_is_rejected() {
    let config = json!({
        "timestamp": { "require": false },
        "username_token": {
            "enabled": true,
            "password_type": "PasswordText",
            "credentials": [
                {"username": "alice", "password": "one"},
                {"username": "alice", "password": "two"}
            ]
        }
    });
    let err = SoapWsSecurity::new(&config)
        .err()
        .expect("duplicate username must reject");
    assert!(err.contains("duplicates an earlier entry"), "{err}");
}

#[test]
fn test_unsupported_algorithm_values_are_rejected_and_value_redacted() {
    const SENTINEL: &str = "SOAP_ALGORITHM_REJECTED_VALUE_CANARY";
    let cases = [
        (
            json!({
                "timestamp": { "require": true },
                "x509_signature": {
                    "enabled": false,
                    "allowed_algorithms": ["rsa-sha256", SENTINEL]
                }
            }),
            "config.x509_signature.allowed_algorithms",
            "rsa-sha256",
        ),
        (
            json!({
                "timestamp": { "require": true },
                "x509_signature": {
                    "enabled": false,
                    "allowed_digest_algorithms": ["sha256", SENTINEL]
                }
            }),
            "config.x509_signature.allowed_digest_algorithms",
            "sha256",
        ),
        (
            json!({
                "timestamp": { "require": true },
                "saml": {
                    "enabled": false,
                    "allowed_signature_algorithms": ["rsa-sha256", SENTINEL]
                }
            }),
            "config.saml.allowed_signature_algorithms",
            "rsa-sha256",
        ),
        (
            json!({
                "timestamp": { "require": true },
                "saml": {
                    "enabled": false,
                    "allowed_digest_algorithms": ["sha256", SENTINEL]
                }
            }),
            "config.saml.allowed_digest_algorithms",
            "sha256",
        ),
    ];

    for (config, field, accepted) in cases {
        let err = SoapWsSecurity::new(&config)
            .err()
            .expect("unknown algorithm must reject");
        assert!(
            err.contains(field) && err.contains(accepted),
            "unexpected error: {err}"
        );
        assert!(
            !err.contains(SENTINEL),
            "rejected algorithm must be value-redacted: {err}"
        );
    }
}

#[test]
fn test_non_string_cert_path_entry_is_rejected() {
    let config = json!({
        "timestamp": { "require": true },
        "saml": { "enabled": false, "trusted_issuers": ["https://idp", 7] },
        "reject_missing_security_header": false
    });
    let err = SoapWsSecurity::new(&config)
        .err()
        .expect("non-string entry must reject");
    assert!(
        err.contains("trusted_issuers[1]"),
        "unexpected error: {err}"
    );
}

#[test]
fn test_zero_nonce_cache_controls_are_rejected() {
    // `cache_ttl_seconds` is intentionally absent: retention is fixed, so the
    // key is no longer part of the schema at all (see
    // `the_removed_retention_key_is_rejected_rather_than_ignored`).
    let config = json!({
        "timestamp": { "require": true },
        "nonce": { "max_cache_size": 0 },
        "reject_missing_security_header": false
    });
    let err = SoapWsSecurity::new(&config)
        .err()
        .expect("zero must be rejected");
    assert!(err.contains("max_cache_size"), "unexpected error: {err}");
}

// ── GHSA-3ffh-5842-8m92: bounded, cache-safe nonce state ───────────────────

#[test]
fn test_oversized_nonce_is_rejected_before_retention() {
    let plugin = SoapWsSecurity::new(&json!({
        "timestamp": { "require": true },
        "nonce": { "max_encoded_length": 64 },
        "reject_missing_security_header": false
    }))
    .unwrap();

    let oversized = "A".repeat(65);
    let err = plugin
        .check_nonce_replay(&oversized)
        .expect_err("oversized nonce must be rejected");
    assert!(err.contains("maximum permitted length"), "{err}");
    assert!(
        !err.contains(&oversized),
        "the nonce value must never appear in the diagnostic"
    );

    // Rejected nonces must not be retained, so the same value is still
    // rejected for length rather than reported as a replay.
    let repeat = plugin
        .check_nonce_replay(&oversized)
        .expect_err("still rejected");
    assert!(repeat.contains("maximum permitted length"), "{repeat}");
}

#[test]
fn test_nonce_cache_is_bounded_by_total_retained_bytes() {
    // The byte cap is deliberately far tighter than the entry cap: 4096 bytes
    // of 64-byte nonces is 64 entries against a 100,000-entry cap. Retention
    // must be bounded by the byte axis without evicting any live claim.
    let plugin = SoapWsSecurity::new(&json!({
        "timestamp": { "require": true },
        "nonce": {
            "max_cache_size": 100_000,
            "max_encoded_length": 64,
            "max_total_cache_bytes": 4_096
        },
        "reject_missing_security_header": false
    }))
    .unwrap();

    let first = format!("{:064}", 0);
    assert!(plugin.check_nonce_replay(&first).is_ok());
    for index in 1..64 {
        let nonce = format!("{:064}", index);
        assert!(
            plugin.check_nonce_replay(&nonce).is_ok(),
            "available byte budget must admit nonce at index {index}"
        );
    }

    let rejected = format!("{:064}", 64);
    let error = plugin
        .check_nonce_replay(&rejected)
        .expect_err("full byte budget must reject instead of evicting");
    assert!(error.contains("at capacity"), "{error}");

    for nonce in [first, format!("{:064}", 63)] {
        let error = plugin
            .check_nonce_replay(&nonce)
            .expect_err("retained nonce must remain replay-protected");
        assert!(error.contains("replay detected"), "{error}");
    }
}

#[tokio::test]
async fn test_oversized_wire_nonce_is_rejected_structurally() {
    let plugin = SoapWsSecurity::new(&json!({
        "timestamp": { "require": false },
        "username_token": {
            "enabled": true,
            "password_type": "PasswordDigest",
            "credentials": [{"username": "alice", "password": "secret123"}]
        },
        "nonce": { "replay_scope": "process", "max_encoded_length": 64 },
        "reject_missing_security_header": true
    }))
    .unwrap();

    // A near-limit nonce: valid Base64, valid username, invalid digest. It must
    // be refused on length before any decode or retention.
    let big_nonce = vec![b'x'; 4_096];
    let engine = &base64::engine::general_purpose::STANDARD;
    let encoded = base64::Engine::encode(engine, &big_nonce);
    let token = password_digest_token("alice", "wrong-password", &big_nonce);
    let mut ctx = make_ctx_with_soap_body(&wrap_soap(&token));
    let mut headers = soap_headers();
    let result = run_soap_request_policy(&plugin, &mut ctx, &mut headers).await;
    assert_eq!(reject_status(&result), 401);
    let body = reject_body(&result);
    assert_eq!(
        body,
        r#"{"error":"WS-Security: Nonce exceeds the maximum permitted length"}"#
    );
    assert!(
        !body.contains(&encoded[..32]),
        "the nonce must never be echoed back to the client"
    );
}

// ── Explicit JSON null vs omission (GHSA-gr7f-55c2-rpvw residual) ───────────

#[test]
fn test_explicit_null_fields_are_rejected_not_defaulted() {
    // Previously `present()` filtered null to absence, so these inputs silently
    // applied weaker/default policy despite OpenAPI typing without nullable.
    let cases: &[(&str, Value, &str)] = &[
        (
            "username_token.enabled null",
            json!({
                "timestamp": { "require": true },
                "username_token": {
                    "enabled": null,
                    "password_type": "PasswordText",
                    "credentials": [{"username": "alice", "password": "secret123"}]
                },
                "reject_missing_security_header": false
            }),
            "config.username_token.enabled",
        ),
        (
            "saml.audience null",
            json!({
                "timestamp": { "require": true },
                "saml": { "enabled": false, "audience": null },
                "reject_missing_security_header": false
            }),
            "config.saml.audience",
        ),
        (
            "nonce object null",
            json!({
                "timestamp": { "require": true },
                "nonce": null,
                "reject_missing_security_header": false
            }),
            "config.nonce",
        ),
        (
            "timestamp.require null",
            json!({
                "timestamp": { "require": null },
                "reject_missing_security_header": false
            }),
            "config.timestamp.require",
        ),
        (
            "credentials null",
            json!({
                "timestamp": { "require": true },
                "username_token": {
                    "enabled": false,
                    "credentials": null
                },
                "reject_missing_security_header": false
            }),
            "config.username_token.credentials",
        ),
        (
            "credential.password null",
            json!({
                "timestamp": { "require": false },
                "username_token": {
                    "enabled": true,
                    "password_type": "PasswordText",
                    "credentials": [{"username": "alice", "password": null}]
                },
                "reject_missing_security_header": false
            }),
            "password",
        ),
    ];

    for (label, config, path_fragment) in cases {
        let err = SoapWsSecurity::new(config)
            .err()
            .unwrap_or_else(|| panic!("{label}: explicit null must reject"));
        assert!(
            err.contains(path_fragment) && err.contains("must not be null"),
            "{label}: unexpected error: {err}"
        );
    }
}

#[test]
fn test_omitted_optional_fields_still_admit_defaults() {
    // Parity pin: omission (not null) still selects documented defaults.
    let plugin = SoapWsSecurity::new(&json!({
        "timestamp": { "require": true },
        "reject_missing_security_header": false
    }))
    .expect("omitted optional nested objects must remain valid");
    assert!(plugin.check_nonce_replay("omitted-defaults-nonce").is_ok());
}

#[test]
fn test_nonce_age_index_expiry_and_accounting_are_exact() {
    let harness = SoapNonceReplayHarness::new(&json!({
        "timestamp": { "require": true },
        "nonce": {
            "max_cache_size": 3,
            "max_encoded_length": 16,
            "max_total_cache_bytes": 4_096
        },
        "reject_missing_security_header": false
    }))
    .expect("config must admit");

    for (nonce, seconds) in [
        ("nonce-a-00000001", 0),
        ("nonce-b-00000002", 1),
        ("nonce-c-00000003", 2),
    ] {
        harness
            .claim_at(nonce, Duration::from_secs(seconds))
            .expect("fresh nonce must admit");
    }
    assert!(
        harness
            .claim_at("nonce-c-00000003", Duration::from_secs(3))
            .is_err(),
        "same-key claim inside the retention horizon must be a replay"
    );

    let before = harness.snapshot().expect("snapshot");
    assert_eq!(before.entry_count, 3);
    assert_eq!(before.age_index_entry_count, 3);
    assert_eq!(before.retained_key_bytes, 48);
    assert_eq!(before.recomputed_key_bytes, 48);
    assert_eq!(before.shared_key_entries, 3);
    assert_eq!(before.last_expired_removals, 0);

    // One second past the fixed horizon, so the oldest entry — and only the
    // oldest, because reclamation stops as soon as there is room — is expired.
    harness
        .claim_at(
            "nonce-d-00000004",
            Duration::from_secs(CLAIM_RETENTION_SECONDS + 1),
        )
        .expect("one exact-oldest expiry must make room");
    let after_expiry = harness.snapshot().expect("snapshot");
    assert_eq!(after_expiry.entry_count, 3);
    assert_eq!(after_expiry.age_index_entry_count, 3);
    assert_eq!(after_expiry.retained_key_bytes, 48);
    assert_eq!(after_expiry.recomputed_key_bytes, 48);
    assert_eq!(after_expiry.shared_key_entries, 3);
    assert_eq!(after_expiry.last_expired_removals, 1);

    harness
        .claim_at(
            "nonce-b-00000002",
            Duration::from_secs(CLAIM_RETENTION_SECONDS + 1),
        )
        .expect("expired same-key claim must refresh in place");
    let after_refresh = harness.snapshot().expect("snapshot");
    assert_eq!(after_refresh.entry_count, 3);
    assert_eq!(after_refresh.age_index_entry_count, 3);
    assert_eq!(after_refresh.retained_key_bytes, 48);
    assert_eq!(after_refresh.recomputed_key_bytes, 48);
    assert_eq!(after_refresh.shared_key_entries, 3);
    assert_eq!(after_refresh.last_expired_removals, 0);
}

// ── Live entries are never evicted (GHSA-54mh-v348-j878) ───────────────────
//
// The remediation these tests pin is deliberate: the replay coverage a claim is
// promised — the full fixed `CLAIM_RETENTION_SECONDS` horizon — is honoured for
// the whole window. Capacity exhaustion is a *rejection*, never a licence to
// unprotect an already-claimed nonce.

#[test]
fn test_nonce_entry_cap_rejects_instead_of_evicting_live_entries() {
    let harness = SoapNonceReplayHarness::new(&json!({
        "timestamp": { "require": true },
        "nonce": {
            "max_cache_size": 3,
            "max_encoded_length": 16,
            "max_total_cache_bytes": 4_096
        },
        "reject_missing_security_header": false
    }))
    .expect("config must admit");

    for (nonce, seconds) in [
        ("nonce-a-00000001", 0),
        ("nonce-b-00000002", 1),
        ("nonce-c-00000003", 2),
    ] {
        harness
            .claim_at(nonce, Duration::from_secs(seconds))
            .expect("fresh nonce must admit");
    }

    let err = harness
        .claim_at("nonce-d-00000004", Duration::from_secs(3))
        .expect_err("entry cap full of live entries must fail closed");
    assert_eq!(err, "WS-Security: replay protection state is at capacity");

    let snapshot = harness.snapshot().expect("snapshot");
    assert_eq!(snapshot.entry_count, 3);
    assert_eq!(snapshot.age_index_entry_count, 3);
    assert_eq!(snapshot.retained_key_bytes, 48);
    assert_eq!(snapshot.recomputed_key_bytes, 48);
    assert_eq!(snapshot.shared_key_entries, 3);
    assert_eq!(snapshot.last_expired_removals, 0);

    // Every live nonce — including the exact oldest — is still a replay.
    for nonce in ["nonce-a-00000001", "nonce-b-00000002", "nonce-c-00000003"] {
        assert_eq!(
            harness
                .claim_at(nonce, Duration::from_secs(4))
                .expect_err("live nonce must remain replay-protected"),
            "WS-Security: nonce replay detected",
            "{nonce} lost replay protection to a capacity admission"
        );
    }
    // The rejected nonce was not recorded, so it never became a silent replay.
    let after = harness.snapshot().expect("snapshot");
    assert_eq!(after.entry_count, 3);
    assert_eq!(after.retained_key_bytes, 48);
}

#[test]
fn test_nonce_tight_byte_cap_preserves_live_entry_and_rejects() {
    // A single maximum-length nonce pins the whole byte budget. The previous
    // behaviour evicted it and re-admitted it one second later; that is the
    // replay this test forbids.
    let harness = SoapNonceReplayHarness::new(&json!({
        "timestamp": { "require": true },
        "nonce": {
            "max_cache_size": 100_000,
            "max_encoded_length": 4_096,
            "max_total_cache_bytes": 4_096
        },
        "reject_missing_security_header": false
    }))
    .expect("tight byte cap must admit");

    let first = "A".repeat(4_096);
    let second = "B".repeat(4_096);
    harness
        .claim_at(&first, Duration::ZERO)
        .expect("first maximum-length nonce must admit");

    let err = harness
        .claim_at(&second, Duration::from_secs(1))
        .expect_err("byte cap must reject rather than unprotect the live nonce");
    assert_eq!(err, "WS-Security: replay protection state is at capacity");
    assert!(
        !err.contains(second.as_str()) && !err.contains(first.as_str()),
        "saturation diagnostic must never include the nonce"
    );

    let snapshot = harness.snapshot().expect("snapshot");
    assert_eq!(snapshot.entry_count, 1);
    assert_eq!(snapshot.retained_key_bytes, 4_096);
    assert_eq!(snapshot.recomputed_key_bytes, 4_096);
    assert_eq!(snapshot.last_expired_removals, 0);

    assert_eq!(
        harness
            .claim_at(&first, Duration::from_secs(2))
            .expect_err("the live nonce must still be a replay"),
        "WS-Security: nonce replay detected"
    );
    // The rejected nonce was never recorded, so a retry is still a fresh claim
    // decision rather than a replay hit.
    assert_eq!(
        harness
            .claim_at(&second, Duration::from_secs(3))
            .expect_err("retry while still saturated must stay rejected"),
        "WS-Security: replay protection state is at capacity"
    );
}

#[test]
fn test_nonce_expired_entry_is_reclaimed_and_retry_succeeds() {
    // Retention is fixed, not configured; drive the timeline off the constant.
    const TTL: u64 = CLAIM_RETENTION_SECONDS;
    let harness = SoapNonceReplayHarness::new(&json!({
        "timestamp": { "require": true },
        "nonce": {
            "max_cache_size": 100_000,
            "max_encoded_length": 4_096,
            "max_total_cache_bytes": 4_096
        },
        "reject_missing_security_header": false
    }))
    .expect("tight byte cap must admit");

    let first = "A".repeat(4_096);
    let second = "B".repeat(4_096);
    harness
        .claim_at(&first, Duration::ZERO)
        .expect("first maximum-length nonce must admit");

    // Inside the TTL the second nonce is refused and the first stays protected.
    assert_eq!(
        harness
            .claim_at(&second, Duration::from_secs(TTL - 1))
            .expect_err("saturated inside the TTL must reject"),
        "WS-Security: replay protection state is at capacity"
    );

    // Once the first entry is provably expired the retry reclaims it and wins.
    harness
        .claim_at(&second, Duration::from_secs(TTL))
        .expect("expired entry must be reclaimed for the retry");
    let snapshot = harness.snapshot().expect("snapshot");
    assert_eq!(snapshot.entry_count, 1);
    assert_eq!(snapshot.age_index_entry_count, 1);
    assert_eq!(snapshot.retained_key_bytes, 4_096);
    assert_eq!(snapshot.recomputed_key_bytes, 4_096);
    assert_eq!(snapshot.shared_key_entries, 1);
    assert_eq!(snapshot.last_expired_removals, 1);

    // The freshly claimed nonce now owns the whole budget and is protected.
    assert_eq!(
        harness
            .claim_at(&second, Duration::from_secs(TTL + 1))
            .expect_err("the newly claimed nonce must be replay-protected"),
        "WS-Security: nonce replay detected"
    );
}

#[test]
fn test_nonce_expiry_reclaims_only_expired_prefix_of_age_index() {
    const TTL: u64 = CLAIM_RETENTION_SECONDS;
    let harness = SoapNonceReplayHarness::new(&json!({
        "timestamp": { "require": true },
        "nonce": {
            "max_cache_size": 4,
            "max_encoded_length": 16,
            "max_total_cache_bytes": 4_096
        },
        "reject_missing_security_header": false
    }))
    .expect("config must admit");

    // Two old entries and two recent ones fill the entry cap.
    for (nonce, seconds) in [
        ("nonce-a-00000001", 0),
        ("nonce-b-00000002", 1),
        ("nonce-c-00000003", TTL - 2),
        ("nonce-d-00000004", TTL - 1),
    ] {
        harness
            .claim_at(nonce, Duration::from_secs(seconds))
            .expect("fresh nonce must admit");
    }

    // At t=TTL+1 only the first two entries are past the retention horizon.
    // Admitting one nonce needs exactly one slot, so exactly one expired entry
    // is reclaimed.
    harness
        .claim_at("nonce-e-00000005", Duration::from_secs(TTL + 1))
        .expect("an expired entry must make room");
    let snapshot = harness.snapshot().expect("snapshot");
    assert_eq!(snapshot.last_expired_removals, 1);
    assert_eq!(snapshot.entry_count, 4);
    assert_eq!(snapshot.age_index_entry_count, 4);
    assert_eq!(snapshot.retained_key_bytes, 64);
    assert_eq!(snapshot.recomputed_key_bytes, 64);

    // The still-live entries kept their protection; only the expired head went.
    for nonce in ["nonce-c-00000003", "nonce-d-00000004", "nonce-e-00000005"] {
        assert_eq!(
            harness
                .claim_at(nonce, Duration::from_secs(TTL + 2))
                .expect_err("live nonce must remain replay-protected"),
            "WS-Security: nonce replay detected",
            "{nonce} lost replay protection"
        );
    }
}

#[test]
fn test_nonce_saturation_fails_closed_after_bounded_index_work() {
    const ENTRY_LEN: usize = 16;
    const ENTRY_COUNT: usize = 4_096 / ENTRY_LEN;
    let harness = SoapNonceReplayHarness::new(&json!({
        "timestamp": { "require": true },
        "nonce": {
            "max_cache_size": 1_000_000,
            "max_encoded_length": 4_096,
            "max_total_cache_bytes": 4_096
        },
        "reject_missing_security_header": false
    }))
    .expect("config must admit");

    for index in 0..ENTRY_COUNT {
        let nonce = format!("{index:016x}");
        assert_eq!(nonce.len(), ENTRY_LEN);
        harness
            .claim_at(&nonce, Duration::ZERO)
            .expect("initial fill must admit");
    }
    let before = harness.snapshot().expect("snapshot");
    assert_eq!(before.entry_count, ENTRY_COUNT);
    assert_eq!(before.age_index_entry_count, ENTRY_COUNT);
    assert_eq!(before.retained_key_bytes, 4_096);
    assert_eq!(before.recomputed_key_bytes, 4_096);
    assert_eq!(before.shared_key_entries, ENTRY_COUNT);

    let large_nonce = "Z".repeat(4_096);
    let err = harness
        .claim_at(&large_nonce, Duration::from_secs(1))
        .expect_err("live entries must not be evicted to seat a 4096-byte nonce");
    assert_eq!(err, "WS-Security: replay protection state is at capacity");
    assert!(
        !err.contains(large_nonce.as_str()),
        "saturation diagnostic must never include the nonce"
    );

    // Nothing was reclaimed: every live entry survived the saturation probe.
    let after = harness.snapshot().expect("snapshot");
    assert_eq!(after.entry_count, ENTRY_COUNT);
    assert_eq!(after.age_index_entry_count, ENTRY_COUNT);
    assert_eq!(after.retained_key_bytes, 4_096);
    assert_eq!(after.recomputed_key_bytes, 4_096);
    assert_eq!(after.shared_key_entries, ENTRY_COUNT);
    assert_eq!(after.last_expired_removals, 0);
    assert_eq!(after.max_maintenance_entries, 64);
    assert_eq!(
        harness
            .claim_at("0000000000000000", Duration::from_secs(2))
            .expect_err("the oldest live entry must still be a replay"),
        "WS-Security: nonce replay detected"
    );
}

#[test]
fn test_nonce_reclaim_over_bounded_budget_rejects_then_retries_to_success() {
    // 256 tiny entries saturate the byte cap. Reclaiming all of them for one
    // maximum-length nonce needs more than the 64-entry per-request budget, so
    // early attempts fail closed and later retries succeed once enough proven
    // expired entries have been reclaimed. No live entry is ever discarded.
    const ENTRY_LEN: usize = 16;
    const MAX_BYTES: usize = 4_096;
    const ENTRY_COUNT: usize = MAX_BYTES / ENTRY_LEN;
    const TTL: u64 = CLAIM_RETENTION_SECONDS;

    let harness = SoapNonceReplayHarness::new(&json!({
        "timestamp": { "require": true },
        "nonce": {
            "max_cache_size": 1_000_000,
            "max_encoded_length": MAX_BYTES,
            "max_total_cache_bytes": MAX_BYTES
        },
        "reject_missing_security_header": false
    }))
    .expect("config must admit");

    for index in 0..ENTRY_COUNT {
        let nonce = format!("{index:016x}");
        assert_eq!(nonce.len(), ENTRY_LEN);
        harness
            .claim_at(&nonce, Duration::ZERO)
            .expect("initial fill must admit");
    }

    let large_nonce = "Z".repeat(MAX_BYTES);
    // Still inside the TTL: nothing is reclaimable and the claim fails closed.
    assert_eq!(
        harness
            .claim_at(&large_nonce, Duration::from_secs(TTL - 1))
            .expect_err("live entries must not be reclaimed"),
        "WS-Security: replay protection state is at capacity"
    );
    let live = harness.snapshot().expect("snapshot");
    assert_eq!(live.entry_count, ENTRY_COUNT);
    assert_eq!(live.last_expired_removals, 0);

    // Past the TTL every entry is provably expired. Each attempt reclaims at
    // most the maintenance budget, so the claim succeeds only after enough
    // retries — and never by discarding unexpired state.
    let mut attempts = 0usize;
    loop {
        attempts += 1;
        assert!(attempts <= 16, "reclamation failed to converge");
        let snapshot_before = harness.snapshot().expect("snapshot");
        match harness.claim_at(&large_nonce, Duration::from_secs(TTL)) {
            Ok(()) => break,
            Err(err) => {
                assert_eq!(err, "WS-Security: replay protection state is at capacity");
                let after = harness.snapshot().expect("snapshot");
                assert_eq!(
                    after.last_expired_removals, after.max_maintenance_entries,
                    "a rejected attempt must have spent the whole bounded budget"
                );
                assert_eq!(
                    snapshot_before.entry_count - after.entry_count,
                    after.max_maintenance_entries,
                    "only budget-bounded expired reclamation may occur"
                );
                assert_eq!(after.retained_key_bytes, after.recomputed_key_bytes);
            }
        }
    }
    assert!(
        attempts > 1,
        "one bounded batch must not free the whole cap"
    );

    let final_snapshot = harness.snapshot().expect("snapshot");
    assert_eq!(final_snapshot.entry_count, 1);
    assert_eq!(final_snapshot.retained_key_bytes, MAX_BYTES);
    assert_eq!(final_snapshot.recomputed_key_bytes, MAX_BYTES);
    assert_eq!(final_snapshot.shared_key_entries, 1);
}

#[test]
fn test_nonce_fail_closed_contract_is_documented_in_openapi_and_docs() {
    let spec: Value =
        serde_yaml::from_str(include_str!("../../../openapi.yaml")).expect("openapi.yaml parses");
    let config = &spec["components"]["schemas"]["SoapWsSecurityConfig"];
    let nonce = &config["properties"]["nonce"]["properties"];
    let max_cache_size = nonce["max_cache_size"]["description"]
        .as_str()
        .expect("max_cache_size description");
    let max_total_cache_bytes = nonce["max_total_cache_bytes"]["description"]
        .as_str()
        .expect("max_total_cache_bytes description");
    assert!(
        max_cache_size.contains("never evicted"),
        "max_cache_size must advertise that in-TTL nonces are never evicted: {max_cache_size}"
    );
    assert!(
        max_cache_size.contains("401") && max_total_cache_bytes.contains("401"),
        "both nonce caps must advertise the fail-closed rejection"
    );

    let plugins_doc = include_str!("../../../docs/plugins.md");
    let cache_doc = include_str!("../../../docs/cache_management.md");
    for (label, text) in [("plugins", plugins_doc), ("cache", cache_doc)] {
        assert!(
            text.contains("the walk stops at the first still-live entry"),
            "{label} docs must state that reclamation stops at the first live entry"
        );
        assert!(
            !text.contains("selects exact-oldest live entries"),
            "{label} docs must not describe forced eviction of live nonces"
        );
    }
}

#[test]
fn test_nonce_maintenance_source_reclaims_only_expired_entries() {
    let source = include_str!("../../../src/plugins/soap_ws_security.rs");
    let start = source
        .find("fn reclaim_expired_nonce_room_locked(")
        .expect("maintenance function");
    let end = source[start..]
        .find("pub(crate) fn check_nonce_replay_at_for_tests")
        .map(|offset| start + offset)
        .expect("maintenance function end");
    let maintenance = &source[start..end];

    assert!(
        maintenance.contains("age_index.first_key_value()"),
        "reclamation must walk the ordered index from its oldest end"
    );
    assert!(
        maintenance.contains("state.last_expired_removals < NONCE_MAX_MAINTENANCE_ENTRIES"),
        "reclamation must stay inside the per-request maintenance budget"
    );
    assert!(
        maintenance.contains("if Self::nonce_age_seconds(now, age_key.0) < ttl_seconds {")
            && maintenance.contains("break;"),
        "reclamation must stop at the first still-live entry"
    );
    // No forced eviction of live replay state may return (GHSA-54mh-v348-j878).
    assert!(!maintenance.contains("amortized_target"));
    assert!(!maintenance.contains("candidates"));
    assert!(!maintenance.contains("remaining_budget"));
    assert!(!maintenance.contains("Vec::with_capacity"));
    // And no lookup-map scan may creep back in.
    assert!(!maintenance.contains("state.cache.iter("));
    assert!(!maintenance.contains("state.cache.retain("));
    assert!(!maintenance.contains("for (key, entry) in &state.cache"));
    assert!(!maintenance.contains("collect::<Vec"));
}

#[test]
fn test_nonce_inconsistent_age_index_fails_closed() {
    let err = soap_nonce_inconsistent_state_outcome_for_test(&json!({
        "timestamp": { "require": true },
        "nonce": {
            "max_cache_size": 10
        },
        "reject_missing_security_header": false
    }))
    .expect("one-shot inconsistency probe");
    assert_eq!(err, "WS-Security: replay protection state is at capacity");
}

// ── Concurrent nonce-cap invariants (GHSA-3ffh-5842-8m92 residual) ──────────

#[test]
fn test_concurrent_nonce_admission_saturates_without_unprotecting_live_claims() {
    const MAX_ENTRIES: usize = 128;
    const MAX_BYTES: usize = 4_096; // MIN_NONCE_MAX_TOTAL_CACHE_BYTES
    const NONCE_LEN: usize = 64;
    const BYTE_CAP_ENTRIES: usize = MAX_BYTES / NONCE_LEN; // 64, the binding cap
    const THREADS: usize = 32;
    const PER_THREAD: usize = 64;

    let harness = Arc::new(
        SoapNonceReplayHarness::new(&json!({
            "timestamp": { "require": true },
            "nonce": {
                "max_cache_size": MAX_ENTRIES,
                "max_encoded_length": NONCE_LEN,
                "max_total_cache_bytes": MAX_BYTES
            },
            "reject_missing_security_header": false
        }))
        .expect("tight caps must admit"),
    );

    let barrier = Arc::new(Barrier::new(THREADS));
    let admitted = Arc::new(Mutex::new(Vec::<String>::new()));
    let rejected = Arc::new(AtomicUsize::new(0));
    let mut handles = Vec::with_capacity(THREADS);
    for thread_id in 0..THREADS {
        let harness = Arc::clone(&harness);
        let barrier = Arc::clone(&barrier);
        let admitted = Arc::clone(&admitted);
        let rejected = Arc::clone(&rejected);
        handles.push(std::thread::spawn(move || {
            barrier.wait();
            for index in 0..PER_THREAD {
                // Fixed-width distinct keys so byte accounting is exact.
                let nonce = format!("t{thread_id:02}-{index:060}");
                debug_assert_eq!(nonce.len(), NONCE_LEN);
                match harness.claim(&nonce) {
                    Ok(()) => admitted.lock().expect("admitted").push(nonce),
                    Err(err) if err == "WS-Security: replay protection state is at capacity" => {
                        rejected.fetch_add(1, Ordering::Relaxed);
                    }
                    Err(err) => panic!("unexpected nonce outcome: {err}"),
                }
                // Caps must hold on every observation, not only at the end.
                let snapshot = harness.snapshot().expect("snapshot");
                assert!(
                    snapshot.entry_count <= MAX_ENTRIES,
                    "entry cap overshot under concurrency"
                );
                assert!(
                    snapshot.entry_count <= BYTE_CAP_ENTRIES,
                    "byte-derived entry cap overshot under concurrency"
                );
                assert!(
                    snapshot.retained_key_bytes <= MAX_BYTES,
                    "byte cap overshot under concurrency"
                );
                assert_eq!(snapshot.entry_count, snapshot.age_index_entry_count);
                assert_eq!(snapshot.retained_key_bytes, snapshot.recomputed_key_bytes);
                assert_eq!(snapshot.entry_count, snapshot.shared_key_entries);
            }
        }));
    }
    for handle in handles {
        handle.join().expect("worker");
    }

    let admitted = admitted.lock().expect("admitted").clone();
    let snapshot = harness.snapshot().expect("snapshot");
    // Nothing expires inside the flood, so exactly the byte-derived cap of
    // distinct nonces can ever be admitted and every later claim fails closed.
    assert_eq!(
        admitted.len(),
        BYTE_CAP_ENTRIES,
        "only the byte cap's worth of distinct nonces may be admitted"
    );
    assert_eq!(
        rejected.load(Ordering::Relaxed),
        THREADS * PER_THREAD - BYTE_CAP_ENTRIES,
        "every claim past capacity must fail closed"
    );
    assert_eq!(snapshot.entry_count, BYTE_CAP_ENTRIES);
    assert_eq!(snapshot.retained_key_bytes, MAX_BYTES);
    assert_eq!(snapshot.retained_key_bytes, snapshot.recomputed_key_bytes);
    assert_eq!(snapshot.entry_count, snapshot.shared_key_entries);

    // The security property: no admitted nonce was ever evicted to seat a
    // later one, so replaying any of them is still detected.
    for nonce in &admitted {
        assert_eq!(
            harness
                .claim(nonce)
                .expect_err("an admitted nonce must stay replay-protected"),
            "WS-Security: nonce replay detected",
            "an admitted nonce lost replay protection under a concurrent flood"
        );
    }
}

#[test]
fn test_concurrent_same_key_nonce_is_exact_replay_without_overshoot() {
    let harness = Arc::new(
        SoapNonceReplayHarness::new(&json!({
            "timestamp": { "require": true },
            "nonce": {
                "max_cache_size": 8,
                "max_encoded_length": 32,
                "max_total_cache_bytes": 4_096
            },
            "reject_missing_security_header": false
        }))
        .expect("config must admit"),
    );

    const THREADS: usize = 64;
    let barrier = Arc::new(Barrier::new(THREADS));
    let ok = Arc::new(AtomicUsize::new(0));
    let replay = Arc::new(AtomicUsize::new(0));
    let mut handles = Vec::with_capacity(THREADS);
    for _ in 0..THREADS {
        let harness = Arc::clone(&harness);
        let barrier = Arc::clone(&barrier);
        let ok = Arc::clone(&ok);
        let replay = Arc::clone(&replay);
        handles.push(std::thread::spawn(move || {
            barrier.wait();
            match harness.claim("same-key-concurrent-nonce!!") {
                Ok(()) => {
                    ok.fetch_add(1, Ordering::Relaxed);
                }
                Err(err) if err.contains("nonce replay detected") => {
                    replay.fetch_add(1, Ordering::Relaxed);
                }
                Err(err) => panic!("unexpected same-key outcome: {err}"),
            }
        }));
    }
    for handle in handles {
        handle.join().expect("worker");
    }

    assert_eq!(ok.load(Ordering::Relaxed), 1, "exactly one claim may admit");
    assert_eq!(
        replay.load(Ordering::Relaxed),
        THREADS - 1,
        "all other claims must be replays"
    );
    let snapshot = harness.snapshot().expect("snapshot");
    assert_eq!(snapshot.entry_count, 1);
    assert_eq!(snapshot.age_index_entry_count, 1);
    assert_eq!(
        snapshot.retained_key_bytes,
        "same-key-concurrent-nonce!!".len()
    );
    assert_eq!(snapshot.retained_key_bytes, snapshot.recomputed_key_bytes);
    assert_eq!(snapshot.shared_key_entries, 1);
}

// ── GHSA-54mh-v348-j878: Created freshness, Timestamp binding, replay scope ──
//
// The remaining half of the advisory. PR #3353 already proved that an
// authenticated live nonce is never evicted and that exhaustion fails closed;
// these tests cover what was still open:
//
//   * the UsernameToken's own `wsu:Created` was only ever a digest input, never
//     parsed or bounded, so a captured token stayed digest-valid forever;
//   * nothing tied that instant to the outer `wsu:Timestamp`, so a captured
//     token could be paired with a freshly minted outer Timestamp;
//   * replay state was rebuilt per plugin instance, so a reload generation (and
//     every additional replica) started from an empty cache.

/// PasswordDigest policy with the outer-Timestamp binding switched off, so the
/// inner freshness window can be observed on its own.
fn digest_unbound_config(created_max_age_seconds: u64) -> Value {
    json!({
        "timestamp": { "require": false },
        "username_token": {
            "enabled": true,
            "password_type": "PasswordDigest",
            "credentials": [{"username": "alice", "password": "secret123"}],
            "require_timestamp_binding": false,
            "created_max_age_seconds": created_max_age_seconds,
            "created_clock_skew_seconds": 0
        },
        "nonce": { "replay_scope": "process" },
        "reject_missing_security_header": true
    })
}

fn offset_created(offset: chrono::Duration) -> String {
    (chrono::Utc::now() + offset)
        .format("%Y-%m-%dT%H:%M:%S%.3fZ")
        .to_string()
}

async fn digest_outcome(plugin: &SoapWsSecurity, security_block: &str) -> PluginResult {
    let mut ctx = make_ctx_with_soap_body(&wrap_soap(security_block));
    let mut headers = soap_headers();
    run_soap_request_policy(plugin, &mut ctx, &mut headers).await
}

#[tokio::test]
async fn digest_created_that_is_too_old_is_rejected() {
    // The digest still verifies — the token is genuine, just stale. Before this
    // fix nothing looked at the instant, so "genuine but stale" was accepted.
    let plugin = SoapWsSecurity::new(&digest_unbound_config(300)).unwrap();
    let stale = offset_created(-chrono::Duration::hours(1));
    let block =
        password_digest_security_block("alice", "secret123", b"stale-created-01", &stale, None);
    let result = digest_outcome(&plugin, &block).await;
    assert_username_token_structural(&result, "UsernameToken Created is too old", &["alice"]);
}

#[tokio::test]
async fn digest_created_in_the_future_is_rejected() {
    let plugin = SoapWsSecurity::new(&digest_unbound_config(300)).unwrap();
    let future = offset_created(chrono::Duration::hours(1));
    let block =
        password_digest_security_block("alice", "secret123", b"future-created-1", &future, None);
    let result = digest_outcome(&plugin, &block).await;
    assert_username_token_structural(
        &result,
        "UsernameToken Created is in the future",
        &["alice"],
    );
}

#[tokio::test]
async fn digest_created_that_is_malformed_is_rejected_without_echoing_it() {
    // The malformed value is a digest input bound to the shared secret, so the
    // rejection must not echo it back.
    const MALFORMED: &str = "SOAP_CREATED_CANARY_not-a-datetime";
    let plugin = SoapWsSecurity::new(&digest_unbound_config(300)).unwrap();
    for created in [MALFORMED, "99999-01-01T00:00:00Z", ""] {
        let nonce = b"bad-created-01!!";
        let block = password_digest_security_block("alice", "secret123", nonce, created, None);
        let result = digest_outcome(&plugin, &block).await;
        assert!(
            is_reject(&result),
            "malformed Created {created:?} must reject"
        );
        assert_eq!(reject_status(&result), 401);
        assert!(
            !reject_body(&result).contains(MALFORMED),
            "the rejected Created value must never be echoed: {}",
            reject_body(&result)
        );
    }
}

#[tokio::test]
async fn digest_within_the_freshness_window_still_succeeds() {
    let plugin = SoapWsSecurity::new(&digest_unbound_config(300)).unwrap();
    let recent = offset_created(-chrono::Duration::seconds(30));
    let block =
        password_digest_security_block("alice", "secret123", b"fresh-created-01", &recent, None);
    let result = digest_outcome(&plugin, &block).await;
    assert!(
        matches!(result, PluginResult::Continue),
        "a token inside its freshness window must still authenticate: {result:?}"
    );
}

#[tokio::test]
async fn captured_token_paired_with_a_fresh_timestamp_is_rejected() {
    // The advisory's scenario 3, with the inner freshness window deliberately
    // widened to 24h so it cannot be what rejects the request. The only thing
    // standing between the attacker and a replay is the binding: the captured
    // UsernameToken's own Created no longer matches the freshly generated outer
    // Timestamp, and moving the inner instant would invalidate the digest.
    let plugin = SoapWsSecurity::new(&json!({
        "timestamp": { "require": true, "max_age_seconds": 300 },
        "username_token": {
            "enabled": true,
            "password_type": "PasswordDigest",
            "credentials": [{"username": "alice", "password": "secret123"}],
            "created_max_age_seconds": 86400,
            "created_max_timestamp_divergence_seconds": 60
        },
        "nonce": { "replay_scope": "process" },
        "reject_missing_security_header": true
    }))
    .unwrap();

    let captured = offset_created(-chrono::Duration::minutes(30));
    let fresh_timestamp = offset_created(chrono::Duration::zero());
    let block = password_digest_security_block(
        "alice",
        "secret123",
        b"captured-token-1",
        &captured,
        Some(&fresh_timestamp),
    );
    let result = digest_outcome(&plugin, &block).await;
    assert_username_token_structural(&result, "diverges from the Timestamp Created", &["alice"]);
}

#[tokio::test]
async fn digest_without_an_outer_timestamp_is_rejected_by_default() {
    let plugin = SoapWsSecurity::new(&username_token_digest_config()).unwrap();
    let created = fresh_created();
    let block =
        password_digest_security_block("alice", "secret123", b"no-timestamp-01!", &created, None);
    let result = digest_outcome(&plugin, &block).await;
    assert_username_token_structural(&result, "requires a Timestamp", &["alice"]);
}

#[tokio::test]
async fn digest_created_past_the_timestamp_expires_is_rejected() {
    let plugin = SoapWsSecurity::new(&json!({
        "timestamp": { "require": false, "max_age_seconds": 3600, "clock_skew_seconds": 300 },
        "username_token": {
            "enabled": true,
            "password_type": "PasswordDigest",
            "credentials": [{"username": "alice", "password": "secret123"}],
            "created_clock_skew_seconds": 0,
            "created_max_timestamp_divergence_seconds": 3600
        },
        "nonce": { "replay_scope": "process" },
        "reject_missing_security_header": true
    }))
    .unwrap();

    // The outer Timestamp must itself stay in policy (Expires is 4 minutes ago
    // against a 5-minute outer skew, so it has not "expired" on its own terms),
    // while the UsernameToken Created sits one minute ago — after that Expires
    // with a zero UsernameToken skew.
    let ts_created = offset_created(-chrono::Duration::minutes(10));
    let ts_expires = offset_created(-chrono::Duration::minutes(4));
    let ut_created = offset_created(-chrono::Duration::minutes(1));

    let nonce = b"past-expires-01!";
    let nonce_b64 =
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, nonce.as_slice());
    let mut data = Vec::new();
    data.extend_from_slice(nonce.as_slice());
    data.extend_from_slice(ut_created.as_bytes());
    data.extend_from_slice(b"secret123");
    let digest = ring::digest::digest(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY, &data);
    let digest_b64 =
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, digest.as_ref());

    let block = format!(
        r#"<wsu:Timestamp wsu:Id="TS-1"><wsu:Created>{ts_created}</wsu:Created><wsu:Expires>{ts_expires}</wsu:Expires></wsu:Timestamp>
        <wsse:UsernameToken>
        <wsse:Username>alice</wsse:Username>
        <wsse:Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest">{digest_b64}</wsse:Password>
        <wsse:Nonce>{nonce_b64}</wsse:Nonce>
        <wsu:Created>{ut_created}</wsu:Created>
    </wsse:UsernameToken>"#
    );
    let result = digest_outcome(&plugin, &block).await;
    assert_username_token_structural(&result, "past the Timestamp Expires", &["alice"]);
}

#[tokio::test]
async fn a_present_timestamp_is_validated_even_when_not_required() {
    // The binding is only meaningful if the outer instant it binds to has been
    // validated. `timestamp.require: false` means "a Timestamp may be absent",
    // never "an out-of-policy Timestamp is ignored".
    let plugin = SoapWsSecurity::new(&username_token_digest_config()).unwrap();
    let stale_timestamp = offset_created(-chrono::Duration::hours(6));
    let block = password_digest_security_block(
        "alice",
        "secret123",
        b"stale-outer-ts01",
        &stale_timestamp,
        Some(&stale_timestamp),
    );
    let result = digest_outcome(&plugin, &block).await;
    assert!(is_reject(&result));
    assert!(
        reject_body(&result).contains("Timestamp Created is too old"),
        "a present-but-stale Timestamp must be rejected on its own terms: {}",
        reject_body(&result)
    );
}

#[tokio::test]
async fn malformed_outer_timestamp_values_are_not_echoed() {
    let plugin = SoapWsSecurity::new(&username_token_digest_config()).unwrap();
    let created = fresh_created();
    let marker = "credential-like-outer-timestamp-value";

    let invalid_created = password_digest_security_block(
        "alice",
        "secret123",
        b"bad-outer-created",
        &created,
        Some(marker),
    );
    let created_result = digest_outcome(&plugin, &invalid_created).await;
    assert!(is_reject(&created_result));
    assert!(!reject_body(&created_result).contains(marker));

    let token =
        password_digest_security_block("alice", "secret123", b"bad-outer-expiry!", &created, None);
    let invalid_timestamp = format!(
        r#"<wsu:Timestamp wsu:Id="TS-1"><wsu:Created>{created}</wsu:Created><wsu:Expires>{marker}</wsu:Expires></wsu:Timestamp>"#
    );
    let invalid_expires = format!("{invalid_timestamp}{token}");
    let expires_result = digest_outcome(&plugin, &invalid_expires).await;
    assert!(is_reject(&expires_result));
    assert!(!reject_body(&expires_result).contains(marker));
}

// ── Replay scope admission ──────────────────────────────────────────────────

#[test]
fn password_digest_requires_an_explicit_replay_scope() {
    // A gateway cannot see its own replica count, so the deployment shape has
    // to be declared. Defaulting to process-local state is what let one
    // captured token be spent once per replica.
    let config = json!({
        "timestamp": { "require": true },
        "username_token": {
            "enabled": true,
            "password_type": "PasswordDigest",
            "credentials": [{"username": "alice", "password": "secret123"}]
        }
    });
    let err = SoapWsSecurity::new(&config)
        .err()
        .expect("PasswordDigest without a declared replay scope must fail admission");
    assert!(err.contains("config.nonce.replay_scope"), "{err}");
    assert!(err.contains("cross-replica"), "{err}");
}

#[test]
fn password_text_does_not_require_a_replay_scope() {
    // PasswordText carries no nonce, so there is no replay state to scope.
    assert!(SoapWsSecurity::new(&username_token_config()).is_ok());
}

#[tokio::test]
async fn replay_inactive_policy_does_not_consume_a_registry_scope() {
    let scope = "soap-replay-inactive";
    let key = soap_nonce_replay_scope_key_for_test(scope);
    let plugin = SoapWsSecurity::new_with_http_client_and_config_id(
        &timestamp_only_config(),
        PluginHttpClient::default(),
        Some(scope),
    )
    .expect("timestamp-only plugin must construct");

    assert!(
        !soap_nonce_replay_registry_contains_for_test(&key).expect("registry"),
        "a policy that cannot make replay claims must keep private state"
    );
    drop(plugin);
}

#[test]
fn openapi_requires_replay_scope_for_password_digest_only() {
    let spec: Value =
        serde_yaml::from_str(include_str!("../../../openapi.yaml")).expect("openapi.yaml parses");
    let schema = &spec["components"]["schemas"]["SoapWsSecurityConfig"];
    let validator = jsonschema::draft202012::options()
        .build(schema)
        .expect("SoapWsSecurityConfig schema compiles");

    let digest_missing_scope = json!({
        "timestamp": { "require": true },
        "username_token": {
            "enabled": true,
            "password_type": "PasswordDigest",
            "credentials": [{"username": "alice", "password": "secret123"}]
        }
    });
    assert!(
        validator.validate(&digest_missing_scope).is_err(),
        "OpenAPI must reject PasswordDigest without nonce.replay_scope"
    );

    let digest_default_password_type = json!({
        "timestamp": { "require": true },
        "username_token": {
            "enabled": true,
            "credentials": [{"username": "alice", "password": "secret123"}]
        }
    });
    assert!(
        validator.validate(&digest_default_password_type).is_err(),
        "omitted password_type defaults to PasswordDigest and still requires replay_scope"
    );

    let digest_ok = json!({
        "timestamp": { "require": true },
        "username_token": {
            "enabled": true,
            "password_type": "PasswordDigest",
            "credentials": [{"username": "alice", "password": "secret123"}]
        },
        "nonce": { "replay_scope": "process" }
    });
    assert!(
        validator.validate(&digest_ok).is_ok(),
        "PasswordDigest with an explicit replay_scope must validate"
    );

    let shared_without_redis = json!({
        "timestamp": { "require": true },
        "username_token": {
            "enabled": true,
            "password_type": "PasswordDigest",
            "credentials": [{"username": "alice", "password": "secret123"}]
        },
        "nonce": { "replay_scope": "shared" }
    });
    assert!(
        validator.validate(&shared_without_redis).is_err(),
        "shared replay scope must require sync_mode=redis and redis_url"
    );

    let shared_with_redis = json!({
        "timestamp": { "require": true },
        "username_token": {
            "enabled": true,
            "password_type": "PasswordDigest",
            "credentials": [{"username": "alice", "password": "secret123"}]
        },
        "nonce": { "replay_scope": "shared" },
        "sync_mode": "redis",
        "redis_url": "redis://redis.internal:6379"
    });
    assert!(
        validator.validate(&shared_with_redis).is_ok(),
        "shared replay scope with Redis must validate"
    );

    let process_with_redis = json!({
        "timestamp": { "require": true },
        "username_token": {
            "enabled": true,
            "password_type": "PasswordDigest",
            "credentials": [{"username": "alice", "password": "secret123"}]
        },
        "nonce": { "replay_scope": "process" },
        "sync_mode": "redis",
        "redis_url": "redis://redis.internal:6379"
    });
    assert!(
        validator.validate(&process_with_redis).is_err(),
        "sync_mode=redis must require replay_scope=shared"
    );

    let text_ok = json!({
        "timestamp": { "require": false },
        "username_token": {
            "enabled": true,
            "password_type": "PasswordText",
            "credentials": [{"username": "alice", "password": "secret123"}]
        }
    });
    assert!(
        validator.validate(&text_ok).is_ok(),
        "PasswordText must remain valid without a replay scope"
    );
}

#[test]
fn invalid_replay_scope_value_is_rejected() {
    let mut config = username_token_digest_config();
    config["nonce"]["replay_scope"] = json!("cluster");
    let err = SoapWsSecurity::new(&config)
        .err()
        .expect("an unknown replay scope must reject");
    assert!(err.contains("'process' or 'shared'"), "{err}");
    assert!(
        !err.contains("cluster"),
        "the rejected value must not be echoed: {err}"
    );
}

#[test]
fn shared_replay_scope_requires_a_redis_backend() {
    let mut config = username_token_digest_config();
    config["nonce"]["replay_scope"] = json!("shared");
    let err = SoapWsSecurity::new(&config)
        .err()
        .expect("shared scope without redis must fail closed at admission");
    assert!(err.contains("sync_mode"), "{err}");
}

#[test]
fn redis_sync_mode_requires_the_shared_replay_scope() {
    let mut config = username_token_digest_config();
    config["sync_mode"] = json!("redis");
    config["redis_url"] = json!("redis://127.0.0.1:6379");
    let err = SoapWsSecurity::new(&config)
        .err()
        .expect("a redis backend that nothing claims against must fail admission");
    assert!(err.contains("replay_scope"), "{err}");
}

#[test]
fn misspelled_redis_root_keys_still_fail_closed() {
    let mut config = username_token_digest_config();
    config["redis_ur1"] = json!("redis://127.0.0.1:6379");
    assert!(
        SoapWsSecurity::new(&config).is_err(),
        "the root allowlist must union the shared Redis keys, not open the root"
    );
}

#[test]
fn zero_replay_bounds_remain_rejected_for_password_digest() {
    let mut config = username_token_digest_config();
    config["nonce"]["max_cache_size"] = json!(0);
    let err = SoapWsSecurity::new(&config)
        .err()
        .expect("nonce.max_cache_size = 0 must be rejected");
    assert!(err.contains("max_cache_size"), "{err}");
}

// ── Replay state across generations, instances, and replicas ────────────────

fn digest_plugin_with_config_id(config_id: Option<&str>) -> SoapWsSecurity {
    SoapWsSecurity::new_with_http_client_and_config_id(
        &username_token_digest_config(),
        PluginHttpClient::default(),
        config_id,
    )
    .expect("digest plugin must construct")
}

// These construct a `PluginHttpClient`, so they run on a runtime like every
// other client-constructing plugin test.
//
// Process-global replay scopes are shared by the full unit binary. Every test
// that joins that registry is serialized on `soap_nonce_replay_registry` so the
// capacity-fill proof cannot starve siblings, and intentional
// poisoned/inconsistent leftovers are force-removed via
// [`SoapNonceReplayScopeLease`] after fail-closed assertions.
#[tokio::test]
#[serial_test::serial(soap_nonce_replay_registry)]
async fn replay_state_survives_a_reload_generation_swap() {
    // A reload builds a new plugin instance from the same plugin-config
    // resource. Before this fix that instance started from an empty cache, so
    // replaying a captured token across a reload always succeeded.
    let scope = "soap-reload-scope-a";
    let _lease = SoapNonceReplayScopeLease::for_plugin_config_ids(&[scope]);
    let generation_one = digest_plugin_with_config_id(Some(scope));
    assert!(
        generation_one
            .check_nonce_replay("reload-scope-nonce")
            .is_ok()
    );

    let generation_two = digest_plugin_with_config_id(Some(scope));
    let replay = generation_two
        .check_nonce_replay("reload-scope-nonce")
        .expect_err("a new generation must inherit the previous generation's claims");
    assert!(replay.contains("nonce replay detected"), "{replay}");

    // Live claims stay live for the old generation too — one shared scope.
    let replay_old = generation_one
        .check_nonce_replay("reload-scope-nonce")
        .expect_err("the outgoing generation shares the same state");
    assert!(replay_old.contains("nonce replay detected"), "{replay_old}");
}

#[tokio::test]
#[serial_test::serial(soap_nonce_replay_registry)]
async fn distinct_plugin_configs_do_not_share_a_replay_scope() {
    let _lease =
        SoapNonceReplayScopeLease::for_plugin_config_ids(&["soap-scope-b", "soap-scope-c"]);
    let a = digest_plugin_with_config_id(Some("soap-scope-b"));
    let b = digest_plugin_with_config_id(Some("soap-scope-c"));
    assert!(a.check_nonce_replay("independent-scope-nonce").is_ok());
    assert!(
        b.check_nonce_replay("independent-scope-nonce").is_ok(),
        "an unrelated plugin config must not answer from another policy's state"
    );
}

#[tokio::test]
#[serial_test::serial(soap_nonce_replay_registry)]
async fn identityless_construction_gets_private_replay_state() {
    // Admin config validation constructs the plugin without a resource id. That
    // construction must not read, mutate, or consume a live proxy's claims.
    let _lease = SoapNonceReplayScopeLease::for_plugin_config_ids(&["soap-scope-d"]);
    let live = digest_plugin_with_config_id(Some("soap-scope-d"));
    assert!(live.check_nonce_replay("validation-probe-nonce").is_ok());

    let validation_instance = SoapWsSecurity::new(&username_token_digest_config()).unwrap();
    assert!(
        validation_instance
            .check_nonce_replay("validation-probe-nonce")
            .is_ok(),
        "a validation construction must not consult live replay state"
    );
    assert!(
        live.check_nonce_replay("validation-probe-nonce").is_err(),
        "and must not have consumed the live claim either"
    );
}

// ── Retired process replay-scope pruning ────────────────────────────────────

#[tokio::test]
#[serial_test::serial(soap_nonce_replay_registry)]
async fn active_strong_references_keep_a_replay_scope_from_being_pruned() {
    let scope = "soap-prune-active-ref";
    let probe = "soap-prune-active-ref-probe";
    let _lease = SoapNonceReplayScopeLease::for_plugin_config_ids(&[scope, probe]);
    let key = soap_nonce_replay_scope_key_for_test(scope);
    let live = digest_plugin_with_config_id(Some(scope));
    live.check_nonce_replay("active-ref-nonce")
        .expect("claim must admit");

    // Creating an unrelated scope runs cold-path pruning; the live holder keeps
    // strong_count > 1, so the scope must remain.
    let _probe = digest_plugin_with_config_id(Some(probe));
    assert!(
        soap_nonce_replay_registry_contains_for_test(&key).expect("registry"),
        "a scope with a live plugin generation must not be pruned"
    );
    assert!(
        live.check_nonce_replay("active-ref-nonce").is_err(),
        "the live claim must still be present"
    );
}

#[tokio::test]
#[serial_test::serial(soap_nonce_replay_registry)]
async fn a_retired_scope_with_a_live_claim_is_retained() {
    let scope = "soap-prune-live-retired";
    let probe = "soap-prune-live-retired-probe";
    let _lease = SoapNonceReplayScopeLease::for_plugin_config_ids(&[scope, probe]);
    let key = soap_nonce_replay_scope_key_for_test(scope);
    {
        let generation = digest_plugin_with_config_id(Some(scope));
        generation
            .check_nonce_replay("live-retired-nonce")
            .expect("claim must admit");
    }
    // Registry is now the sole strong owner, but the newest claim is still live.
    let _probe = digest_plugin_with_config_id(Some(probe));
    assert!(
        soap_nonce_replay_registry_contains_for_test(&key).expect("registry"),
        "a retired scope with any live claim must stay fail-closed"
    );
    let rejoined = digest_plugin_with_config_id(Some(scope));
    assert!(
        rejoined.check_nonce_replay("live-retired-nonce").is_err(),
        "rejoining must inherit the live claim rather than starting empty"
    );
}

#[tokio::test]
#[serial_test::serial(soap_nonce_replay_registry)]
async fn a_fully_expired_retired_scope_is_reclaimed() {
    let scope = "soap-prune-expired-retired";
    let probe = "soap-prune-expired-retired-probe";
    let _lease = SoapNonceReplayScopeLease::for_plugin_config_ids(&[scope, probe]);
    let key = soap_nonce_replay_scope_key_for_test(scope);
    let epoch = std::time::Instant::now()
        .checked_sub(Duration::from_secs(CLAIM_RETENTION_SECONDS + 120))
        .expect("instant subtract");
    {
        let harness =
            SoapNonceReplayHarness::with_scope(&username_token_digest_config(), scope, epoch)
                .expect("scoped harness");
        harness
            .claim_at("expired-retired-nonce", Duration::ZERO)
            .expect("backdated claim must admit");
    }
    assert!(soap_nonce_replay_registry_contains_for_test(&key).expect("registry"));
    let _probe = digest_plugin_with_config_id(Some(probe));
    assert!(
        !soap_nonce_replay_registry_contains_for_test(&key).expect("registry"),
        "a retired scope whose newest claim is past retention must be reclaimed"
    );
    let rejoined = digest_plugin_with_config_id(Some(scope));
    assert!(
        rejoined.check_nonce_replay("expired-retired-nonce").is_ok(),
        "reclaiming must free the slot without resurrecting expired claims"
    );
}

#[tokio::test]
#[serial_test::serial(soap_nonce_replay_registry)]
async fn an_empty_retired_scope_is_reclaimable() {
    let scope = "soap-prune-empty-retired";
    let probe = "soap-prune-empty-retired-probe";
    let _lease = SoapNonceReplayScopeLease::for_plugin_config_ids(&[scope, probe]);
    let key = soap_nonce_replay_scope_key_for_test(scope);
    {
        let _generation = digest_plugin_with_config_id(Some(scope));
    }
    let _probe = digest_plugin_with_config_id(Some(probe));
    assert!(
        !soap_nonce_replay_registry_contains_for_test(&key).expect("registry"),
        "an empty retired scope must free its registry slot"
    );
}

#[tokio::test]
#[serial_test::serial(soap_nonce_replay_registry)]
async fn retired_empty_scopes_free_registry_capacity() {
    let http = PluginHttpClient::default();
    let mut lease = SoapNonceReplayScopeLease::empty();
    let mut holders = Vec::new();
    for i in 0..(MAX_NONCE_REPLAY_SCOPES_FOR_TESTS + 8) {
        let id = format!("soap-prune-cap-fill-{i}");
        lease.track_plugin_config_id(&id);
        match SoapWsSecurity::new_with_http_client_and_config_id(
            &username_token_digest_config(),
            http.clone(),
            Some(&id),
        ) {
            Ok(plugin) => holders.push(plugin),
            Err(err) => {
                assert!(
                    err.contains("refusing to create more"),
                    "unexpected construction failure before the cap: {err}"
                );
                break;
            }
        }
    }
    assert!(
        !holders.is_empty(),
        "test must hold at least one scope against the registry cap"
    );
    lease.track_plugin_config_id("soap-prune-cap-overflow-while-held");
    let overflow = SoapWsSecurity::new_with_http_client_and_config_id(
        &username_token_digest_config(),
        http.clone(),
        Some("soap-prune-cap-overflow-while-held"),
    );
    assert!(
        overflow.is_err(),
        "held empty scopes must consume registry capacity"
    );

    holders.clear();
    lease.track_plugin_config_id("soap-prune-cap-after-reclaim");
    SoapWsSecurity::new_with_http_client_and_config_id(
        &username_token_digest_config(),
        http,
        Some("soap-prune-cap-after-reclaim"),
    )
    .expect("reclaiming empty retired scopes must free capacity for a new scope");
}

#[tokio::test]
#[serial_test::serial(soap_nonce_replay_registry)]
async fn poisoned_retired_scopes_are_not_replaced() {
    let scope = "soap-prune-poisoned";
    let probe = "soap-prune-poisoned-probe";
    let _lease = SoapNonceReplayScopeLease::for_plugin_config_ids(&[scope, probe]);
    let key = soap_nonce_replay_scope_key_for_test(scope);
    soap_poison_process_replay_scope_for_test(&username_token_digest_config(), scope)
        .expect("poison helper");
    let _probe = digest_plugin_with_config_id(Some(probe));
    assert!(
        soap_nonce_replay_registry_contains_for_test(&key).expect("registry"),
        "poisoned state must remain fail-closed rather than being silently replaced"
    );
    let err = SoapWsSecurity::new_with_http_client_and_config_id(
        &username_token_digest_config(),
        PluginHttpClient::default(),
        Some(scope),
    )
    .err()
    .expect("rejoining a poisoned scope must fail closed");
    assert!(err.contains("unavailable"), "{err}");
}

#[tokio::test]
#[serial_test::serial(soap_nonce_replay_registry)]
async fn inconsistent_retired_scopes_are_not_replaced() {
    let scope = "soap-prune-inconsistent";
    let probe = "soap-prune-inconsistent-probe";
    let _lease = SoapNonceReplayScopeLease::for_plugin_config_ids(&[scope, probe]);
    let key = soap_nonce_replay_scope_key_for_test(scope);
    soap_retire_inconsistent_process_replay_scope_for_test(&username_token_digest_config(), scope)
        .expect("inconsistent retire helper");
    let _probe = digest_plugin_with_config_id(Some(probe));
    assert!(
        soap_nonce_replay_registry_contains_for_test(&key).expect("registry"),
        "structurally inconsistent state must not be silently replaced"
    );
    let rejoined = digest_plugin_with_config_id(Some(scope));
    assert_eq!(
        rejoined
            .check_nonce_replay("inconsistent-probe-nonce")
            .expect_err("inconsistent state must fail closed"),
        "WS-Security: replay protection state is at capacity"
    );
}

#[tokio::test]
#[serial_test::serial(soap_nonce_replay_registry)]
async fn same_cardinality_index_drift_is_not_reclaimed() {
    let scope = "soap-prune-same-cardinality-drift";
    let probe = "soap-prune-same-cardinality-probe";
    let _lease = SoapNonceReplayScopeLease::for_plugin_config_ids(&[scope, probe]);
    let key = soap_nonce_replay_scope_key_for_test(scope);
    soap_retire_same_cardinality_drift_scope_for_test(&username_token_digest_config(), scope)
        .expect("same-cardinality retire helper");
    let _probe = digest_plugin_with_config_id(Some(probe));
    assert!(
        soap_nonce_replay_registry_contains_for_test(&key).expect("registry"),
        "cache/index mapping drift must not be reclaimed as expired state"
    );
}

#[tokio::test]
#[serial_test::serial(soap_nonce_replay_registry)]
async fn overlapping_generations_retain_one_shared_replay_state() {
    let scope = "soap-prune-overlap-gens";
    let probe = "soap-prune-overlap-gens-probe";
    let _lease = SoapNonceReplayScopeLease::for_plugin_config_ids(&[scope, probe]);
    let key = soap_nonce_replay_scope_key_for_test(scope);
    let generation_one = digest_plugin_with_config_id(Some(scope));
    let generation_two = digest_plugin_with_config_id(Some(scope));
    generation_one
        .check_nonce_replay("overlap-nonce")
        .expect("first claim");
    drop(generation_one);
    let _probe = digest_plugin_with_config_id(Some(probe));
    assert!(
        soap_nonce_replay_registry_contains_for_test(&key).expect("registry"),
        "an overlapping live generation must keep the shared scope"
    );
    assert!(
        generation_two.check_nonce_replay("overlap-nonce").is_err(),
        "both generations must share one claim map"
    );
}

#[tokio::test]
#[serial_test::serial(soap_nonce_replay_registry)]
async fn intentional_poisoned_scope_is_externally_isolated_after_fail_closed_proof() {
    // Production prune must keep poisoned state fail-closed; external tests
    // must still be able to free the slot afterward so parallel suite siblings
    // cannot exhaust the process-global registry cap.
    let scope = "soap-prune-poisoned-isolation";
    let probe = "soap-prune-poisoned-isolation-probe";
    let successor = "soap-prune-poisoned-isolation-successor";
    let _lease = SoapNonceReplayScopeLease::for_plugin_config_ids(&[scope, probe, successor]);
    let key = soap_nonce_replay_scope_key_for_test(scope);

    soap_poison_process_replay_scope_for_test(&username_token_digest_config(), scope)
        .expect("poison helper");
    let _probe = digest_plugin_with_config_id(Some(probe));
    assert!(
        soap_nonce_replay_registry_contains_for_test(&key).expect("registry"),
        "production prune must leave poisoned state in place"
    );
    let err = SoapWsSecurity::new_with_http_client_and_config_id(
        &username_token_digest_config(),
        PluginHttpClient::default(),
        Some(scope),
    )
    .err()
    .expect("rejoining a poisoned scope must fail closed");
    assert!(err.contains("unavailable"), "{err}");

    assert!(
        soap_remove_nonce_replay_scope_for_test(&key).expect("external isolation"),
        "test-support removal must free the poisoned slot"
    );
    assert!(
        !soap_nonce_replay_registry_contains_for_test(&key).expect("registry"),
        "external isolation must drop the registry entry without production reclaim"
    );
    // Prove a fresh successor can join without hitting the process-global cap.
    let _successor = digest_plugin_with_config_id(Some(successor));
}

#[tokio::test]
#[serial_test::serial(soap_nonce_replay_registry)]
async fn blank_plugin_config_id_fails_closed() {
    let err = SoapWsSecurity::new_with_http_client_and_config_id(
        &username_token_digest_config(),
        PluginHttpClient::default(),
        Some("   "),
    )
    .err()
    .expect("a blank id would collapse every policy onto one scope");
    assert!(err.contains("must not be blank"), "{err}");
}

// ── Shared (multi-replica) backend ──────────────────────────────────────────

fn shared_scope_config(redis_url: &str) -> Value {
    let mut config = username_token_digest_config();
    config["nonce"]["replay_scope"] = json!("shared");
    config["sync_mode"] = json!("redis");
    config["redis_url"] = json!(redis_url);
    config["redis_connect_timeout_seconds"] = json!(1);
    config
}

#[tokio::test]
async fn shared_replay_scope_constructs_and_advertises_its_backend_for_dns_warmup() {
    let plugin =
        SoapWsSecurity::new(&shared_scope_config("redis://soap-nonce.invalid:6379")).unwrap();
    assert_eq!(
        plugin.warmup_hostnames(),
        vec!["soap-nonce.invalid".to_string()],
        "a shared replay backend must be pre-warmed like every other Redis-backed plugin"
    );
}

#[tokio::test]
async fn shared_replay_scope_never_answers_from_process_local_state() {
    // A shared-scope instance holds no local map. Answering "not seen" from an
    // empty one would be a silent, per-replica bypass, so the process-local
    // entry point fails closed instead.
    let plugin = SoapWsSecurity::new(&shared_scope_config("redis://127.0.0.1:1")).unwrap();
    let err = plugin
        .check_nonce_replay("shared-scope-local-probe")
        .expect_err("a shared-scope instance has no process-local claim to make");
    assert!(err.contains("backend is unavailable"), "{err}");
}

#[tokio::test]
async fn shared_backend_outage_fails_admission_closed() {
    // Port 1 refuses immediately, so this is a deterministic outage rather than
    // a timing-dependent one. A replay-protection outage must reject the
    // request; degrading to process-local state would reinstate exactly the
    // cross-replica bypass the shared backend exists to close.
    let plugin = SoapWsSecurity::new(&shared_scope_config("redis://127.0.0.1:1")).unwrap();
    let token = password_digest_token("alice", "secret123", b"shared-outage-01");
    let result = digest_outcome(&plugin, &token).await;
    assert!(is_reject(&result));
    assert_eq!(reject_status(&result), 401);
    assert!(
        reject_body(&result).contains("replay protection backend is unavailable"),
        "got: {}",
        reject_body(&result)
    );
}

#[tokio::test]
async fn shared_backend_outage_rejects_before_it_can_be_treated_as_authenticated() {
    let plugin = SoapWsSecurity::new(&shared_scope_config("redis://127.0.0.1:1")).unwrap();
    let token = password_digest_token("alice", "secret123", b"shared-outage-02");
    let mut ctx = make_ctx_with_soap_body(&wrap_soap(&token));
    let mut headers = soap_headers();
    let result = run_soap_request_policy(&plugin, &mut ctx, &mut headers).await;
    assert!(is_reject(&result));
    assert!(
        !ctx.metadata.contains_key("soap_ws_username"),
        "an unclaimable nonce must not leave an authenticated identity behind"
    );
}

// ── Invalid-digest flood ordering ───────────────────────────────────────────

#[tokio::test]
async fn an_invalid_digest_flood_cannot_displace_a_captured_live_nonce() {
    // Capacity is deliberately tiny. Unauthenticated attempts must never reach
    // replay state at all, so no number of them can make room by displacing the
    // legitimate claim, and the legitimate nonce stays replay-protected.
    let mut config = username_token_digest_config();
    config["nonce"]["max_cache_size"] = json!(2);
    let plugin = SoapWsSecurity::new(&config).unwrap();

    let victim = password_digest_token("alice", "secret123", b"victim-nonce-01!");
    assert!(
        matches!(
            digest_outcome(&plugin, &victim).await,
            PluginResult::Continue
        ),
        "the legitimate claim must be admitted first"
    );

    for index in 0..32u8 {
        let nonce = format!("flood-nonce-{index:03}");
        let attempt = password_digest_token("alice", "wrong-password", nonce.as_bytes());
        let result = digest_outcome(&plugin, &attempt).await;
        assert!(is_reject(&result), "an invalid digest must be rejected");
        assert_eq!(
            reject_body(&result),
            r#"{"error":"WS-Security: invalid credentials"}"#,
            "a failed attempt must not be reported as a replay-state outcome"
        );
    }

    let replay = digest_outcome(&plugin, &victim).await;
    assert!(is_reject(&replay));
    assert!(
        reject_body(&replay).contains("nonce replay detected"),
        "the captured nonce must still be protected after the flood: {}",
        reject_body(&replay)
    );
}

// ── The claim must outlive the token, and every future token (GHSA-54mh) ────
//
// Binding the outer Timestamp stops a captured UsernameToken from being paired
// with a freshly minted one. It does nothing once the *claim* has expired: the
// captured request is then replayable unchanged, both of its instants still
// inside their windows.
//
// Deriving retention from the *configured* window is not enough either. Replay
// state outlives the generation that wrote it, so a claim has to cover every
// window a later admitted generation may open — including a widening that lands
// long after a per-generation retention would already have let the entry be
// reclaimed or refreshed, at which point nothing can resurrect it. These tests
// pin the contract that closes that: every claim, in both scopes, is retained
// for the fixed `CLAIM_RETENTION_SECONDS` horizon — the widest acceptance span
// the schema admits anywhere — with no operator knob able to shorten it.

/// A PasswordDigest policy with an explicit inner `Created` window.
fn digest_config_with_created_window(max_age: u64, skew: u64) -> Value {
    let mut config = username_token_digest_config();
    config["username_token"]["created_max_age_seconds"] = json!(max_age);
    config["username_token"]["created_clock_skew_seconds"] = json!(skew);
    config["username_token"]["require_timestamp_binding"] = json!(false);
    config
}

fn retention_seconds_of(config: &Value) -> u64 {
    SoapNonceReplayHarness::new(config)
        .expect("config must admit")
        .snapshot()
        .expect("snapshot")
        .retention_seconds
}

#[test]
fn retention_is_the_fixed_global_horizon_for_every_admissible_window() {
    // Not derived from the configured window: the narrowest and the widest
    // admissible policies retain claims for exactly the same span, so no
    // reload from any one of them to any other can leave a gap.
    assert_eq!(
        retention_seconds_of(&username_token_digest_config()),
        CLAIM_RETENTION_SECONDS,
        "the default policy"
    );
    for (max_age, skew) in [(1, 0), (1, 3_600), (300, 300), (86_400, 0), (86_400, 3_600)] {
        assert_eq!(
            retention_seconds_of(&digest_config_with_created_window(max_age, skew)),
            CLAIM_RETENTION_SECONDS,
            "created_max_age_seconds = {max_age}, created_clock_skew_seconds = {skew}"
        );
    }
}

#[test]
fn the_removed_retention_key_is_rejected_rather_than_ignored() {
    // `nonce.cache_ttl_seconds` cannot shorten retention any more, so it is gone
    // from the schema entirely rather than accepted and silently ignored — an
    // accepted-but-inert knob would misdescribe the guarantee. Per the build-out
    // policy there is no compatibility shim.
    for value in [json!(1), json!(901), json!(93_601), json!(200_000)] {
        let mut config = username_token_digest_config();
        config["nonce"]["cache_ttl_seconds"] = value.clone();
        let err = SoapWsSecurity::new(&config)
            .err()
            .unwrap_or_else(|| panic!("nonce.cache_ttl_seconds = {value} must be rejected"));
        assert!(
            err.contains("cache_ttl_seconds"),
            "the rejected key must be named: {err}"
        );
    }
}

#[test]
fn the_maximum_created_window_remains_admissible() {
    // The fixed horizon is derived from the schema ceilings, so the widest
    // acceptance settings stay configurable and are still covered.
    let maximum = digest_config_with_created_window(86_400, 3_600);
    assert_eq!(retention_seconds_of(&maximum), CLAIM_RETENTION_SECONDS);
    assert_eq!(
        CLAIM_RETENTION_SECONDS,
        86_400 + 2 * 3_600 + 1,
        "the horizon is MAX_UT_CREATED_MAX_AGE + 2 × MAX_CLOCK_SKEW + 1"
    );
}

#[test]
fn a_password_text_policy_is_not_forced_to_size_a_replay_cache() {
    // Replay state is unreachable without PasswordDigest. The policy still
    // admits with no nonce configuration at all.
    let config = json!({
        "timestamp": { "require": false },
        "username_token": {
            "enabled": true,
            "password_type": "PasswordText",
            "credentials": [{"username": "alice", "password": "secret123"}]
        },
        "reject_missing_security_header": true
    });
    assert_eq!(retention_seconds_of(&config), CLAIM_RETENTION_SECONDS);
}

#[test]
fn the_created_acceptance_interval_has_exactly_the_span_the_retention_covers() {
    // Exact endpoints at an injected instant, so nothing here races the clock.
    const MAX_AGE: i64 = 10;
    const SKEW: i64 = 5;
    let config = digest_config_with_created_window(MAX_AGE as u64, SKEW as u64);
    let created_at = chrono::DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")
        .expect("fixed instant")
        .with_timezone(&chrono::Utc);
    let created = created_at.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();

    let decide = |now: chrono::DateTime<chrono::Utc>| {
        soap_username_token_created_outcome_for_test(&config, "", &created, now)
            .expect("config must admit")
    };

    // Earliest acceptance: the token may arrive a full skew *before* its own
    // Created. This is the earliest instant at which its nonce can be claimed.
    let earliest = created_at - chrono::Duration::seconds(SKEW);
    assert!(
        decide(earliest).is_ok(),
        "the future-skew boundary is accepted"
    );
    assert!(
        decide(earliest - chrono::Duration::seconds(1))
            .expect_err("one second earlier is out of policy")
            .contains("in the future")
    );

    // Latest acceptance.
    let latest = created_at + chrono::Duration::seconds(MAX_AGE + SKEW);
    assert!(decide(latest).is_ok(), "the max-age boundary is accepted");
    assert!(
        decide(latest + chrono::Duration::seconds(1))
            .expect_err("one second later is out of policy")
            .contains("too old")
    );

    // The span an unchanged token can be accepted over under this policy, and
    // the widest span any admissible policy could ever accept it over. The
    // fixed retention strictly exceeds both, which is what makes a later
    // widening safe rather than merely improbable.
    let acceptance_span = (latest - earliest).num_seconds() as u64;
    assert_eq!(acceptance_span, (MAX_AGE + 2 * SKEW) as u64);
    let widest_admissible_span = 86_400 + 2 * 3_600;
    assert!(
        CLAIM_RETENTION_SECONDS > acceptance_span
            && CLAIM_RETENTION_SECONDS > widest_admissible_span,
        "the claim must outlive every instant at which any admissible generation \
         would accept the token"
    );
}

#[test]
fn a_claim_covers_the_widest_acceptable_instant_and_expires_only_after_it() {
    // The widest admissible acceptance span, measured from the earliest instant
    // a claim can be made, is 86400 + 2 × 3600 = 93600s. The claim is live
    // through that instant and reclaimable exactly one second later.
    let harness = SoapNonceReplayHarness::new(&digest_config_with_created_window(86_400, 3_600))
        .expect("config must admit");
    assert_eq!(
        harness.snapshot().expect("snapshot").retention_seconds,
        CLAIM_RETENTION_SECONDS
    );

    harness
        .claim_at("boundary-nonce-01", Duration::ZERO)
        .expect("the earliest possible claim admits");
    assert_eq!(
        harness
            .claim_at(
                "boundary-nonce-01",
                Duration::from_secs(CLAIM_RETENTION_SECONDS - 1)
            )
            .expect_err("the last acceptable instant must still be protected"),
        "WS-Security: nonce replay detected"
    );
    // One second later the entry expires — and the token itself stopped being
    // acceptable at that same instant, so nothing is left to replay.
    harness
        .claim_at(
            "boundary-nonce-01",
            Duration::from_secs(CLAIM_RETENTION_SECONDS),
        )
        .expect("past the widest acceptance window the entry may be reclaimed");
}

// ── The residual this PR closes: retention across future generations ────────

/// A time comfortably past the retention a *narrow* generation would have
/// derived for itself (300 + 2 × 300 + 1 = 901s) and equally comfortably inside
/// the fixed horizon.
const PAST_NARROW_GENERATION_RETENTION: u64 = 2_000;

#[tokio::test]
#[serial_test::serial(soap_nonce_replay_registry)]
async fn a_claim_stays_live_past_the_retention_its_own_generation_would_have_derived() {
    // Under a per-generation retention this nonce was expired at t=901 and the
    // repeat below was an in-place *refresh* — i.e. the captured token admitted
    // a second time. The fixed horizon keeps it a replay.
    let scope = "soap-future-generation-liveness";
    let _lease = SoapNonceReplayScopeLease::for_plugin_config_ids(&[scope]);
    let harness = SoapNonceReplayHarness::with_scope(
        &digest_config_with_created_window(300, 300),
        scope,
        std::time::Instant::now(),
    )
    .expect("narrow generation must admit");

    harness
        .claim_at("future-gen-nonce-01", Duration::ZERO)
        .expect("the claim is admitted");
    assert_eq!(
        harness
            .claim_at(
                "future-gen-nonce-01",
                Duration::from_secs(PAST_NARROW_GENERATION_RETENTION)
            )
            .expect_err("the claim must still be live"),
        "WS-Security: nonce replay detected"
    );
}

#[tokio::test]
#[serial_test::serial(soap_nonce_replay_registry)]
async fn capacity_pressure_cannot_reclaim_a_claim_a_later_generation_still_needs() {
    // The other way a claim used to disappear: once past the narrow
    // generation's own retention it became reclaimable, so ordinary capacity
    // pressure removed it — and a high-water mark cannot resurrect a removed
    // entry. With a one-entry cap, the second nonce must be refused rather than
    // allowed to evict the first.
    let scope = "soap-future-generation-capacity";
    let _lease = SoapNonceReplayScopeLease::for_plugin_config_ids(&[scope]);
    let mut config = digest_config_with_created_window(300, 300);
    config["nonce"]["max_cache_size"] = json!(1);
    let harness = SoapNonceReplayHarness::with_scope(&config, scope, std::time::Instant::now())
        .expect("narrow generation must admit");

    harness
        .claim_at("capacity-nonce-01", Duration::ZERO)
        .expect("the first claim is admitted");
    assert_eq!(
        harness
            .claim_at(
                "capacity-nonce-02",
                Duration::from_secs(PAST_NARROW_GENERATION_RETENTION)
            )
            .expect_err("a live claim must never be evicted to make room"),
        "WS-Security: replay protection state is at capacity"
    );
    let snapshot = harness.snapshot().expect("snapshot");
    assert_eq!(snapshot.entry_count, 1);
    assert_eq!(snapshot.last_expired_removals, 0);
}

#[tokio::test]
#[serial_test::serial(soap_nonce_replay_registry)]
async fn a_later_maximally_widened_generation_still_detects_the_replay() {
    // The advisory's residual, end to end. A narrow generation claims a nonce.
    // Well past the retention that generation would have derived for itself, a
    // reload widens the acceptance window to the schema maximum — which is
    // exactly when the captured token becomes acceptable again. The claim is
    // still there, and stays there through the widened window's last acceptable
    // instant.
    let scope = "soap-future-generation-widening";
    let _lease = SoapNonceReplayScopeLease::for_plugin_config_ids(&[scope]);
    let epoch = std::time::Instant::now();
    let narrow = SoapNonceReplayHarness::with_scope(
        &digest_config_with_created_window(300, 300),
        scope,
        epoch,
    )
    .expect("narrow generation must admit");
    narrow
        .claim_at("widening-nonce-01", Duration::ZERO)
        .expect("the narrow generation claims the nonce");

    // The reload lands after the old per-generation retention would have
    // elapsed, so there is nothing left to extend — only what was never allowed
    // to expire.
    let wide = SoapNonceReplayHarness::with_scope(
        &digest_config_with_created_window(86_400, 3_600),
        scope,
        epoch,
    )
    .expect("widened generation must admit");
    assert_eq!(
        wide.snapshot().expect("snapshot").retention_seconds,
        CLAIM_RETENTION_SECONDS,
        "retention is the fixed horizon in every generation"
    );

    assert_eq!(
        wide.claim_at(
            "widening-nonce-01",
            Duration::from_secs(PAST_NARROW_GENERATION_RETENTION)
        )
        .expect_err("the widened generation must still see a replay"),
        "WS-Security: nonce replay detected"
    );
    // And through the last instant the widened window itself would accept the
    // unchanged token.
    assert_eq!(
        wide.claim_at(
            "widening-nonce-01",
            Duration::from_secs(CLAIM_RETENTION_SECONDS - 1)
        )
        .expect_err("the widened acceptance window must be fully covered"),
        "WS-Security: nonce replay detected"
    );
}

#[tokio::test]
#[serial_test::serial(soap_nonce_replay_registry)]
async fn no_generation_can_expire_or_refresh_another_generations_claim() {
    // Both directions at once: neither a narrower nor a wider generation has a
    // retention of its own to impose, so a claim behaves identically whichever
    // generation observes it.
    let scope = "soap-generation-symmetry";
    let _lease = SoapNonceReplayScopeLease::for_plugin_config_ids(&[scope]);
    let epoch = std::time::Instant::now();
    let wide = SoapNonceReplayHarness::with_scope(
        &digest_config_with_created_window(86_400, 3_600),
        scope,
        epoch,
    )
    .expect("wide generation must admit");
    wide.claim_at("symmetry-nonce-01", Duration::ZERO)
        .expect("the wide generation claims the nonce");

    let narrow =
        SoapNonceReplayHarness::with_scope(&digest_config_with_created_window(1, 0), scope, epoch)
            .expect("narrow generation must admit");
    assert_eq!(
        narrow.snapshot().expect("snapshot").retention_seconds,
        CLAIM_RETENTION_SECONDS,
        "the narrowest admissible generation reads the same fixed horizon"
    );

    for (label, harness) in [("narrow", &narrow), ("wide", &wide)] {
        assert_eq!(
            harness
                .claim_at(
                    "symmetry-nonce-01",
                    Duration::from_secs(PAST_NARROW_GENERATION_RETENTION)
                )
                .expect_err("no generation may expire or refresh the claim"),
            "WS-Security: nonce replay detected",
            "{label} generation"
        );
    }
}

// Constructs a Redis client like every other shared-backend test, so it runs
// on a runtime.
#[tokio::test]
async fn the_shared_claim_ttl_is_the_fixed_future_safe_horizon() {
    // `SET NX EX` cannot extend a key it did not create, so a per-generation TTL
    // would be unfixable in the widening direction: keys written under the old
    // value expire early whatever a later generation declares, and "raise,
    // drain, then widen" is operator procedure rather than enforcement. Every
    // replica and every generation therefore writes the same fixed horizon, so
    // an existing key `SET NX` declines to touch already carries the full span.
    // Observed through a pure seam — no live server is involved.
    for (max_age, skew) in [(1, 0), (300, 300), (600, 120), (86_400, 3_600)] {
        let mut config = shared_scope_config("redis://soap-nonce.invalid:6379");
        config["username_token"]["created_max_age_seconds"] = json!(max_age);
        config["username_token"]["created_clock_skew_seconds"] = json!(skew);
        assert_eq!(
            soap_shared_claim_retention_seconds_for_test(&config).expect("shared scope seam"),
            CLAIM_RETENTION_SECONDS,
            "created_max_age_seconds = {max_age}, created_clock_skew_seconds = {skew}"
        );
    }

    // The keyspace retention is not declarable either, on this path or any
    // other: the removed key fails admission closed.
    let mut declared = shared_scope_config("redis://soap-nonce.invalid:6379");
    declared["nonce"]["cache_ttl_seconds"] = json!(7_200);
    let err = SoapWsSecurity::new(&declared)
        .err()
        .expect("a declared keyspace retention must be refused");
    assert!(err.contains("cache_ttl_seconds"), "{err}");
}

// ── Advisory regression coverage ────────────────────────────────────────────
//
// GHSA-435h-f785-wmm4 — client-selected/misparsed media type bypasses SOAP
//                       protection
// GHSA-9g4v-h9hm-846r — reference×body XML work before signature authentication
// GHSA-gfrx-43w6-jq3c — SOAP identity established after authorization
// GHSA-f44p-hfqr-cvcc — SAML assertions lack recipient/freshness/replay binding
// GHSA-3mwq-c8j6-9xhp — X.509 signatures need not protect the SOAP Body

mod advisory_regressions {
    use super::*;

    fn strict_username_token_config() -> serde_json::Value {
        json!({
            "timestamp": { "require": false },
            "username_token": {
                "enabled": true,
                "password_type": "PasswordText",
                "credentials": [{"username": "alice", "password": "secret123"}]
            },
            "reject_missing_security_header": true
        })
    }

    fn valid_username_token_body() -> String {
        wrap_soap(
            r#"<wsse:UsernameToken>
        <wsse:Username>alice</wsse:Username>
        <wsse:Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText">secret123</wsse:Password>
    </wsse:UsernameToken>"#,
        )
    }

    fn ctx_with(body: &str, content_type: Option<&str>) -> RequestContext {
        let mut ctx = RequestContext::new(
            "127.0.0.1".to_string(),
            "POST".to_string(),
            "/ws".to_string(),
        );
        if let Some(content_type) = content_type {
            ctx.headers
                .insert("content-type".to_string(), content_type.to_string());
        }
        ctx.request_body_bytes = Some(bytes::Bytes::copy_from_slice(body.as_bytes()));
        ctx
    }

    // ── GHSA-435h-f785-wmm4 ─────────────────────────────────────────────

    /// A SOAP envelope labelled with a non-SOAP media type used to skip the
    /// whole policy. On a strict route it is now refused before dispatch, and
    /// the body is not even buffered.
    #[tokio::test]
    async fn mislabelled_soap_is_rejected_on_a_strict_route() {
        let plugin = SoapWsSecurity::new(&strict_username_token_config()).unwrap();
        let body = wrap_soap("<wsse:UsernameToken/>");

        for content_type in [
            "application/octet-stream",
            "text/plain",
            "application/json",
            "multipart/form-data; boundary=application/xml",
        ] {
            let mut ctx = ctx_with(&body, Some(content_type));
            assert!(
                !plugin.should_buffer_request_body(&ctx),
                "{content_type} must not be buffered as SOAP"
            );
            let mut headers = soap_headers_with_content_type(content_type);
            let result = run_soap_request_policy(&plugin, &mut ctx, &mut headers).await;
            match result {
                PluginResult::Reject { status_code, .. } => assert_eq!(
                    status_code, 415,
                    "{content_type} must be refused as an unsupported representation"
                ),
                other => panic!("{content_type} must be rejected on a strict route, got {other:?}"),
            }
        }
    }

    /// An absent Content-Type is the same bypass with no label at all.
    #[tokio::test]
    async fn absent_content_type_is_rejected_on_a_strict_route() {
        let plugin = SoapWsSecurity::new(&strict_username_token_config()).unwrap();
        let mut ctx = ctx_with(&wrap_soap("<wsse:UsernameToken/>"), None);
        let mut headers = HashMap::new();
        let result = run_soap_request_policy(&plugin, &mut ctx, &mut headers).await;
        match result {
            PluginResult::Reject {
                status_code, body, ..
            } => {
                assert_eq!(status_code, 415);
                assert!(body.contains("missing a Content-Type"), "got: {body}");
            }
            other => panic!("absent Content-Type must be rejected, got {other:?}"),
        }
    }

    /// `mixed_route` is the explicit opt-out, and it is the only thing that
    /// restores pass-through.
    #[tokio::test]
    async fn mixed_route_mode_restores_pass_through() {
        let mut config = strict_username_token_config();
        config["content_type"] = json!({ "mode": "mixed_route" });
        let plugin = SoapWsSecurity::new(&config).unwrap();

        let mut ctx = ctx_with("{\"not\":\"soap\"}", Some("application/json"));
        let mut headers = non_soap_headers();
        assert!(matches!(
            run_soap_request_policy(&plugin, &mut ctx, &mut headers).await,
            PluginResult::Continue
        ));

        // A governed representation is still governed in mixed mode.
        let mut ctx = ctx_with(&wrap_soap("<wsse:UsernameToken/>"), Some("text/xml"));
        let mut headers = soap_headers();
        assert!(is_reject(
            &run_soap_request_policy(&plugin, &mut ctx, &mut headers).await
        ));
    }

    /// Parameter values that merely contain a SOAP essence never make a
    /// request SOAP, and a charset parameter never stops one being SOAP.
    #[test]
    fn media_type_classification_is_not_substring_matching() {
        let plugin = SoapWsSecurity::new(&strict_username_token_config()).unwrap();
        assert!(plugin.should_buffer_request_body(&ctx_with("", Some("text/xml; charset=utf-8"))));
        assert!(plugin.should_buffer_request_body(&ctx_with("", Some("APPLICATION/SOAP+XML"))));
        assert!(!plugin.should_buffer_request_body(&ctx_with(
            "",
            Some("multipart/form-data; boundary=application/soap+xml")
        )));
        assert!(!plugin.should_buffer_request_body(&ctx_with("", Some("application/xmlish"))));
    }

    #[test]
    fn multipart_boundary_must_not_end_in_space() {
        use ferrum_edge::_test_support::soap_classify_request_for_test as classify;
        let content_type =
            "multipart/related; type=\"application/xop+xml\"; boundary=\"MIME boundary \"";

        assert_eq!(
            classify(&strict_username_token_config(), Some(content_type)),
            Ok("reject:400:malformed_multipart".to_string())
        );
    }

    #[test]
    fn multipart_parameters_follow_http_quoted_string_rules() {
        use ferrum_edge::_test_support::soap_classify_request_for_test as classify;
        let config = strict_username_token_config();

        assert_eq!(
            classify(
                &config,
                Some("multipart/related; type='application/xop+xml'; boundary=MIME_boundary")
            ),
            Ok("reject:400:malformed_media_type".to_string()),
            "single quotes are token bytes, but the slash remains invalid in an unquoted parameter value"
        );
        assert_eq!(
            classify(
                &config,
                Some("multipart/related; type=\"application/xop+xml\"; boundary=MIME boundary")
            ),
            Ok("reject:400:malformed_media_type".to_string()),
            "a boundary containing spaces must use a double-quoted parameter"
        );
    }

    /// Classification names the representation. A bare `application/xop+xml`
    /// infoset is distinguishable from plain XML even though both carry the
    /// whole envelope in the body, because only the XOP forms may reference
    /// octets that live outside the bytes Ferrum validates.
    #[test]
    fn governed_representations_are_named_by_class() {
        use ferrum_edge::_test_support::soap_classify_request_for_test as classify;
        let config = strict_username_token_config();

        let xml = classify(&config, Some("text/xml"));
        assert_eq!(xml, Ok("xml".to_string()));

        let xop = classify(&config, Some("application/xop+xml"));
        assert_eq!(xop, Ok("xop".to_string()));

        let package = "multipart/related; type=\"application/xop+xml\"; boundary=b";
        let mtom = classify(&config, Some(package));
        assert_eq!(mtom, Ok("mtom".to_string()));

        let other = classify(&config, Some("application/json"));
        let refused = "reject:415:unsupported_media_type".to_string();
        assert_eq!(other, Ok(refused));
    }

    /// MTOM/XOP: the envelope lives in the multipart root part and is
    /// validated there; the packaging is not a way around the policy.
    #[tokio::test]
    async fn mtom_root_part_is_validated() {
        let plugin = SoapWsSecurity::new(&strict_username_token_config()).unwrap();
        let content_type = "multipart/related; type=\"application/xop+xml\"; \
                            boundary=MIME_boundary; start=\"<root@example.com>\"";
        let package = format!(
            "--MIME_boundary\r\n\
             Content-Type: application/xop+xml; charset=utf-8; type=\"text/xml\"\r\n\
             Content-Transfer-Encoding: binary\r\n\
             Content-ID: <root@example.com>\r\n\
             \r\n\
             {}\r\n\
             --MIME_boundary--\r\n",
            valid_username_token_body()
        );

        let mut ctx = ctx_with(&package, Some(content_type));
        assert!(plugin.should_buffer_request_body(&ctx));
        let mut headers = soap_headers_with_content_type(content_type);
        assert!(
            matches!(
                run_soap_request_policy(&plugin, &mut ctx, &mut headers).await,
                PluginResult::Continue
            ),
            "a valid MTOM root part must authenticate"
        );

        // Same packaging, unauthenticated envelope: refused, not forwarded.
        let hostile = package.replace("secret123", "wrong-password");
        let mut ctx = ctx_with(&hostile, Some(content_type));
        let mut headers = soap_headers_with_content_type(content_type);
        assert!(is_reject(
            &run_soap_request_policy(&plugin, &mut ctx, &mut headers).await
        ));
    }

    /// Declaring that a route does not accept MTOM must refuse SOAP-bearing
    /// multipart rather than let it stream past.
    #[tokio::test]
    async fn mtom_can_be_refused_outright() {
        let mut config = strict_username_token_config();
        config["content_type"] = json!({ "allow_mtom": false });
        let plugin = SoapWsSecurity::new(&config).unwrap();
        let content_type =
            "multipart/related; type=\"application/xop+xml\"; boundary=MIME_boundary";
        let mut ctx = ctx_with("--MIME_boundary--\r\n", Some(content_type));
        let mut headers = soap_headers_with_content_type(content_type);
        match run_soap_request_policy(&plugin, &mut ctx, &mut headers).await {
            PluginResult::Reject { status_code, .. } => assert_eq!(status_code, 415),
            other => panic!("MTOM must be refused when disallowed, got {other:?}"),
        }
    }

    // ── GHSA-gfrx-43w6-jq3c ─────────────────────────────────────────────

    /// A UsernameToken policy is an auth plugin, buffers before authenticate,
    /// and publishes the SOAP principal as the request identity.
    #[tokio::test]
    async fn soap_identity_is_published_before_authorization() {
        let plugin = SoapWsSecurity::new(&strict_username_token_config()).unwrap();
        assert!(plugin.is_auth_plugin());
        assert!(plugin.requires_request_body_before_authenticate());
        assert!(!plugin.requires_request_body_before_before_proxy());

        let mut ctx = ctx_with(&valid_username_token_body(), Some("text/xml"));
        let consumer_index = ConsumerIndex::new(&[]);
        let result = plugin.authenticate(&mut ctx, &consumer_index).await;

        assert!(matches!(result, PluginResult::Continue));
        assert_eq!(ctx.authenticated_identity.as_deref(), Some("alice"));
        assert_eq!(ctx.auth_method, Some("soap_ws_security"));
        assert_eq!(
            ctx.metadata.get("soap_ws_username").map(String::as_str),
            Some("alice")
        );
    }

    /// The timestamp-only policy establishes no principal, so it must stay out
    /// of the authentication chain (otherwise every request becomes
    /// "Authentication required") and keep validating in `before_proxy`.
    #[test]
    fn timestamp_only_policy_is_not_an_auth_plugin() {
        let plugin = SoapWsSecurity::new(&timestamp_only_config()).unwrap();
        assert!(!plugin.is_auth_plugin());
        assert!(!plugin.requires_request_body_before_authenticate());
        assert!(plugin.requires_request_body_before_before_proxy());
    }

    /// The two phases are mutually exclusive: an identity-establishing policy
    /// does nothing in `before_proxy`, so no message is validated twice.
    #[tokio::test]
    async fn identity_policy_does_not_double_run_in_before_proxy() {
        let plugin = SoapWsSecurity::new(&strict_username_token_config()).unwrap();
        let mut ctx = ctx_with("not a soap envelope at all", Some("text/xml"));
        let mut headers = soap_headers();
        assert!(matches!(
            plugin.before_proxy(&mut ctx, &mut headers).await,
            PluginResult::Continue
        ));
        assert!(ctx.authenticated_identity.is_none());
    }

    // ── GHSA-9g4v-h9hm-846r ─────────────────────────────────────────────

    /// Reference resolution must be unreachable for an untrusted signer.
    ///
    /// The fixture declares 64 identical References — over the ceiling of 8 and
    /// duplicated — so if References were processed first the rejection would
    /// name the ceiling or the duplicate. Because trust is settled first, the
    /// only reachable rejection is the trust failure, and none of the
    /// `O(references x body)` canonicalization work is ever performed.
    #[tokio::test]
    async fn untrusted_signer_is_refused_before_any_reference_work() {
        let large_body = "A".repeat(200_000);
        let envelope = format!(
            r#"<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
  <soap:Header>
    <wsse:Security xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
      <wsu:Timestamp wsu:Id="TS-1"><wsu:Created>{created}</wsu:Created></wsu:Timestamp>
      <wsse:BinarySecurityToken>{untrusted_cert}</wsse:BinarySecurityToken>
      <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>{references}</ds:SignedInfo><ds:SignatureValue>AAAA</ds:SignatureValue></ds:Signature>
    </wsse:Security>
  </soap:Header>
  <soap:Body wsu:Id="Body-1"><Payload>{large_body}</Payload></soap:Body>
</soap:Envelope>"#,
            created = fresh_created(),
            untrusted_cert = super::x509_roundtrip::untrusted_cert_der_b64(),
            references = std::iter::repeat_n(
                r##"<ds:Reference URI="#Body-1"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>AAAA</ds:DigestValue></ds:Reference>"##,
                64
            )
            .collect::<String>(),
            large_body = large_body,
        );

        let (plugin, _cert_file) = super::x509_roundtrip::trusted_plugin_for_advisory_test();
        let mut ctx = ctx_with(&envelope, Some("text/xml"));
        let mut headers = soap_headers();
        let result = run_soap_request_policy(&plugin, &mut ctx, &mut headers).await;

        assert!(is_reject(&result));
        let body = reject_body(&result);
        assert!(
            body.contains("not trusted"),
            "an untrusted signer must be refused on the trust check, got: {body}"
        );
        assert!(
            !body.contains("too many Signature References")
                && !body.contains("duplicate Signature Reference"),
            "reference processing must be unreachable for an untrusted signer: {body}"
        );
    }

    // ── GHSA-f44p-hfqr-cvcc ─────────────────────────────────────────────

    /// SAML now requires a declared replay scope, a service audience, and a
    /// service recipient. Each omission is a configuration error, not a weaker
    /// runtime policy.
    #[test]
    fn saml_requires_binding_and_replay_configuration() {
        // A real trust anchor on disk: `trusted_signing_certs` is loaded during
        // construction, so a nonexistent path would fail admission before any
        // of the bindings under test could be reached.
        let bundle = super::saml_fixtures::IdpBundle::new();
        let signing_cert = bundle.trusted_cert_path.to_str().unwrap();
        let base = json!({
            "timestamp": { "require": false },
            "saml": {
                "enabled": true,
                "trusted_issuers": ["https://idp.example.com"],
                "trusted_signing_certs": [signing_cert],
                "audience": "https://service.example.com",
                "recipient": "https://service.example.com/ws"
            },
            "nonce": { "replay_scope": "process" }
        });

        let mut without_audience = base.clone();
        without_audience["saml"]
            .as_object_mut()
            .unwrap()
            .remove("audience");
        let err = SoapWsSecurity::new(&without_audience)
            .err()
            .expect("saml.audience must be required");
        assert!(err.contains("config.saml.audience"), "got: {err}");

        let mut without_recipient = base.clone();
        without_recipient["saml"]
            .as_object_mut()
            .unwrap()
            .remove("recipient");
        let err = SoapWsSecurity::new(&without_recipient)
            .err()
            .expect("saml.recipient must be required");
        assert!(err.contains("config.saml.recipient"), "got: {err}");

        let mut without_scope = base.clone();
        without_scope.as_object_mut().unwrap().remove("nonce");
        let err = SoapWsSecurity::new(&without_scope)
            .err()
            .expect("saml must require a declared replay scope");
        assert!(err.contains("replay_scope"), "got: {err}");

        let mut holder_of_key = base.clone();
        holder_of_key["saml"]["allowed_subject_confirmation_methods"] =
            json!(["urn:oasis:names:tc:SAML:2.0:cm:holder-of-key"]);
        let err = SoapWsSecurity::new(&holder_of_key)
            .err()
            .expect("holder-of-key must be refused");
        assert!(err.contains("holder-of-key"), "got: {err}");
    }

    // ── GHSA-3mwq-c8j6-9xhp ─────────────────────────────────────────────

    /// `require_signed_timestamp` alongside `timestamp.require: false` is the
    /// vacuously-satisfiable pairing the advisory describes.
    #[test]
    fn contradictory_signed_timestamp_configuration_is_refused() {
        // `trusted_certs` is loaded during construction, so the pairing under
        // test is only reachable behind a trust anchor that actually exists.
        let bundle = super::saml_fixtures::IdpBundle::new();
        let err = SoapWsSecurity::new(&json!({
            "timestamp": { "require": false },
            "x509_signature": {
                "enabled": true,
                "trusted_certs": [bundle.trusted_cert_path.to_str().unwrap()],
                "require_signed_timestamp": true
            }
        }))
        .err()
        .expect("contradictory timestamp policy must be refused");
        assert!(err.contains("require_signed_timestamp"), "got: {err}");
    }

    // ── Requirement 6: the authenticated representation is what dispatches ──

    /// A later request-body transform must not be able to substitute a
    /// different message for the one that was authenticated.
    #[tokio::test]
    async fn a_mutated_body_is_refused_before_backend_dispatch() {
        let plugin = SoapWsSecurity::new(&strict_username_token_config()).unwrap();
        assert!(plugin.requires_final_request_body_before_backend_dispatch());

        let body = valid_username_token_body();
        let mut ctx = ctx_with(&body, Some("text/xml"));
        let consumer_index = ConsumerIndex::new(&[]);
        assert!(matches!(
            plugin.authenticate(&mut ctx, &consumer_index).await,
            PluginResult::Continue
        ));

        let headers = soap_headers();
        assert!(matches!(
            plugin
                .on_final_request_body_with_context(&mut ctx, &headers, body.as_bytes())
                .await,
            PluginResult::Continue
        ));

        let tampered = body.replace("Widget", "Mainframe");
        // Public metadata is deliberately untrusted. Before the private typed
        // proof, a later/custom plugin could replace the digest with the
        // transformed body's value and authorize bytes SOAP never validated.
        let tampered_digest = ring::digest::digest(&ring::digest::SHA256, tampered.as_bytes());
        let forged_public_digest = tampered_digest
            .as_ref()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        ctx.metadata.insert(
            "soap_ws_security.authenticated_body_sha256".to_string(),
            forged_public_digest,
        );
        match plugin
            .on_final_request_body_with_context(&mut ctx, &headers, tampered.as_bytes())
            .await
        {
            PluginResult::Reject { status_code, .. } => assert_eq!(status_code, 500),
            other => panic!("a mutated authenticated body must not dispatch, got {other:?}"),
        }
    }

    /// The representation binding belongs to the identity-establishing form
    /// only. A timestamp-only policy authenticates nobody and claims no
    /// integrity over the Body, so it must not bind the representation: a
    /// request-body transformer's rewrite lands immediately before the
    /// final-body hooks, and binding here would fail every governed SOAP
    /// request on such a proxy closed with `500` while protecting nothing.
    #[tokio::test]
    async fn a_timestamp_only_policy_does_not_bind_the_representation() {
        let plugin = SoapWsSecurity::new(&timestamp_only_config()).unwrap();
        assert!(!plugin.requires_final_request_body_before_backend_dispatch());
        assert!(!plugin.needs_final_request_body_context());

        let body = wrap_soap(&fresh_timestamp());
        let mut ctx = ctx_with(&body, Some("text/xml"));
        let mut headers = soap_headers();
        assert!(matches!(
            plugin.before_proxy(&mut ctx, &mut headers).await,
            PluginResult::Continue
        ));

        let transformed = body.replace("Widget", "Mainframe");
        assert!(matches!(
            plugin
                .on_final_request_body_with_context(&mut ctx, &headers, transformed.as_bytes())
                .await,
            PluginResult::Continue
        ));
    }
}

// ── Strict MTOM/XOP MIME framing (GHSA-435h-f785-wmm4 residual) ─────────────
//
// The package parser decides *which bytes are the SOAP envelope*. Any shape
// where a conforming backend parser would frame the package differently is a
// gateway/backend representation split — the exact bypass class the advisory
// describes — so every one of them fails closed here.

mod mtom_strict_framing {
    use ferrum_edge::_test_support::soap_extract_mtom_root_part_for_test as extract;

    const BOUNDARY: &str = "MIME_boundary";
    const ROOT_ID: &str = "root@example.com";

    /// A conforming two-part package: an XOP root selectable by `start`, plus
    /// one opaque attachment.
    fn package(root_body: &str, attachment_body: &str) -> String {
        format!(
            "--MIME_boundary\r\n\
             Content-Type: application/xop+xml; charset=utf-8; type=\"text/xml\"\r\n\
             Content-Transfer-Encoding: binary\r\n\
             Content-ID: <root@example.com>\r\n\
             \r\n\
             {root_body}\r\n\
             --MIME_boundary\r\n\
             Content-Type: application/octet-stream\r\n\
             Content-ID: <attachment@example.com>\r\n\
             \r\n\
             {attachment_body}\r\n\
             --MIME_boundary--\r\n"
        )
    }

    /// The resolved root part's body, as text.
    fn root_of(package: &str, start: Option<&str>) -> String {
        let resolved = extract(package.as_bytes(), BOUNDARY, start);
        let (body, _) = resolved.expect("package must resolve");
        String::from_utf8(body).expect("root part is UTF-8 here")
    }

    /// The package must fail closed with exactly `class`.
    fn assert_closed(package: &str, start: Option<&str>, class: &str) {
        let outcome = extract(package.as_bytes(), BOUNDARY, start);
        let actual = outcome.err().unwrap_or("<accepted>");
        assert_eq!(actual, class);
    }

    /// The conforming shapes still work: `start`-selected and first-part
    /// selection both resolve the envelope, the root's own Content-Type (which
    /// carries its charset) comes back with it, and an RFC 2046 preamble is
    /// ignored rather than inspected.
    #[test]
    fn valid_packages_resolve_the_root_envelope() {
        let package = package("<soap:Envelope/>", "opaque-bytes");
        assert_eq!(root_of(&package, Some(ROOT_ID)), "<soap:Envelope/>");
        assert_eq!(root_of(&package, None), "<soap:Envelope/>");

        let resolved = extract(package.as_bytes(), BOUNDARY, Some(ROOT_ID));
        let (_, content_type) = resolved.expect("package must resolve");
        assert_eq!(
            content_type,
            "application/xop+xml; charset=utf-8; type=\"text/xml\""
        );

        let with_preamble = format!("this is a MIME preamble\r\n{package}");
        assert_eq!(root_of(&with_preamble, Some(ROOT_ID)), "<soap:Envelope/>");
    }

    /// A `--boundary` that is not at the start of a line is payload, not
    /// framing. The unanchored byte-substring search this replaced truncated
    /// the envelope at the first such occurrence, so Ferrum validated a prefix
    /// of the message the backend executed in full.
    #[test]
    fn an_embedded_boundary_substring_does_not_reframe_the_root() {
        let root = "<soap:Envelope><!--MIME_boundary--></soap:Envelope>";
        let package = package(root, "opaque-bytes");
        assert_eq!(
            root_of(&package, Some(ROOT_ID)),
            root,
            "a boundary substring inside the envelope is payload"
        );
    }

    /// A fake part planted in the preamble must not become the root. With
    /// first-part selection an unanchored search finds the planted delimiter
    /// first and returns the attacker's envelope; anchored framing skips it and
    /// selects the real first part.
    #[test]
    fn a_payload_fake_delimiter_cannot_become_the_root() {
        let real = package("<soap:Envelope>real</soap:Envelope>", "opaque");
        // The planted delimiter is mid-line, so it is not a delimiter line for
        // any conforming parser.
        let planted = format!(
            "preamble --MIME_boundary\r\n\
             Content-Type: text/xml\r\n\
             \r\n\
             <soap:Envelope>forged</soap:Envelope>\r\n\
             {real}"
        );
        assert_eq!(
            root_of(&planted, None),
            "<soap:Envelope>real</soap:Envelope>",
            "an unanchored delimiter must not select a root"
        );
        assert_eq!(
            root_of(&planted, Some(ROOT_ID)),
            "<soap:Envelope>real</soap:Envelope>"
        );
    }

    /// LF-only framing is not MIME framing. A parser that tolerates it and one
    /// that does not disagree about every part boundary in the package.
    #[test]
    fn lf_only_framing_fails_closed() {
        let raw = package("<soap:Envelope/>", "opaque");
        let package = raw.replace("\r\n", "\n");
        assert_closed(&package, Some(ROOT_ID), "malformed_encoding");
        assert_closed(&package, None, "malformed_encoding");
    }

    /// The close-delimiter is mandatory, and nothing boundary-shaped may
    /// follow it.
    #[test]
    fn missing_or_ambiguous_closure_fails_closed() {
        let complete = package("<soap:Envelope/>", "opaque");

        let unterminated = complete.replace("--MIME_boundary--\r\n", "");
        assert_closed(&unterminated, Some(ROOT_ID), "malformed_encoding");

        // `--boundary-` is neither a part delimiter nor a close-delimiter.
        let malformed = complete.replace("boundary--\r\n", "boundary-\r\n");
        assert_closed(&malformed, Some(ROOT_ID), "malformed_encoding");

        // A second package framed inside the epilogue: a parser that keeps
        // reading past the close-delimiter frames a different root.
        let with_epilogue = format!(
            "{complete}--MIME_boundary\r\n\
             Content-Type: text/xml\r\n\
             Content-ID: <late@example.com>\r\n\
             \r\n\
             <soap:Envelope>late</soap:Envelope>\r\n\
             --MIME_boundary--\r\n"
        );
        assert_closed(&with_epilogue, Some(ROOT_ID), "malformed_encoding");

        // No parts at all.
        assert_closed("--MIME_boundary--\r\n", None, "malformed_encoding");
    }

    /// Duplicated security-relevant part headers are ambiguous. A first-wins
    /// rule here is a rule the backend need not share.
    #[test]
    fn duplicate_part_headers_fail_closed() {
        let base = package("<soap:Envelope/>", "opaque");

        let duplicate_type = base.replace(
            "Content-Transfer-Encoding: binary\r\n",
            "Content-Type: text/xml\r\nContent-Transfer-Encoding: binary\r\n",
        );
        assert_closed(&duplicate_type, Some(ROOT_ID), "malformed_encoding");

        let duplicate_id = base.replace(
            "Content-ID: <root@example.com>\r\n",
            "Content-ID: <root@example.com>\r\nContent-ID: <b@example.com>\r\n",
        );
        assert_closed(&duplicate_id, Some(ROOT_ID), "malformed_encoding");

        let duplicate_cte = base.replace(
            "Content-Transfer-Encoding: binary\r\n",
            "Content-Transfer-Encoding: binary\r\nContent-Transfer-Encoding: 8bit\r\n",
        );
        assert_closed(&duplicate_cte, Some(ROOT_ID), "malformed_encoding");
    }

    /// Two parts claiming one `Content-ID` let `start` resolve to either
    /// envelope; RFC 2387 requires package-unique ids.
    #[test]
    fn duplicate_root_content_ids_fail_closed() {
        let base = package("<soap:Envelope>real</soap:Envelope>", "opaque");
        let package = base.replace("<attachment@example.com>", "<root@example.com>");
        assert_closed(&package, Some(ROOT_ID), "malformed_encoding");
        // Even first-part selection must not silently prefer one of them.
        assert_closed(&package, None, "malformed_encoding");
    }

    /// Obsolete folded continuation lines unfold differently across parsers.
    #[test]
    fn folded_part_headers_fail_closed() {
        let base = package("<soap:Envelope/>", "opaque");
        let package = base.replace(
            "application/xop+xml; charset=utf-8;",
            "application/xop+xml;\r\n charset=utf-8;",
        );
        assert_closed(&package, Some(ROOT_ID), "malformed_encoding");
    }

    /// A header line with no colon, a non-ASCII header block, and a blank
    /// `Content-ID` are all ambiguous syntax rather than readable metadata.
    #[test]
    fn malformed_part_headers_fail_closed() {
        let base = package("<soap:Envelope/>", "opaque");

        let no_colon = base.replace(
            "Content-Transfer-Encoding: binary\r\n",
            "Content-Transfer-Encoding: binary\r\nnot-a-header-line\r\n",
        );
        assert_closed(&no_colon, Some(ROOT_ID), "malformed_encoding");

        let non_ascii = base.replace("<root@example.com>", "<r\u{00f6}ot>");
        assert_closed(&non_ascii, Some(ROOT_ID), "malformed_encoding");

        let blank_id = base.replace("<root@example.com>", "<>");
        assert_closed(&blank_id, Some(ROOT_ID), "malformed_encoding");
    }

    /// `start` naming a part the package does not contain has no envelope to
    /// validate.
    #[test]
    fn unknown_start_id_fails_closed() {
        let package = package("<soap:Envelope/>", "opaque");
        let absent = Some("absent@example.com");
        assert_closed(&package, absent, "malformed_encoding");
    }

    /// The root part must itself be a SOAP/XOP infoset and must not declare a
    /// re-encoding transfer encoding, or the bytes Ferrum validates are not the
    /// bytes the backend decodes.
    #[test]
    fn a_mislabelled_or_re_encoded_root_fails_closed() {
        let base = package("<soap:Envelope/>", "opaque");

        let mislabelled = base.replace("application/xop+xml", "application/pdf");
        assert_closed(&mislabelled, Some(ROOT_ID), "unsupported_charset");

        let re_encoded = base.replace("binary\r\n", "base64\r\n");
        assert_closed(&re_encoded, Some(ROOT_ID), "unsupported_charset");
    }

    /// Part-count and header-size ceilings stay fail-closed.
    #[test]
    fn part_and_header_bounds_fail_closed() {
        // 65 parts: one over MAX_MULTIPART_PARTS.
        let mut over_capacity = String::new();
        for index in 0..65 {
            over_capacity.push_str(&format!(
                "--MIME_boundary\r\n\
                 Content-Type: application/octet-stream\r\n\
                 Content-ID: <part-{index}@example.com>\r\n\
                 \r\n\
                 payload\r\n"
            ));
        }
        over_capacity.push_str("--MIME_boundary--\r\n");
        assert_closed(&over_capacity, None, "malformed_encoding");

        // A header block past MAX_MULTIPART_PART_HEADER_BYTES.
        let padding = "X".repeat(9_000);
        let base = package("<soap:Envelope/>", "opaque");
        let oversized = base.replace(
            "Content-Transfer-Encoding: binary\r\n",
            &format!("Content-Transfer-Encoding: binary\r\nX-Pad: {padding}\r\n"),
        );
        assert_closed(&oversized, Some(ROOT_ID), "malformed_encoding");
    }
}

// ── Governed representations always parse or reject ─────────────────────────
//
// `reject_missing_security_header: false` is the documented opt-out for a
// governed message that genuinely carries no `wsse:Security` header. It is not
// an opt-out from *parsing*: turning a gateway/backend parser disagreement into
// pass-through skips authentication, integrity, freshness, and replay for a
// message the backend still executes.

mod governed_parse_failures_reject {
    use super::*;

    fn permissive_config() -> serde_json::Value {
        json!({
            "timestamp": { "require": false },
            "username_token": {
                "enabled": true,
                "password_type": "PasswordText",
                "credentials": [{"username": "alice", "password": "secret123"}]
            },
            "reject_missing_security_header": false
        })
    }

    async fn run(body: &str) -> PluginResult {
        let plugin = SoapWsSecurity::new(&permissive_config()).unwrap();
        let mut ctx = make_ctx_with_soap_body(body);
        let mut headers = soap_headers();
        run_soap_request_policy(&plugin, &mut ctx, &mut headers).await
    }

    /// A SOAP 1.1 envelope wrapping exactly `inner`, so structural fixtures can
    /// state only the shape they are about.
    fn envelope(inner: &str) -> String {
        let ns = "http://schemas.xmlsoap.org/soap/envelope/";
        format!("<soap:Envelope xmlns:soap=\"{ns}\">{inner}</soap:Envelope>")
    }

    /// XML the gateway cannot parse is not proof that the backend cannot.
    #[tokio::test]
    async fn malformed_xml_rejects_even_with_the_missing_header_opt_out() {
        let unclosed = r#"<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">"#;
        let result = run(unclosed).await;
        assert_eq!(reject_status(&result), 400);
        assert!(
            reject_body(&result).contains("malformed"),
            "got: {}",
            reject_body(&result)
        );
    }

    /// A non-envelope root is unsupported structure, not an absent header.
    #[tokio::test]
    async fn unsupported_structure_rejects_even_with_the_opt_out() {
        let result = run("<notasoap>hello</notasoap>").await;
        assert_eq!(reject_status(&result), 400);
        let body = reject_body(&result);
        assert!(
            body.contains("not a namespace-qualified SOAP Envelope"),
            "{body}"
        );
    }

    /// Two namespace-correct `soap:Body` elements are exactly the ambiguity
    /// that lets a gateway and a backend read different messages.
    #[tokio::test]
    async fn duplicate_envelope_structure_rejects_even_with_the_opt_out() {
        let two_bodies = "<soap:Header/><soap:Body><A/></soap:Body><soap:Body><B/></soap:Body>";
        assert_eq!(reject_status(&run(&envelope(two_bodies)).await), 400);

        let two_headers = "<soap:Header/><soap:Header/><soap:Body><A/></soap:Body>";
        assert_eq!(reject_status(&run(&envelope(two_headers)).await), 400);
    }

    /// A parsing-budget failure is a refusal to read the message, so it cannot
    /// become a decision to forward it unvalidated.
    #[tokio::test]
    async fn a_parsing_budget_failure_rejects_even_with_the_opt_out() {
        let nodes = "<N/>".repeat(66_000);
        let inner = format!("<soap:Header/><soap:Body>{nodes}</soap:Body>");
        assert_eq!(reject_status(&run(&envelope(&inner)).await), 400);
    }

    /// The documented opt-out itself is preserved: a well-formed envelope whose
    /// Header genuinely carries no `wsse:Security` still passes through.
    #[tokio::test]
    async fn a_genuinely_absent_security_header_still_passes_through() {
        let inner = "<soap:Header/><soap:Body><GetPrice/></soap:Body>";
        assert!(matches!(
            run(&envelope(inner)).await,
            PluginResult::Continue
        ));
    }
}

// ── SAML assertions must name a principal (GHSA-f44p-hfqr-cvcc residual) ────
//
// An enabled SAML policy makes this instance an authentication plugin whose
// documented principal is the Subject `NameID`. An assertion that satisfies
// every binding but names nobody authenticated nothing, so accepting it —
// while burning its single-use replay id — silently degraded the request to
// unauthenticated and let an attacker spend a legitimate assertion id.

mod saml_name_id_is_required {
    use super::*;

    fn plugin_and_bundle() -> (SoapWsSecurity, saml_fixtures::IdpBundle) {
        let bundle = saml_fixtures::IdpBundle::new();
        let plugin = SoapWsSecurity::new(&saml_config(&bundle, None)).unwrap();
        (plugin, bundle)
    }

    fn assertion_with(assertion_id: &str, name_id_fragment: Option<&str>) -> String {
        let mut builder = saml_fixtures::AssertionBuilder::new(
            assertion_id,
            "https://idp.example.com/metadata",
            "alice@example.com",
        );
        builder.name_id_fragment = name_id_fragment.map(str::to_string);
        builder.build()
    }

    async fn run(plugin: &SoapWsSecurity, assertion: &str) -> PluginResult {
        let mut ctx = make_ctx_with_soap_body(&wrap_saml_assertion(assertion));
        let mut headers = soap_headers();
        run_soap_request_policy(plugin, &mut ctx, &mut headers).await
    }

    /// A fully signed, fully bound assertion whose Subject has no `NameID`
    /// authenticates nobody.
    #[tokio::test]
    async fn an_absent_name_id_rejects() {
        let (plugin, _bundle) = plugin_and_bundle();
        let result = run(&plugin, &assertion_with("_no-name-id", Some(""))).await;
        assert_eq!(reject_status(&result), 401);
        assert!(
            reject_body(&result).contains("NameID"),
            "got: {}",
            reject_body(&result)
        );
    }

    /// Two `NameID` elements are two candidate principals; a downstream
    /// consumer need not pick the one the gateway did.
    #[tokio::test]
    async fn a_duplicate_name_id_rejects() {
        let (plugin, _bundle) = plugin_and_bundle();
        let two_name_ids = concat!(
            "<saml:NameID>alice@example.com</saml:NameID>",
            "<saml:NameID>mallory@example.com</saml:NameID>"
        );
        let assertion = assertion_with("_duplicate-name-id", Some(two_name_ids));
        let result = run(&plugin, &assertion).await;
        assert_eq!(reject_status(&result), 401);
    }

    /// A whitespace-only `NameID` is not an identity.
    #[tokio::test]
    async fn a_blank_name_id_rejects() {
        let (plugin, _bundle) = plugin_and_bundle();
        let assertion = assertion_with("_blank-name-id", Some("<saml:NameID>   </saml:NameID>"));
        let result = run(&plugin, &assertion).await;
        assert_eq!(reject_status(&result), 401);
        assert!(
            reject_body(&result).contains("NameID"),
            "got: {}",
            reject_body(&result)
        );
    }

    /// The positive case: one nonblank `NameID` becomes the request principal.
    #[tokio::test]
    async fn a_valid_name_id_becomes_the_principal() {
        let (plugin, _bundle) = plugin_and_bundle();
        let assertion = assertion_with("_valid-name-id", None);
        let mut ctx = make_ctx_with_soap_body(&wrap_saml_assertion(&assertion));
        let consumer_index = ConsumerIndex::new(&[]);
        assert!(matches!(
            plugin.authenticate(&mut ctx, &consumer_index).await,
            PluginResult::Continue
        ));
        assert_eq!(
            ctx.authenticated_identity.as_deref(),
            Some("alice@example.com")
        );
        assert_eq!(
            ctx.metadata.get("soap_ws_saml_subject").map(String::as_str),
            Some("alice@example.com")
        );
    }

    /// The semantic failure must consume no replay state: the very same
    /// assertion id must still be spendable by a well-formed assertion.
    #[tokio::test]
    async fn a_principal_less_assertion_does_not_burn_the_replay_id() {
        let (plugin, _bundle) = plugin_and_bundle();
        let shared_id = "_shared-assertion-id";

        let rejected = run(&plugin, &assertion_with(shared_id, Some(""))).await;
        assert_eq!(reject_status(&rejected), 401);

        let accepted = run(&plugin, &assertion_with(shared_id, None)).await;
        assert!(
            matches!(accepted, PluginResult::Continue),
            "a rejected principal-less assertion must not claim the id: {accepted:?}"
        );

        // And the id is claimed exactly once by the assertion that was accepted.
        let replayed = run(&plugin, &assertion_with(shared_id, None)).await;
        assert_eq!(reject_status(&replayed), 401);
        assert!(
            reject_body(&replayed).contains("already been used"),
            "got: {}",
            reject_body(&replayed)
        );
    }
}

// ── SAML / WS-Security comment truncation (CVE-2017-11427 class) ────────────
//
// An XML comment inside a signed value splits the DOM's character data into two
// text nodes while exclusive canonicalization — the transform that produces the
// bytes the signature actually digests — drops the comment and emits both runs.
// A reader that returns only the first run therefore acts on a truncated prefix
// of an identity the IdP legitimately signed. These tests pin the fix on every
// element whose value this plugin reads.

/// The premise of the whole class, proved directly against Ferrum's own
/// exclusive c14n: the comment is invisible to the digest, so the IdP signature
/// covers the FULL string. Anything the gateway trusts must agree with this.
#[test]
fn test_saml_comment_is_invisible_to_exclusive_canonicalization() {
    let benign = format!(
        r#"<saml:Assertion xmlns:saml="{ns}" ID="_c14n-benign"><saml:Subject><saml:NameID>admin@evil.example</saml:NameID></saml:Subject></saml:Assertion>"#,
        ns = saml_fixtures::SAML_NS,
    );
    let split = format!(
        r#"<saml:Assertion xmlns:saml="{ns}" ID="_c14n-benign"><saml:Subject><saml:NameID>admin<!--truncate-->@evil.example</saml:NameID></saml:Subject></saml:Assertion>"#,
        ns = saml_fixtures::SAML_NS,
    );

    let benign_c14n = soap_exclusive_canonicalize_element_for_test(&benign, "Assertion", "")
        .expect("benign assertion must canonicalize");
    let split_c14n = soap_exclusive_canonicalize_element_for_test(&split, "Assertion", "")
        .expect("comment-split assertion must canonicalize");

    assert_eq!(
        benign_c14n, split_c14n,
        "exclusive c14n must drop the comment and emit both text runs — that is \
         why the signature keeps verifying"
    );
    assert!(
        benign_c14n.contains("admin@evil.example"),
        "the signed bytes name the full identity: {benign_c14n}"
    );
}

/// The attack itself: a validly-signed assertion whose NameID is split by a
/// comment must never resolve to the truncated prefix.
#[tokio::test]
async fn test_saml_name_id_comment_truncation_rejected() {
    let bundle = saml_fixtures::IdpBundle::new();
    let plugin = SoapWsSecurity::new(&saml_config(&bundle, None)).unwrap();

    let mut builder = saml_fixtures::AssertionBuilder::new(
        "_assertion-comment-nameid",
        "https://idp.example.com/metadata",
        "admin@evil.example",
    );
    // The comment is present when the fixture signs, and c14n drops it, so this
    // assertion carries a genuinely valid IdP signature over
    // `admin@evil.example`.
    builder.name_id_fragment =
        Some("<saml:NameID>admin<!---->@evil.example</saml:NameID>".to_string());
    let assertion = builder.build();

    let body = wrap_saml_assertion(&assertion);
    let mut ctx = make_ctx_with_soap_body(&body);
    let mut headers = soap_headers();
    let result = run_soap_request_policy(&plugin, &mut ctx, &mut headers).await;

    assert!(
        is_reject(&result),
        "a comment-split NameID must not authenticate the truncated prefix: {result:?}"
    );
    assert_eq!(reject_status(&result), 401);
    assert!(
        reject_body(&result).contains("comment"),
        "expected the comment rejection, got: {}",
        reject_body(&result)
    );
    assert_ne!(
        ctx.metadata.get("soap_ws_saml_subject").map(String::as_str),
        Some("admin"),
        "the truncated prefix must never become the request principal"
    );
    assert_ne!(ctx.authenticated_identity.as_deref(), Some("admin"));
}

/// A comment before the value makes `Node::text()` return `None` outright; the
/// rejection must still be the explicit comment refusal, not an "empty NameID"
/// accident that a later refactor could turn back into a truncation.
#[tokio::test]
async fn test_saml_name_id_leading_comment_rejected() {
    let bundle = saml_fixtures::IdpBundle::new();
    let plugin = SoapWsSecurity::new(&saml_config(&bundle, None)).unwrap();

    let mut builder = saml_fixtures::AssertionBuilder::new(
        "_assertion-leading-comment-nameid",
        "https://idp.example.com/metadata",
        "admin@evil.example",
    );
    builder.name_id_fragment =
        Some("<saml:NameID><!---->admin@evil.example</saml:NameID>".to_string());
    let assertion = builder.build();

    let body = wrap_saml_assertion(&assertion);
    let mut ctx = make_ctx_with_soap_body(&body);
    let mut headers = soap_headers();
    let result = run_soap_request_policy(&plugin, &mut ctx, &mut headers).await;

    assert!(is_reject(&result), "got {result:?}");
    assert!(
        reject_body(&result).contains("comment"),
        "expected the comment rejection, got: {}",
        reject_body(&result)
    );
}

/// Several comments, including one that splits the local part, must not be
/// stitched back into a shorter principal either.
#[tokio::test]
async fn test_saml_name_id_multiple_comments_rejected() {
    let bundle = saml_fixtures::IdpBundle::new();
    let plugin = SoapWsSecurity::new(&saml_config(&bundle, None)).unwrap();

    let mut builder = saml_fixtures::AssertionBuilder::new(
        "_assertion-multi-comment-nameid",
        "https://idp.example.com/metadata",
        "admin@evil.example",
    );
    builder.name_id_fragment =
        Some("<saml:NameID>ad<!--a-->min<!--b-->@evil.example</saml:NameID>".to_string());
    let assertion = builder.build();

    let body = wrap_saml_assertion(&assertion);
    let mut ctx = make_ctx_with_soap_body(&body);
    let mut headers = soap_headers();
    let result = run_soap_request_policy(&plugin, &mut ctx, &mut headers).await;

    assert!(is_reject(&result), "got {result:?}");
    assert!(
        reject_body(&result).contains("comment"),
        "expected the comment rejection, got: {}",
        reject_body(&result)
    );
    for truncation in ["ad", "admin", "admin@evil.example"] {
        assert_ne!(
            ctx.metadata.get("soap_ws_saml_subject").map(String::as_str),
            Some(truncation),
            "a rejected assertion must publish no principal"
        );
    }
}

/// The paired control: the very same identity, without the comment, still
/// authenticates and resolves to exactly the string the signature covers.
#[tokio::test]
async fn test_saml_comment_free_name_id_still_accepted() {
    let bundle = saml_fixtures::IdpBundle::new();
    let plugin = SoapWsSecurity::new(&saml_config(&bundle, None)).unwrap();

    let assertion = saml_fixtures::AssertionBuilder::new(
        "_assertion-comment-free-nameid",
        "https://idp.example.com/metadata",
        "admin@evil.example",
    )
    .build();

    let body = wrap_saml_assertion(&assertion);
    let mut ctx = make_ctx_with_soap_body(&body);
    let mut headers = soap_headers();
    let result = run_soap_request_policy(&plugin, &mut ctx, &mut headers).await;

    assert!(
        matches!(result, PluginResult::Continue),
        "the benign assertion must still validate: {result:?}"
    );
    assert_eq!(
        ctx.metadata.get("soap_ws_saml_subject").map(String::as_str),
        Some("admin@evil.example"),
        "the resolved principal must be the string the signature covered"
    );
}

/// A comment that is NOT inside a value element is ordinary markup: c14n drops
/// it and nothing reads it, so the assertion must still validate. This is what
/// keeps the fix from degenerating into "reject every comment".
#[tokio::test]
async fn test_saml_comment_outside_value_elements_still_accepted() {
    let bundle = saml_fixtures::IdpBundle::new();
    let plugin = SoapWsSecurity::new(&saml_config(&bundle, None)).unwrap();

    let mut builder = saml_fixtures::AssertionBuilder::new(
        "_assertion-benign-comment",
        "https://idp.example.com/metadata",
        "alice@example.com",
    );
    builder.name_id_fragment =
        Some("<!--idp--><saml:NameID>alice@example.com</saml:NameID>".to_string());
    let assertion = builder.build();

    let body = wrap_saml_assertion(&assertion);
    let mut ctx = make_ctx_with_soap_body(&body);
    let mut headers = soap_headers();
    let result = run_soap_request_policy(&plugin, &mut ctx, &mut headers).await;

    assert!(
        matches!(result, PluginResult::Continue),
        "a comment between elements is not a truncation: {result:?}"
    );
    assert_eq!(
        ctx.metadata.get("soap_ws_saml_subject").map(String::as_str),
        Some("alice@example.com")
    );
}

/// Issuer trust confusion: the truncated prefix is a trusted issuer, the signed
/// value is not.
#[tokio::test]
async fn test_saml_issuer_comment_truncation_rejected() {
    let bundle = saml_fixtures::IdpBundle::new();
    let plugin = SoapWsSecurity::new(&saml_config(&bundle, None)).unwrap();

    let assertion = saml_fixtures::AssertionBuilder::new(
        "_assertion-comment-issuer",
        "https://idp.example.com/metadata<!---->.evil.example",
        "alice@example.com",
    )
    .build();

    let body = wrap_saml_assertion(&assertion);
    let mut ctx = make_ctx_with_soap_body(&body);
    let mut headers = soap_headers();
    let result = run_soap_request_policy(&plugin, &mut ctx, &mut headers).await;

    assert!(
        is_reject(&result),
        "a comment-split Issuer must not resolve to the trusted prefix: {result:?}"
    );
    assert!(
        reject_body(&result).contains("comment"),
        "expected the comment rejection, got: {}",
        reject_body(&result)
    );
}

/// Audience-binding bypass: the truncated prefix is this service, the signed
/// value names another one.
#[tokio::test]
async fn test_saml_audience_comment_truncation_rejected() {
    let bundle = saml_fixtures::IdpBundle::new();
    let plugin = SoapWsSecurity::new(&saml_config(&bundle, None)).unwrap();

    let mut builder = saml_fixtures::AssertionBuilder::new(
        "_assertion-comment-audience",
        "https://idp.example.com/metadata",
        "alice@example.com",
    );
    builder.audience = Some(format!(
        "{}<!---->.evil.example",
        saml_fixtures::TEST_AUDIENCE
    ));
    let assertion = builder.build();

    let body = wrap_saml_assertion(&assertion);
    let mut ctx = make_ctx_with_soap_body(&body);
    let mut headers = soap_headers();
    let result = run_soap_request_policy(&plugin, &mut ctx, &mut headers).await;

    assert!(
        is_reject(&result),
        "a comment-split Audience must not admit this service on its prefix: {result:?}"
    );
    assert!(
        reject_body(&result).contains("comment"),
        "expected the comment rejection, got: {}",
        reject_body(&result)
    );
}

/// Insert `<!---->` a few characters into the first `open_tag` element's value,
/// so its character data is split rather than merely prefixed.
fn split_element_value_with_comment(xml: &str, open_tag: &str) -> String {
    let open = xml.find(open_tag).expect("fixture must contain the tag");
    let mut out = xml.to_string();
    // Every value this helper is used on is base64 (ASCII), so a fixed byte
    // offset is a char boundary.
    out.insert_str(open + open_tag.len() + 4, "<!---->");
    out
}

/// The signature carriers are read through the same helper, so a comment there
/// is a named refusal instead of a base64/verification accident — there is only
/// ever ONE reading of an element's value in this module.
#[tokio::test]
async fn test_saml_signature_value_comment_rejected() {
    let bundle = saml_fixtures::IdpBundle::new();
    let plugin = SoapWsSecurity::new(&saml_config(&bundle, None)).unwrap();

    let assertion = saml_fixtures::AssertionBuilder::new(
        "_assertion-comment-sigvalue",
        "https://idp.example.com/metadata",
        "alice@example.com",
    )
    .build();
    let assertion = split_element_value_with_comment(&assertion, "<ds:SignatureValue>");

    let body = wrap_saml_assertion(&assertion);
    let mut ctx = make_ctx_with_soap_body(&body);
    let mut headers = soap_headers();
    let result = run_soap_request_policy(&plugin, &mut ctx, &mut headers).await;

    assert!(is_reject(&result), "got {result:?}");
    assert!(
        reject_body(&result).contains("comment"),
        "expected the comment rejection, got: {}",
        reject_body(&result)
    );
}

#[tokio::test]
async fn test_saml_digest_value_comment_rejected() {
    let bundle = saml_fixtures::IdpBundle::new();
    let plugin = SoapWsSecurity::new(&saml_config(&bundle, None)).unwrap();

    let assertion = saml_fixtures::AssertionBuilder::new(
        "_assertion-comment-digestvalue",
        "https://idp.example.com/metadata",
        "alice@example.com",
    )
    .build();
    let assertion = split_element_value_with_comment(&assertion, "<ds:DigestValue>");

    let body = wrap_saml_assertion(&assertion);
    let mut ctx = make_ctx_with_soap_body(&body);
    let mut headers = soap_headers();
    let result = run_soap_request_policy(&plugin, &mut ctx, &mut headers).await;

    assert!(is_reject(&result), "got {result:?}");
    assert!(
        reject_body(&result).contains("comment"),
        "expected the comment rejection, got: {}",
        reject_body(&result)
    );
}

#[tokio::test]
async fn test_saml_x509_certificate_comment_rejected() {
    let bundle = saml_fixtures::IdpBundle::new();
    let plugin = SoapWsSecurity::new(&saml_config(&bundle, None)).unwrap();

    let assertion = saml_fixtures::AssertionBuilder::new(
        "_assertion-comment-x509",
        "https://idp.example.com/metadata",
        "alice@example.com",
    )
    .build();
    let assertion = split_element_value_with_comment(&assertion, "<ds:X509Certificate>");

    let body = wrap_saml_assertion(&assertion);
    let mut ctx = make_ctx_with_soap_body(&body);
    let mut headers = soap_headers();
    let result = run_soap_request_policy(&plugin, &mut ctx, &mut headers).await;

    assert!(is_reject(&result), "got {result:?}");
    assert!(
        reject_body(&result).contains("comment"),
        "expected the comment rejection, got: {}",
        reject_body(&result)
    );
}

/// The same shape on the non-SAML path. Nothing signs a plain UsernameToken,
/// but the gateway/backend identity differential is identical: Ferrum would
/// authenticate `alice` while a backend re-parsing the envelope sees
/// `alice@evil.example`.
#[tokio::test]
async fn test_username_token_username_comment_truncation_rejected() {
    let plugin = SoapWsSecurity::new(&username_token_config()).unwrap();
    let ut = r#"<wsse:UsernameToken>
        <wsse:Username>alice<!---->@evil.example</wsse:Username>
        <wsse:Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText">secret123</wsse:Password>
    </wsse:UsernameToken>"#;
    let body = wrap_soap(ut);
    let mut ctx = make_ctx_with_soap_body(&body);
    let mut headers = soap_headers();
    let result = run_soap_request_policy(&plugin, &mut ctx, &mut headers).await;

    assert!(
        is_reject(&result),
        "a comment-split Username must not authenticate the truncated prefix: {result:?}"
    );
    assert!(
        reject_body(&result).contains("comment"),
        "expected the comment rejection, got: {}",
        reject_body(&result)
    );
    assert_ne!(
        ctx.metadata.get("soap_ws_username").map(String::as_str),
        Some("alice"),
        "the truncated prefix must never become the request principal"
    );
}

#[tokio::test]
async fn test_username_token_password_comment_truncation_rejected() {
    let plugin = SoapWsSecurity::new(&username_token_config()).unwrap();
    let ut = r#"<wsse:UsernameToken>
        <wsse:Username>alice</wsse:Username>
        <wsse:Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText">secret123<!---->trailing</wsse:Password>
    </wsse:UsernameToken>"#;
    let body = wrap_soap(ut);
    let mut ctx = make_ctx_with_soap_body(&body);
    let mut headers = soap_headers();
    let result = run_soap_request_policy(&plugin, &mut ctx, &mut headers).await;

    assert!(is_reject(&result), "got {result:?}");
    assert!(
        reject_body(&result).contains("comment"),
        "expected the comment rejection, got: {}",
        reject_body(&result)
    );
}

/// Control for the non-SAML path: a comment between the token's child elements
/// is ordinary markup and must still validate.
#[tokio::test]
async fn test_username_token_comment_outside_value_elements_still_accepted() {
    let plugin = SoapWsSecurity::new(&username_token_config()).unwrap();
    let ut = r#"<wsse:UsernameToken>
        <!-- issued by the test client -->
        <wsse:Username>alice</wsse:Username>
        <wsse:Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText">secret123</wsse:Password>
    </wsse:UsernameToken>"#;
    let body = wrap_soap(ut);
    let mut ctx = make_ctx_with_soap_body(&body);
    let mut headers = soap_headers();
    let result = run_soap_request_policy(&plugin, &mut ctx, &mut headers).await;

    assert!(
        matches!(result, PluginResult::Continue),
        "a comment between elements is not a truncation: {result:?}"
    );
    assert_eq!(ctx.metadata.get("soap_ws_username").unwrap(), "alice");
}

/// `wsu:Created` feeds the PasswordDigest input and the replay-cache key; a
/// split there must not produce a digest input the client did not present.
#[tokio::test]
async fn test_username_token_created_comment_truncation_rejected() {
    let plugin = SoapWsSecurity::new(&username_token_digest_config()).unwrap();
    let created = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
    let ut = format!(
        r#"<wsse:UsernameToken>
        <wsse:Username>alice</wsse:Username>
        <wsse:Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest">ZGlnZXN0</wsse:Password>
        <wsse:Nonce>bm9uY2UtdmFsdWU=</wsse:Nonce>
        <wsu:Created>{}<!----></wsu:Created>
    </wsse:UsernameToken>"#,
        created
    );
    let body = wrap_soap(&ut);
    let mut ctx = make_ctx_with_soap_body(&body);
    let mut headers = soap_headers();
    let result = run_soap_request_policy(&plugin, &mut ctx, &mut headers).await;

    assert!(is_reject(&result), "got {result:?}");
    assert!(
        reject_body(&result).contains("comment"),
        "expected the comment rejection, got: {}",
        reject_body(&result)
    );
}

/// `wsse:Nonce` is both the digest input and the replay-cache key; a split
/// there must be refused, not silently keyed on the prefix.
#[tokio::test]
async fn test_username_token_nonce_comment_truncation_rejected() {
    let plugin = SoapWsSecurity::new(&username_token_digest_config()).unwrap();
    let created = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
    let ut = format!(
        r#"<wsse:UsernameToken>
        <wsse:Username>alice</wsse:Username>
        <wsse:Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest">ZGlnZXN0</wsse:Password>
        <wsse:Nonce>bm9uY2Ut<!---->dmFsdWU=</wsse:Nonce>
        <wsu:Created>{}</wsu:Created>
    </wsse:UsernameToken>"#,
        created
    );
    let body = wrap_soap(&ut);
    let mut ctx = make_ctx_with_soap_body(&body);
    let mut headers = soap_headers();
    let result = run_soap_request_policy(&plugin, &mut ctx, &mut headers).await;

    assert!(is_reject(&result), "got {result:?}");
    assert!(
        reject_body(&result).contains("comment"),
        "expected the comment rejection, got: {}",
        reject_body(&result)
    );
}

/// `wsu:Timestamp` bounds message freshness; a split `Created` must not be
/// read as a shorter, differently-parsed instant.
#[tokio::test]
async fn test_timestamp_created_comment_truncation_rejected() {
    let plugin = SoapWsSecurity::new(&timestamp_only_config()).unwrap();
    let now = chrono::Utc::now();
    let created = now.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();
    let expires = (now + chrono::Duration::minutes(5))
        .format("%Y-%m-%dT%H:%M:%S%.3fZ")
        .to_string();
    let ts = format!(
        r#"<wsu:Timestamp wsu:Id="TS-1">
        <wsu:Created>{}<!----></wsu:Created>
        <wsu:Expires>{}</wsu:Expires>
      </wsu:Timestamp>"#,
        created, expires
    );
    let body = wrap_soap(&ts);
    let mut ctx = make_ctx_with_soap_body(&body);
    let mut headers = soap_headers();
    let result = run_soap_request_policy(&plugin, &mut ctx, &mut headers).await;

    assert!(is_reject(&result), "got {result:?}");
    assert!(
        reject_body(&result).contains("comment"),
        "expected the comment rejection, got: {}",
        reject_body(&result)
    );
}

// ── Pre-parse XML nesting depth (issue #4565) ──────────────────────────────
//
// `roxmltree`'s tokenizer recurses once per open element
// (`parse_element` -> `parse_content` -> `parse_element`), so `MAX_XML_NODES`
// alone cannot stop a deeply nested envelope from overflowing the worker stack
// *inside* `Document::parse_with_options`. `parse_bounded_xml` therefore
// screens element nesting over the raw bytes first, bounded by the shared
// `XML_MAX_NESTING_DEPTH` (256). `MAX_CANONICALIZATION_DEPTH` remains the
// separate post-parse walk budget.

/// `<soap:Body>` payload nested `levels` deep. The envelope itself contributes
/// two levels (`Envelope` > `Body`) above this.
fn nested_soap_payload(levels: usize) -> String {
    let mut xml = String::with_capacity(levels * 8);
    for _ in 0..levels {
        xml.push_str("<n>");
    }
    xml.push_str("leaf");
    for _ in 0..levels {
        xml.push_str("</n>");
    }
    xml
}

fn soap_envelope_with_body(security_content: &str, body_content: &str) -> String {
    format!(
        r#"<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Header>
    <wsse:Security xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
                   xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
      {security_content}
    </wsse:Security>
  </soap:Header>
  <soap:Body>
    {body_content}
  </soap:Body>
</soap:Envelope>"#
    )
}

#[tokio::test]
async fn soap_envelope_nested_beyond_the_depth_bound_is_rejected_before_parse() {
    let plugin = SoapWsSecurity::new(&timestamp_only_config()).unwrap();
    let envelope = soap_envelope_with_body(&fresh_timestamp(), &nested_soap_payload(300));
    let mut ctx = make_ctx_with_soap_body(&envelope);
    let mut headers = soap_headers_with_content_type("text/xml");

    let result = run_soap_request_policy(&plugin, &mut ctx, &mut headers).await;
    match &result {
        PluginResult::Reject { status_code, .. } => assert_eq!(*status_code, 400),
        other => panic!("expected Reject for a nesting bomb, got {other:?}"),
    }
    assert!(
        reject_body(&result).contains("nesting exceeds the supported depth"),
        "expected the fixed depth rejection, got: {}",
        reject_body(&result)
    );
    // The rejection never echoes envelope bytes.
    assert!(!reject_body(&result).contains("leaf"));
}

#[tokio::test]
async fn soap_envelope_within_the_depth_bound_still_validates() {
    let plugin = SoapWsSecurity::new(&timestamp_only_config()).unwrap();
    // 250 payload levels + `Envelope` + `Body` = 252, inside the 256 bound.
    let envelope = soap_envelope_with_body(&fresh_timestamp(), &nested_soap_payload(250));
    let mut ctx = make_ctx_with_soap_body(&envelope);
    let mut headers = soap_headers_with_content_type("text/xml");

    let result = run_soap_request_policy(&plugin, &mut ctx, &mut headers).await;
    assert!(
        matches!(result, PluginResult::Continue),
        "a 252-level envelope must validate normally, got {result:?}"
    );
}

#[tokio::test]
async fn soap_depth_screen_ignores_tags_inside_comments_and_cdata() {
    let plugin = SoapWsSecurity::new(&timestamp_only_config()).unwrap();
    let mut payload = String::from("<wrapper><!--");
    for _ in 0..600 {
        payload.push_str("<a><b><c>");
    }
    payload.push_str("--><data><![CDATA[");
    for _ in 0..600 {
        payload.push_str("<a><b><c>");
    }
    payload.push_str("]]></data></wrapper>");

    let envelope = soap_envelope_with_body(&fresh_timestamp(), &payload);
    let mut ctx = make_ctx_with_soap_body(&envelope);
    let mut headers = soap_headers_with_content_type("text/xml");

    let result = run_soap_request_policy(&plugin, &mut ctx, &mut headers).await;
    assert!(
        matches!(result, PluginResult::Continue),
        "commented-out and CDATA-quoted tags must not count toward nesting, got {result:?}"
    );
}

#[tokio::test]
async fn soap_depth_screen_does_not_end_a_tag_at_a_quoted_angle_bracket() {
    let plugin = SoapWsSecurity::new(&timestamp_only_config()).unwrap();
    // Each start tag carries an attribute value of `/>`. A scan that is not
    // quote-aware terminates the tag at that `>` and, seeing `/` as the last
    // significant byte, mistakes every element for self-closing — so 300 real
    // levels would measure as depth 1 and sail past the bound. Both `>` and `/`
    // are legal unescaped inside an attribute value, so `roxmltree` accepts the
    // document; only the screen may refuse it.
    let mut payload = String::new();
    for _ in 0..300 {
        payload.push_str(r#"<n note="/>">"#);
    }
    payload.push_str("leaf");
    for _ in 0..300 {
        payload.push_str("</n>");
    }

    let envelope = soap_envelope_with_body(&fresh_timestamp(), &payload);
    let mut ctx = make_ctx_with_soap_body(&envelope);
    let mut headers = soap_headers_with_content_type("text/xml");

    let result = run_soap_request_policy(&plugin, &mut ctx, &mut headers).await;
    match &result {
        PluginResult::Reject { status_code, .. } => assert_eq!(*status_code, 400),
        other => {
            panic!("expected Reject: a quoted `>` must not terminate the start tag, got {other:?}")
        }
    }
    assert!(
        reject_body(&result).contains("nesting exceeds the supported depth"),
        "expected the fixed depth rejection, got: {}",
        reject_body(&result)
    );
}

#[tokio::test]
async fn malformed_soap_returns_fixed_parser_categories() {
    let plugin = SoapWsSecurity::new(&timestamp_only_config()).unwrap();
    for (body, category) in [
        (
            "<private_tag></different_tag>",
            "element tags are not balanced",
        ),
        (
            "<root>&private_entity;</root>",
            "entity reference is undeclared or malformed",
        ),
        (
            "<private_namespace:root/>",
            "namespace declaration is not well-formed",
        ),
    ] {
        let mut ctx = make_ctx_with_soap_body(body);
        let result = run_soap_request_policy(&plugin, &mut ctx, &mut soap_headers()).await;
        assert_eq!(reject_status(&result), 400);
        let error: Value = serde_json::from_str(reject_body(&result)).unwrap();
        assert_eq!(
            error["error"],
            format!("WS-Security: malformed or overly complex SOAP XML: {category}")
        );
    }
}

// ── Scalar reader: the concatenated value is used unchanged (issue #5057) ────
//
// Surrounding whitespace decides only whether an otherwise-required element is
// blank. Returning a trimmed copy handed verification and consumption two
// different byte strings, and it made a configured PasswordText credential with
// significant surrounding spaces impossible to present.

const PASSWORD_TEXT_TYPE_ATTR: &str = concat!(
    "http://docs.oasis-open.org/wss/2004/01/",
    "oasis-200401-wss-username-token-profile-1.0#PasswordText"
);

fn padded_credential_config(username: &str, password: &str) -> serde_json::Value {
    json!({
        "timestamp": { "require": false },
        "username_token": {
            "enabled": true,
            "password_type": "PasswordText",
            "credentials": [{"username": username, "password": password}]
        },
        "reject_missing_security_header": true
    })
}

fn username_token_block(username: &str, password: &str) -> String {
    format!(
        r#"<wsse:UsernameToken>
        <wsse:Username>{}</wsse:Username>
        <wsse:Password Type="{}">{}</wsse:Password>
    </wsse:UsernameToken>"#,
        username, PASSWORD_TEXT_TYPE_ATTR, password
    )
}

#[tokio::test]
async fn test_password_text_with_significant_spaces_authenticates() {
    let config = padded_credential_config("alice", "  spaced secret  ");
    let plugin = SoapWsSecurity::new(&config).unwrap();
    let body = wrap_soap(&username_token_block("alice", "  spaced secret  "));
    let mut ctx = make_ctx_with_soap_body(&body);
    let mut headers = soap_headers();
    let result = run_soap_request_policy(&plugin, &mut ctx, &mut headers).await;
    assert!(
        matches!(result, PluginResult::Continue),
        "an admitted password whose spaces are significant must authenticate: {result:?}"
    );
    assert_eq!(ctx.metadata.get("soap_ws_username").unwrap(), "alice");
}

#[tokio::test]
async fn test_password_text_trimmed_variant_does_not_authenticate() {
    let config = padded_credential_config("alice", "  spaced secret  ");
    let plugin = SoapWsSecurity::new(&config).unwrap();
    let body = wrap_soap(&username_token_block("alice", "spaced secret"));
    let mut ctx = make_ctx_with_soap_body(&body);
    let mut headers = soap_headers();
    let result = run_soap_request_policy(&plugin, &mut ctx, &mut headers).await;
    assert_username_token_invalid_credentials(&result, &["alice"]);
}

#[tokio::test]
async fn test_username_is_matched_including_its_surrounding_spaces() {
    let config = padded_credential_config(" padded-user ", "secret123");
    let plugin = SoapWsSecurity::new(&config).unwrap();

    let exact = wrap_soap(&username_token_block(" padded-user ", "secret123"));
    let mut ctx = make_ctx_with_soap_body(&exact);
    let mut headers = soap_headers();
    let result = run_soap_request_policy(&plugin, &mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue), "got {result:?}");
    let published = ctx.metadata.get("soap_ws_username").map(String::as_str);
    assert_eq!(published, Some(" padded-user "));

    let trimmed = wrap_soap(&username_token_block("padded-user", "secret123"));
    let mut ctx = make_ctx_with_soap_body(&trimmed);
    let result = run_soap_request_policy(&plugin, &mut ctx, &mut headers).await;
    assert_username_token_invalid_credentials(&result, &["padded-user"]);
}

/// `xsd:dateTime` really does collapse surrounding whitespace, so a
/// pretty-printed Timestamp must still parse. This is the control that keeps
/// the untrimmed reader from being applied where the datatype forbids it.
#[tokio::test]
async fn test_timestamp_instants_still_collapse_surrounding_whitespace() {
    let plugin = SoapWsSecurity::new(&timestamp_only_config()).unwrap();
    let now = chrono::Utc::now();
    let created = now.format("%Y-%m-%dT%H:%M:%S%.3fZ");
    let expires = (now + chrono::Duration::minutes(5)).format("%Y-%m-%dT%H:%M:%S%.3fZ");
    let timestamp = format!(
        r#"<wsu:Timestamp wsu:Id="TS-1">
        <wsu:Created>
          {}
        </wsu:Created>
        <wsu:Expires>
          {}
        </wsu:Expires>
      </wsu:Timestamp>"#,
        created, expires
    );
    let body = wrap_soap(&timestamp);
    let mut ctx = make_ctx_with_soap_body(&body);
    let mut headers = soap_headers();
    let result = run_soap_request_policy(&plugin, &mut ctx, &mut headers).await;
    assert!(
        matches!(result, PluginResult::Continue),
        "a whitespace-padded xsd:dateTime is still a valid instant: {result:?}"
    );
}

/// The signed NameID reaches consumer lookup byte for byte. Signature
/// verification covers the character data as written, so a trimmed principal is
/// a value the IdP never asserted.
#[tokio::test]
async fn test_saml_name_id_keeps_its_surrounding_whitespace() {
    let bundle = saml_fixtures::IdpBundle::new();
    let plugin = SoapWsSecurity::new(&saml_config(&bundle, None)).unwrap();

    let mut builder = saml_fixtures::AssertionBuilder::new(
        "_assertion-padded-nameid",
        "https://idp.example.com/metadata",
        "unused",
    );
    let fragment = "<saml:NameID> alice@example.com </saml:NameID>";
    builder.name_id_fragment = Some(fragment.to_string());
    let assertion = builder.build();

    let body = wrap_saml_assertion(&assertion);
    let mut ctx = make_ctx_with_soap_body(&body);
    let mut headers = soap_headers();
    let result = run_soap_request_policy(&plugin, &mut ctx, &mut headers).await;
    assert!(
        matches!(result, PluginResult::Continue),
        "a signed assertion whose NameID carries spaces is still valid: {result:?}"
    );
    assert_eq!(
        ctx.metadata.get("soap_ws_saml_subject").map(String::as_str),
        Some(" alice@example.com "),
        "the principal must be the signed character data, not a trimmed copy"
    );
}

// ── Bounded canonical writer (GHSA-hfpm-3pv7-h3jh) ──────────────────────────
//
// The writer charges the per-message work budget BEFORE each run it appends, so
// a refused canonicalization stops at the ceiling instead of allocating the
// complete over-budget representation and charging for it afterwards. What is
// left of the budget is what makes the two orderings distinguishable.

const C14N_BUDGET_FIXTURE: &str = concat!(
    r#"<root xmlns:a="urn:example:a"><a:child attr="value">"#,
    "text &amp; more text &lt; here",
    r#"</a:child></root>"#
);

fn c14n_with_budget(budget_bytes: usize) -> (Result<String, String>, usize) {
    ferrum_edge::_test_support::soap_exclusive_canonicalize_with_budget_for_test(
        C14N_BUDGET_FIXTURE,
        "root",
        budget_bytes,
    )
}

fn c14n_source_len() -> usize {
    let source_len = ferrum_edge::_test_support::soap_canonicalization_source_len_for_test(
        C14N_BUDGET_FIXTURE,
        "root",
    );
    source_len.expect("fixture has a root element")
}

#[test]
fn canonical_writer_charges_the_budget_as_it_writes() {
    let source_len = c14n_source_len();

    let (outcome, remaining) = c14n_with_budget(4096);
    let canonical = outcome.expect("a well-funded canonicalization succeeds");
    assert!(canonical.contains("&amp;"), "got: {canonical}");
    let output_len = canonical.len();
    assert_eq!(
        remaining,
        4096 - source_len - output_len,
        "a successful canonicalization charges exactly source + output"
    );

    // One byte of output allowance. A writer that charged the finished string
    // would leave that byte untouched; one that charges as it writes spends it
    // on the first append and then stops.
    let (outcome, remaining) = c14n_with_budget(source_len + 1);
    let error = outcome.expect_err("one byte of output allowance is not enough");
    assert!(
        error.contains("canonicalization work budget"),
        "got: {error}"
    );
    assert_eq!(
        remaining, 0,
        "the writer must stop at the ceiling with the output allowance spent, not build the \
         whole over-budget result and charge for it afterwards"
    );
}

#[test]
fn canonical_writer_refuses_an_over_budget_subtree_before_walking_it() {
    let source_len = c14n_source_len();
    let (outcome, remaining) = c14n_with_budget(source_len - 1);
    assert!(outcome.is_err(), "an over-budget subtree is refused");
    assert_eq!(
        remaining,
        source_len - 1,
        "refusing before the walk charges nothing"
    );
}

// ── Credential removal (GHSA-xg9v-wc29-fc29) ────────────────────────────────

fn remove_credential_config() -> serde_json::Value {
    json!({
        "timestamp": { "require": false },
        "content_type": { "allow_mtom": false },
        "username_token": {
            "enabled": true,
            "password_type": "PasswordText",
            "remove_credential": true,
            "credentials": [{"username": "alice", "password": "secret123"}]
        },
        "reject_missing_security_header": true
    })
}

async fn strip_credential(
    plugin: &SoapWsSecurity,
    ctx: &mut RequestContext,
    headers: &HashMap<String, String>,
    body: &[u8],
) -> Option<Vec<u8>> {
    plugin
        .transform_request_body_with_context(ctx, body, Some("text/xml"), headers)
        .await
}

async fn final_body_decision(
    plugin: &SoapWsSecurity,
    ctx: &mut RequestContext,
    headers: &HashMap<String, String>,
    body: &[u8],
) -> PluginResult {
    plugin
        .on_final_request_body_with_context(ctx, headers, body)
        .await
}

#[test]
fn test_remove_credential_requires_an_enabled_password_text_policy() {
    let cases: &[(&str, serde_json::Value, &str)] = &[
        (
            "disabled username_token",
            json!({
                "timestamp": { "require": true },
                "username_token": { "remove_credential": true }
            }),
            "requires",
        ),
        (
            "password digest",
            json!({
                "timestamp": { "require": false },
                "username_token": {
                    "enabled": true,
                    "remove_credential": true,
                    "credentials": [{"username": "alice", "password": "secret123"}]
                },
                "nonce": { "replay_scope": "process" }
            }),
            "PasswordText",
        ),
        (
            "explicit allow_mtom",
            json!({
                "timestamp": { "require": false },
                "content_type": { "allow_mtom": true },
                "username_token": {
                    "enabled": true,
                    "password_type": "PasswordText",
                    "remove_credential": true,
                    "credentials": [{"username": "alice", "password": "secret123"}]
                }
            }),
            "allow_mtom",
        ),
    ];
    for (name, config, fragment) in cases {
        let err = SoapWsSecurity::new(config)
            .err()
            .unwrap_or_else(|| panic!("{name} must be refused at admission"));
        assert!(err.contains(fragment), "{name}: got {err}");
    }
}

#[test]
fn test_remove_credential_is_refused_alongside_a_signature_mechanism() {
    let bundle = saml_fixtures::IdpBundle::new();
    let cert_path = bundle.trusted_cert_path.to_str().unwrap();
    let config = json!({
        "timestamp": { "require": false },
        "content_type": { "allow_mtom": false },
        "username_token": {
            "enabled": true,
            "password_type": "PasswordText",
            "remove_credential": true,
            "credentials": [{"username": "alice", "password": "secret123"}]
        },
        "saml": {
            "enabled": true,
            "trusted_issuers": ["https://idp.example.com/metadata"],
            "trusted_signing_certs": [cert_path],
            "audience": saml_fixtures::TEST_AUDIENCE,
            "recipient": saml_fixtures::TEST_RECIPIENT
        },
        "nonce": { "replay_scope": "process" }
    });
    let err = SoapWsSecurity::new(&config)
        .err()
        .expect("removal alongside SAML must be refused");
    assert!(err.contains("remove_credential"), "got {err}");
}

#[test]
fn test_credential_removal_is_opt_in() {
    let default_policy = SoapWsSecurity::new(&username_token_config()).unwrap();
    assert!(
        !default_policy.modifies_request_body(),
        "an ordinary SOAP policy must not declare a request-body transform"
    );
    let removing = SoapWsSecurity::new(&remove_credential_config()).unwrap();
    assert!(removing.modifies_request_body());
}

#[tokio::test]
async fn test_remove_credential_strips_a_security_header_that_holds_only_the_token() {
    let plugin = SoapWsSecurity::new(&remove_credential_config()).unwrap();
    let body = wrap_soap(&username_token_block("alice", "secret123"));
    let mut ctx = make_ctx_with_soap_body(&body);
    let mut headers = soap_headers();

    let result = run_soap_request_policy(&plugin, &mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue), "got {result:?}");
    assert_eq!(ctx.metadata.get("soap_ws_username").unwrap(), "alice");

    let removal = strip_credential(&plugin, &mut ctx, &headers, body.as_bytes()).await;
    let transformed = removal.expect("credential removal must rewrite the body");
    let sanitized = String::from_utf8(transformed.clone()).expect("sanitized body is UTF-8");
    assert!(!sanitized.contains("secret123"), "got: {sanitized}");
    assert!(!sanitized.contains("UsernameToken"), "got: {sanitized}");
    assert!(
        !sanitized.contains("wsse:Security"),
        "a Security header holding only the credential is removed whole: {sanitized}"
    );
    assert!(
        sanitized.contains("<GetPrice") && sanitized.contains("Widget"),
        "the application body must survive: {sanitized}"
    );

    // The final-body proof binds the sanitized representation: it admits the
    // rewritten bytes and still refuses the ones that were validated.
    let accepted = final_body_decision(&plugin, &mut ctx, &headers, &transformed).await;
    assert!(
        matches!(accepted, PluginResult::Continue),
        "got {accepted:?}"
    );
    let refused = final_body_decision(&plugin, &mut ctx, &headers, body.as_bytes()).await;
    assert_eq!(reject_status(&refused), 500);
}

#[tokio::test]
async fn test_remove_credential_keeps_a_security_header_that_also_carries_a_timestamp() {
    let mut config = remove_credential_config();
    config["timestamp"]["require"] = json!(true);
    let plugin = SoapWsSecurity::new(&config).unwrap();

    let credential = username_token_block("alice", "secret123");
    let body = wrap_soap(&format!("{}{}", fresh_timestamp(), credential));
    let mut ctx = make_ctx_with_soap_body(&body);
    let mut headers = soap_headers();

    let result = run_soap_request_policy(&plugin, &mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue), "got {result:?}");

    let removal = strip_credential(&plugin, &mut ctx, &headers, body.as_bytes()).await;
    let transformed = removal.expect("credential removal must rewrite the body");
    let sanitized = String::from_utf8(transformed).expect("sanitized body is UTF-8");
    assert!(!sanitized.contains("secret123"), "got: {sanitized}");
    assert!(!sanitized.contains("UsernameToken"), "got: {sanitized}");
    assert!(
        sanitized.contains("wsse:Security") && sanitized.contains("wsu:Timestamp"),
        "a header carrying more than the credential keeps its other content: {sanitized}"
    );
}

#[tokio::test]
async fn test_remove_credential_refuses_a_signed_envelope() {
    let plugin = SoapWsSecurity::new(&remove_credential_config()).unwrap();
    let signature = concat!(
        r#"<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">"#,
        "<ds:SignatureValue>AAAA</ds:SignatureValue></ds:Signature>"
    );
    let credential = username_token_block("alice", "secret123");
    let body = wrap_soap(&format!("{}{}", credential, signature));
    let mut ctx = make_ctx_with_soap_body(&body);
    let mut headers = soap_headers();
    let result = run_soap_request_policy(&plugin, &mut ctx, &mut headers).await;
    assert_eq!(reject_status(&result), 400);
    assert!(
        reject_body(&result).contains("signed SOAP envelope"),
        "expected the signed-envelope rejection, got: {}",
        reject_body(&result)
    );
    let strip_key = "soap_ws_security.credential_strip_range";
    assert!(
        !ctx.metadata.contains_key(strip_key),
        "no removal is recorded"
    );
}

#[tokio::test]
async fn test_remove_credential_refuses_a_representation_it_cannot_splice() {
    let plugin = SoapWsSecurity::new(&remove_credential_config()).unwrap();
    let body = wrap_soap(&username_token_block("alice", "secret123"));
    let content_type = "application/soap+xml; charset=utf-16";
    let mut ctx = make_ctx_with_soap_bytes(encode_utf16_le(&body), content_type);
    let mut headers = soap_headers_with_content_type(content_type);
    let result = run_soap_request_policy(&plugin, &mut ctx, &mut headers).await;
    assert_eq!(
        reject_status(&result),
        415,
        "a transcoded body cannot be spliced and must not be forwarded with the credential"
    );
    assert!(
        reject_body(&result).contains("cannot have its UsernameToken removed"),
        "got: {}",
        reject_body(&result)
    );
}

#[tokio::test]
async fn test_credential_removal_declines_when_something_else_rewrote_the_body_first() {
    let plugin = SoapWsSecurity::new(&remove_credential_config()).unwrap();
    let body = wrap_soap(&username_token_block("alice", "secret123"));
    let mut ctx = make_ctx_with_soap_body(&body);
    let mut headers = soap_headers();
    let result = run_soap_request_policy(&plugin, &mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue), "got {result:?}");

    let mutated = body.replace("Widget", "Sprocket");
    let declined = strip_credential(&plugin, &mut ctx, &headers, mutated.as_bytes()).await;
    assert!(
        declined.is_none(),
        "the splice must never be applied to bytes this policy did not itself accept"
    );
    let refused = final_body_decision(&plugin, &mut ctx, &headers, mutated.as_bytes()).await;
    assert_eq!(
        reject_status(&refused),
        500,
        "an inapplicable removal fails closed rather than forwarding the credential"
    );
}

/// Rotating a SAML IdP signing certificate does not require a restart
/// (issue #5054): the trust list is read when the plugin generation is
/// constructed, and a configuration reload constructs a new generation.
#[tokio::test]
async fn test_saml_signing_cert_rotation_takes_effect_in_a_new_generation() {
    let rotated_pem = saml_fixtures::UNTRUSTED_IDP_CERT_PEM;
    let before = saml_fixtures::IdpBundle::new();
    let after = saml_fixtures::IdpBundle::with_trusted_cert(rotated_pem);
    let generation_before = SoapWsSecurity::new(&saml_config(&before, None)).unwrap();
    let generation_after = SoapWsSecurity::new(&saml_config(&after, None)).unwrap();

    let assertion = |id: &str, rotated_signer: bool| {
        let issuer = "https://idp.example.com/metadata";
        let mut builder = saml_fixtures::AssertionBuilder::new(id, issuer, "alice@example.com");
        builder.sign_with_untrusted_key = rotated_signer;
        wrap_saml_assertion(&builder.build())
    };

    let accepted = run_saml_generation(&generation_before, &assertion("_rot-1", false)).await;
    assert!(
        matches!(accepted, PluginResult::Continue),
        "got {accepted:?}"
    );
    let refused = run_saml_generation(&generation_before, &assertion("_rot-2", true)).await;
    assert_eq!(reject_status(&refused), 401);

    // Same process, same fixtures — only the constructed generation changed.
    let accepted = run_saml_generation(&generation_after, &assertion("_rot-3", true)).await;
    assert!(
        matches!(accepted, PluginResult::Continue),
        "got {accepted:?}"
    );
    let refused = run_saml_generation(&generation_after, &assertion("_rot-4", false)).await;
    assert_eq!(
        reject_status(&refused),
        401,
        "the retired signer must be refused by the generation the reload installed"
    );
}

async fn run_saml_generation(plugin: &SoapWsSecurity, body: &str) -> PluginResult {
    let mut ctx = make_ctx_with_soap_body(body);
    let mut headers = soap_headers();
    run_soap_request_policy(plugin, &mut ctx, &mut headers).await
}

// ── OpenAPI component / constructor admission parity (issue #5053) ───────────
//
// Generated tooling and schema-based preflight validate against the component,
// so a schema that admits configurations the constructor refuses reports
// success for policies that cannot be installed. This compares the two
// verdicts directly instead of asserting on description strings.

#[test]
fn openapi_soap_ws_security_component_matches_constructor_admission() {
    let spec: Value =
        serde_yaml::from_str(include_str!("../../../openapi.yaml")).expect("openapi.yaml parses");
    let schema = json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$ref": "#/components/schemas/SoapWsSecurityConfig",
        "components": spec["components"].clone()
    });
    let validator = jsonschema::draft202012::options()
        .build(&schema)
        .expect("SoapWsSecurityConfig schema compiles");

    let bundle = saml_fixtures::IdpBundle::new();
    let cert = bundle.trusted_cert_path.to_str().unwrap();
    let issuer = "https://idp.example.com/metadata";
    let audience = saml_fixtures::TEST_AUDIENCE;
    let recipient = saml_fixtures::TEST_RECIPIENT;
    let holder_of_key = "urn:oasis:names:tc:SAML:2.0:cm:holder-of-key";
    let bearer = "urn:oasis:names:tc:SAML:2.0:cm:bearer";

    let cases: Vec<(&str, serde_json::Value)> = vec![
        ("empty object", json!({})),
        ("timestamp only", json!({"timestamp": {"require": true}})),
        (
            "no active feature",
            json!({"timestamp": {"require": false}}),
        ),
        (
            "username_token without credentials",
            json!({"username_token": {"enabled": true, "password_type": "PasswordText"}}),
        ),
        (
            "username_token with an empty credential list",
            json!({"username_token": {
                "enabled": true,
                "password_type": "PasswordText",
                "credentials": []
            }}),
        ),
        (
            "username_token with a blank username",
            json!({"username_token": {
                "enabled": true,
                "password_type": "PasswordText",
                "credentials": [{"username": "   ", "password": "secret123"}]
            }}),
        ),
        (
            "username_token password with significant spaces",
            json!({"username_token": {
                "enabled": true,
                "password_type": "PasswordText",
                "credentials": [{"username": "alice", "password": "  secret123  "}]
            }}),
        ),
        (
            "password digest with a declared replay scope",
            json!({
                "username_token": {
                    "enabled": true,
                    "credentials": [{"username": "alice", "password": "secret123"}]
                },
                "nonce": {"replay_scope": "process"}
            }),
        ),
        (
            "empty arrays on inactive features",
            json!({
                "timestamp": {"require": true},
                "username_token": {"credentials": []},
                "x509_signature": {"trusted_certs": []},
                "saml": {"trusted_issuers": []}
            }),
        ),
        (
            "x509 without trust material",
            json!({"x509_signature": {"enabled": true}}),
        ),
        (
            "x509 with an empty trust list",
            json!({"x509_signature": {"enabled": true, "trusted_certs": []}}),
        ),
        (
            "x509 with a blank trust entry",
            json!({"x509_signature": {"enabled": true, "trusted_certs": ["   "]}}),
        ),
        (
            "x509 with trust material",
            json!({"x509_signature": {"enabled": true, "trusted_certs": [cert]}}),
        ),
        (
            "x509 alongside an explicit allow_mtom",
            json!({
                "content_type": {"allow_mtom": true},
                "x509_signature": {"enabled": true, "trusted_certs": [cert]}
            }),
        ),
        (
            "x509 alongside allow_mtom false",
            json!({
                "content_type": {"allow_mtom": false},
                "x509_signature": {"enabled": true, "trusted_certs": [cert]}
            }),
        ),
        (
            "saml fully bound",
            json!({
                "saml": {
                    "enabled": true,
                    "trusted_issuers": [issuer],
                    "trusted_signing_certs": [cert],
                    "audience": audience,
                    "recipient": recipient
                },
                "nonce": {"replay_scope": "process"}
            }),
        ),
        (
            "saml with an empty issuer list",
            json!({
                "saml": {
                    "enabled": true,
                    "trusted_issuers": [],
                    "trusted_signing_certs": [cert],
                    "audience": audience,
                    "recipient": recipient
                },
                "nonce": {"replay_scope": "process"}
            }),
        ),
        (
            "saml with an empty signing-cert list",
            json!({
                "saml": {
                    "enabled": true,
                    "trusted_issuers": [issuer],
                    "trusted_signing_certs": [],
                    "audience": audience,
                    "recipient": recipient
                },
                "nonce": {"replay_scope": "process"}
            }),
        ),
        (
            "saml with a blank audience",
            json!({
                "saml": {
                    "enabled": true,
                    "trusted_issuers": [issuer],
                    "trusted_signing_certs": [cert],
                    "audience": "   ",
                    "recipient": recipient
                },
                "nonce": {"replay_scope": "process"}
            }),
        ),
        (
            "unsupported subject confirmation method",
            json!({"saml": {"allowed_subject_confirmation_methods": [holder_of_key]}}),
        ),
        (
            "bearer subject confirmation method",
            json!({
                "timestamp": {"require": true},
                "saml": {"allowed_subject_confirmation_methods": [bearer]}
            }),
        ),
        (
            "credential removal on an unsigned PasswordText policy",
            json!({
                "content_type": {"allow_mtom": false},
                "username_token": {
                    "enabled": true,
                    "password_type": "PasswordText",
                    "remove_credential": true,
                    "credentials": [{"username": "alice", "password": "secret123"}]
                }
            }),
        ),
        (
            "credential removal without an enabled username_token",
            json!({
                "timestamp": {"require": true},
                "username_token": {"remove_credential": true}
            }),
        ),
        (
            "credential removal on a PasswordDigest policy",
            json!({
                "username_token": {
                    "enabled": true,
                    "remove_credential": true,
                    "credentials": [{"username": "alice", "password": "secret123"}]
                },
                "nonce": {"replay_scope": "process"}
            }),
        ),
        (
            "credential removal alongside x509",
            json!({
                "content_type": {"allow_mtom": false},
                "username_token": {
                    "enabled": true,
                    "password_type": "PasswordText",
                    "remove_credential": true,
                    "credentials": [{"username": "alice", "password": "secret123"}]
                },
                "x509_signature": {"enabled": true, "trusted_certs": [cert]}
            }),
        ),
        (
            "credential removal alongside an explicit allow_mtom",
            json!({
                "content_type": {"allow_mtom": true},
                "username_token": {
                    "enabled": true,
                    "password_type": "PasswordText",
                    "remove_credential": true,
                    "credentials": [{"username": "alice", "password": "secret123"}]
                }
            }),
        ),
    ];

    for (name, config) in cases {
        let runtime = SoapWsSecurity::new(&config);
        let runtime_admits = runtime.is_ok();
        let schema_admits = validator.validate(&config).is_ok();
        assert_eq!(
            schema_admits,
            runtime_admits,
            "{name}: schema admits={schema_admits}, constructor admits={runtime_admits} \
             (constructor said {:?})",
            runtime.err()
        );
    }
}
