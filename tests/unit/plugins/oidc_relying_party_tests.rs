use ferrum_edge::_test_support::{
    oidc_open_session_cookie_for_test, oidc_sealed_due_refresh_session_cookie_for_test,
    oidc_sealed_refresh_session_cookie_for_test, oidc_sealed_session_cookie_for_test,
    oidc_session_state_from_set_cookie_for_test,
};
use ferrum_edge::ConsumerIndex;
use ferrum_edge::config::types::AuthMode;
use ferrum_edge::plugins::validate_plugin_config;
use ferrum_edge::plugins::{
    Plugin, PluginHttpClient, PluginResult, RequestContext, key_auth::KeyAuth,
    oidc_relying_party::OidcRelyingParty, priority,
};
use ferrum_edge::proxy::run_authentication_phase;
use serde_json::json;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use url::Url;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

use super::jwks_auth_support::{build_rsa_jwks_from_pem, create_rs256_token};
use super::plugin_utils::{assert_continue, assert_reject, create_test_consumer};

const AUTHORITY_MISMATCH_ERROR: &str =
    r#"{"error":"OIDC callback host does not match request host"}"#;
const INVALID_AUTHORITY_ERROR: &str = r#"{"error":"OIDC missing or malformed request authority"}"#;

fn base_config() -> serde_json::Value {
    json!({
        "providers": [{
            "issuer": "https://issuer.example.com",
            "authorization_endpoint": "https://issuer.example.com/authorize",
            "token_endpoint": "https://issuer.example.com/token",
            "jwks_uri": "https://issuer.example.com/jwks",
            "client_id": "ferrum-gateway",
            "client_auth": {"method": "client_secret_basic", "client_secret": "secret"},
            "scopes": ["openid", "profile"],
            "redirect_uri": "https://app.example.com/oauth/callback",
            "callback_path": "/oauth/callback",
            "logout_path": "/oauth/logout"
        }],
        "session": {
            "store": "cookie",
            "cookie_name": "ferrum_session",
            "encryption_secret": "01234567890123456789012345678901"
        },
        "behavior": {
            "trusted_redirect_hosts": ["app.example.com"],
            "post_login_redirect_param": "rd"
        }
    })
}

fn html_ctx() -> RequestContext {
    let mut ctx = RequestContext::new("127.0.0.1".into(), "GET".into(), "/app".into());
    ctx.request_is_secure = true;
    ctx.headers
        .insert("accept".to_string(), "text/html".to_string());
    ctx.headers
        .insert("host".to_string(), "app.example.com".to_string());
    ctx.metadata
        .insert("ferrum.frontend_scheme".to_string(), "https".to_string());
    ctx
}

#[derive(Clone)]
struct BrowserChallenge {
    state: String,
    nonce: String,
    cookie: String,
}

async fn issue_browser_challenge(plugin: &OidcRelyingParty) -> BrowserChallenge {
    issue_browser_challenge_for_context(plugin, html_ctx()).await
}

async fn issue_browser_challenge_for_context(
    plugin: &OidcRelyingParty,
    mut ctx: RequestContext,
) -> BrowserChallenge {
    let PluginResult::Reject {
        status_code,
        headers,
        ..
    } = plugin
        .authenticate(&mut ctx, &ConsumerIndex::new(&[]))
        .await
    else {
        panic!("expected browser challenge");
    };
    assert_eq!(status_code, 302);
    let location = Url::parse(headers.get("location").expect("authorization URL"))
        .expect("authorization URL parses");
    let state = location
        .query_pairs()
        .find_map(|(key, value)| (key == "state").then(|| value.into_owned()))
        .expect("state parameter");
    let nonce = location
        .query_pairs()
        .find_map(|(key, value)| (key == "nonce").then(|| value.into_owned()))
        .expect("nonce parameter");
    let cookie = headers
        .get("set-cookie")
        .cloned()
        .expect("correlation cookie");

    BrowserChallenge {
        state,
        nonce,
        cookie,
    }
}

async fn assert_browser_challenge_fails_closed(
    plugin: &OidcRelyingParty,
    mut ctx: RequestContext,
    expected_body: &str,
) {
    let PluginResult::Reject {
        status_code,
        body,
        headers,
    } = plugin
        .authenticate(&mut ctx, &ConsumerIndex::new(&[]))
        .await
    else {
        panic!("expected browser challenge rejection");
    };
    assert_eq!(status_code, 400);
    assert_eq!(body, expected_body);
    assert!(!headers.contains_key("location"));
    assert!(!headers.contains_key("set-cookie"));
}

fn cookie_attribute<'a>(cookie: &'a str, expected_name: &str) -> Option<Option<&'a str>> {
    cookie.split(';').skip(1).find_map(|attribute| {
        let attribute = attribute.trim();
        let (name, value) = match attribute.split_once('=') {
            Some((name, value)) => (name.trim(), Some(value.trim())),
            None => (attribute, None),
        };
        name.eq_ignore_ascii_case(expected_name).then_some(value)
    })
}

fn cookie_pair(cookie: &str) -> &str {
    cookie
        .split(';')
        .next()
        .expect("cookie contains a name/value pair")
}

fn cookie_name(cookie: &str) -> &str {
    cookie_pair(cookie)
        .split_once('=')
        .map(|(name, _)| name)
        .expect("cookie has a name")
}

fn assert_host_only_correlation_cookie(cookie: &str, expected_max_age: &str) {
    assert_eq!(cookie_attribute(cookie, "domain"), None, "{cookie}");
    assert_eq!(
        cookie_attribute(cookie, "path"),
        Some(Some("/oauth/callback")),
        "{cookie}"
    );
    assert_eq!(
        cookie_attribute(cookie, "samesite"),
        Some(Some("Lax")),
        "{cookie}"
    );
    assert_eq!(
        cookie_attribute(cookie, "max-age"),
        Some(Some(expected_max_age)),
        "{cookie}"
    );
    assert_eq!(cookie_attribute(cookie, "secure"), Some(None), "{cookie}");
    assert_eq!(cookie_attribute(cookie, "httponly"), Some(None), "{cookie}");
}

fn assert_same_correlation_scope(created: &str, cleared: &str) {
    for attribute in ["domain", "path", "samesite", "secure", "httponly"] {
        assert_eq!(
            cookie_attribute(created, attribute),
            cookie_attribute(cleared, attribute),
            "correlation cookie {attribute} scope changed between creation and clearing"
        );
    }
}

fn callback_context(challenge: &BrowserChallenge) -> RequestContext {
    let mut ctx = RequestContext::new("127.0.0.1".into(), "GET".into(), "/oauth/callback".into());
    ctx.request_is_secure = true;
    ctx.headers.insert(
        "cookie".to_string(),
        cookie_pair(&challenge.cookie).to_string(),
    );
    ctx.query_params
        .insert("state".to_string(), challenge.state.clone());
    ctx
}

fn refresh_config(token_endpoint: &str) -> serde_json::Value {
    let mut config = base_config();
    config["providers"][0]["token_endpoint"] = json!(token_endpoint);
    config["providers"][0]["consumer_identity_claim"] = json!("email");
    config
}

fn session_ctx(set_cookie: &str) -> RequestContext {
    let mut ctx = RequestContext::new("127.0.0.1".into(), "GET".into(), "/app".into());
    ctx.request_is_secure = true;
    ctx.headers.insert(
        "cookie".to_string(),
        set_cookie
            .split(';')
            .next()
            .expect("session cookie pair")
            .to_string(),
    );
    ctx
}

async fn rolling_cookie(plugin: &OidcRelyingParty, ctx: &mut RequestContext) -> Option<String> {
    let mut response_headers = HashMap::new();
    assert_continue(plugin.after_proxy(ctx, 200, &mut response_headers).await);
    response_headers.remove("set-cookie")
}

fn refresh_rejection_plugin(token_endpoint: &str) -> OidcRelyingParty {
    let mut config = base_config();
    config["providers"][0]["token_endpoint"] = json!(token_endpoint);
    config["providers"][0]["required_scopes"] = json!(["admin"]);
    config["providers"][0]["consumer_identity_claim"] = json!("email");
    config["providers"][0]["claim_headers"] = json!({"role": "X-Untrusted-Role"});
    OidcRelyingParty::new(&config, PluginHttpClient::default()).unwrap()
}

fn ctx_with_session_cookie(set_cookie: &str) -> RequestContext {
    let cookie_pair = set_cookie
        .split('\n')
        .find(|cookie| cookie.trim_start().starts_with("ferrum_session="))
        .expect("OIDC session cookie")
        .split(';')
        .next()
        .expect("OIDC session cookie pair")
        .to_string();
    let mut ctx = RequestContext::new("127.0.0.1".into(), "GET".into(), "/app".into());
    ctx.request_is_secure = true;
    ctx.headers.insert("cookie".to_string(), cookie_pair);
    ctx
}

#[tokio::test]
async fn new_accepts_minimal_cookie_store_config() {
    let plugin = OidcRelyingParty::new(&base_config(), PluginHttpClient::default()).unwrap();
    assert_eq!(plugin.name(), "oidc_relying_party");
    assert_eq!(plugin.priority(), priority::OIDC_RELYING_PARTY);
}

#[tokio::test]
async fn principal_less_refresh_due_session_does_not_refresh_or_slide() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "new-access-token",
            "refresh_token": "rotated-refresh-token",
            "token_type": "Bearer",
            "expires_in": 3600
        })))
        .mount(&server)
        .await;
    let plugin = OidcRelyingParty::new(
        &refresh_config(&format!("{}/token", server.uri())),
        PluginHttpClient::default(),
    )
    .expect("valid refresh config");
    let now = chrono::Utc::now().timestamp();
    let cookie = oidc_sealed_refresh_session_cookie_for_test(
        &plugin,
        json!({"sub": "subject-only", "exp": now + 3600}),
        Some("refresh-token".to_string()),
        true,
        true,
    )
    .expect("session seals");
    let mut ctx = session_ctx(&cookie);

    assert_continue(
        plugin
            .authenticate(&mut ctx, &ConsumerIndex::new(&[]))
            .await,
    );
    assert!(ctx.authenticated_identity.is_none());
    assert!(rolling_cookie(&plugin, &mut ctx).await.is_none());
    assert_eq!(server.received_requests().await.expect("requests").len(), 0);
}

#[tokio::test]
async fn earlier_single_mode_principal_prevents_later_oidc_refresh_and_slide() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&server)
        .await;
    let oidc = Arc::new(
        OidcRelyingParty::new(
            &refresh_config(&format!("{}/token", server.uri())),
            PluginHttpClient::default(),
        )
        .expect("valid refresh config"),
    );
    let key_auth = Arc::new(KeyAuth::new(&json!({})).expect("valid key auth config"));
    let now = chrono::Utc::now().timestamp();
    let cookie = oidc_sealed_refresh_session_cookie_for_test(
        &oidc,
        json!({
            "sub": "oidc-subject",
            "email": "oidc@example.test",
            "exp": now - 120
        }),
        Some("refresh-token".to_string()),
        true,
        true,
    )
    .expect("session seals");
    let mut ctx = session_ctx(&cookie);
    ctx.headers
        .insert("x-api-key".to_string(), "test-api-key".to_string());
    let key_auth_plugin: Arc<dyn Plugin> = key_auth.clone();
    let oidc_plugin: Arc<dyn Plugin> = oidc.clone();

    assert!(
        run_authentication_phase(
            AuthMode::Single,
            &[key_auth_plugin, oidc_plugin],
            &mut ctx,
            &ConsumerIndex::new(&[create_test_consumer()]),
        )
        .await
        .is_none()
    );
    assert_eq!(ctx.auth_method, Some("key_auth"));
    let mut upstream_headers = ctx.headers.clone();
    assert_continue(key_auth.before_proxy(&mut ctx, &mut upstream_headers).await);
    assert_continue(oidc.before_proxy(&mut ctx, &mut upstream_headers).await);
    assert!(!upstream_headers.contains_key("x-api-key"));
    assert!(rolling_cookie(&oidc, &mut ctx).await.is_none());
    assert_eq!(server.received_requests().await.expect("requests").len(), 0);
}

#[tokio::test]
async fn accepted_oidc_refresh_commits_rotated_token_once() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "new-access-token",
            "refresh_token": "rotated-refresh-token",
            "token_type": "Bearer",
            "expires_in": 3600
        })))
        .mount(&server)
        .await;
    let plugin = OidcRelyingParty::new(
        &refresh_config(&format!("{}/token", server.uri())),
        PluginHttpClient::default(),
    )
    .expect("valid refresh config");
    let now = chrono::Utc::now().timestamp();
    let cookie = oidc_sealed_refresh_session_cookie_for_test(
        &plugin,
        json!({
            "sub": "oidc-subject",
            "email": "accepted@example.test",
            "exp": now + 3600
        }),
        Some("original-refresh-token".to_string()),
        true,
        false,
    )
    .expect("session seals");
    let mut ctx = session_ctx(&cookie);

    assert_continue(
        plugin
            .authenticate(&mut ctx, &ConsumerIndex::new(&[]))
            .await,
    );
    let rolled = rolling_cookie(&plugin, &mut ctx)
        .await
        .expect("accepted refresh must emit its rolling cookie");
    let payload =
        oidc_open_session_cookie_for_test(&plugin, &rolled).expect("rolling cookie opens");
    assert_eq!(payload["refresh_token_b64"], json!("rotated-refresh-token"));
    assert_eq!(payload["access_token_b64"], json!("new-access-token"));

    let mut repeated = session_ctx(&rolled);
    assert_continue(
        plugin
            .authenticate(&mut repeated, &ConsumerIndex::new(&[]))
            .await,
    );
    assert_eq!(server.received_requests().await.expect("requests").len(), 1);
}

#[tokio::test]
async fn accepted_refresh_failure_commits_backoff_and_avoids_retry_storm() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({
            "error": "temporarily_unavailable"
        })))
        .mount(&server)
        .await;
    let plugin = OidcRelyingParty::new(
        &refresh_config(&format!("{}/token", server.uri())),
        PluginHttpClient::default(),
    )
    .expect("valid refresh config");
    let now = chrono::Utc::now().timestamp();
    let cookie = oidc_sealed_refresh_session_cookie_for_test(
        &plugin,
        json!({
            "sub": "oidc-subject",
            "email": "accepted@example.test",
            "exp": now + 3600
        }),
        Some("refresh-token".to_string()),
        true,
        false,
    )
    .expect("session seals");
    let mut ctx = session_ctx(&cookie);

    assert_continue(
        plugin
            .authenticate(&mut ctx, &ConsumerIndex::new(&[]))
            .await,
    );
    let backed_off = rolling_cookie(&plugin, &mut ctx)
        .await
        .expect("refresh failure must emit its backoff cookie");
    let payload =
        oidc_open_session_cookie_for_test(&plugin, &backed_off).expect("backoff cookie opens");
    assert!(
        payload["refresh_after_unix"]
            .as_i64()
            .is_some_and(|next| next > now)
    );

    let mut repeated = session_ctx(&backed_off);
    assert_continue(
        plugin
            .authenticate(&mut repeated, &ConsumerIndex::new(&[]))
            .await,
    );
    assert_eq!(server.received_requests().await.expect("requests").len(), 1);
}

#[tokio::test]
async fn oidc_success_commits_claim_headers_and_rolling_cookie_together() {
    let mut config = base_config();
    config["providers"][0]["consumer_identity_claim"] = json!("email");
    config["providers"][0]["claim_headers"] = json!({"role": "X-Trusted-Role"});
    let plugin = OidcRelyingParty::new(&config, PluginHttpClient::default()).unwrap();
    let now = chrono::Utc::now().timestamp();
    let set_cookie = oidc_sealed_session_cookie_for_test(
        &plugin,
        json!({
            "sub": "oidc-subject",
            "email": "external@example.test",
            "role": "operator",
            "exp": now + 3600
        }),
        true,
    )
    .unwrap();
    let mut ctx = RequestContext::new("127.0.0.1".into(), "GET".into(), "/app".into());
    ctx.headers.insert(
        "cookie".to_string(),
        set_cookie.split(';').next().unwrap().to_string(),
    );

    assert_continue(
        plugin
            .authenticate(&mut ctx, &ConsumerIndex::new(&[]))
            .await,
    );
    assert_eq!(
        ctx.authenticated_identity.as_deref(),
        Some("external@example.test")
    );
    assert_eq!(ctx.auth_method, Some("oidc_relying_party"));

    let mut request_headers = HashMap::new();
    assert_continue(plugin.before_proxy(&mut ctx, &mut request_headers).await);
    assert_eq!(
        request_headers.get("x-trusted-role").map(String::as_str),
        Some("operator")
    );
    let mut response_headers = HashMap::new();
    assert_continue(
        plugin
            .after_proxy(&mut ctx, 200, &mut response_headers)
            .await,
    );
    assert!(response_headers.contains_key("set-cookie"));
}

#[tokio::test]
async fn oidc_single_auth_scope_rejection_returns_rotated_refresh_cookie() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "new-access-token",
            "token_type": "Bearer",
            "refresh_token": "rotated-refresh-token",
            "expires_in": 3600
        })))
        .expect(1)
        .mount(&server)
        .await;
    let plugin = Arc::new(refresh_rejection_plugin(&format!("{}/token", server.uri())));
    let now = chrono::Utc::now().timestamp();
    let cookie = oidc_sealed_due_refresh_session_cookie_for_test(
        &plugin,
        json!({
            "sub": "oidc-subject",
            "email": "rejected@example.test",
            "scope": "viewer",
            "exp": now + 3600
        }),
        "original-refresh-token",
    )
    .unwrap();
    let mut ctx = ctx_with_session_cookie(&cookie);

    let plugin_for_phase: Arc<dyn Plugin> = plugin.clone();
    let (status_code, _, headers) = run_authentication_phase(
        AuthMode::Single,
        &[plugin_for_phase],
        &mut ctx,
        &ConsumerIndex::new(&[]),
    )
    .await
    .expect("scope-rejected OIDC session must reject");
    assert_eq!(status_code, 403);
    assert!(
        ctx.metadata
            .keys()
            .all(|key| !key.contains("rejection_set_cookie"))
    );
    let mut set_cookies = headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("set-cookie"));
    let set_cookie = set_cookies
        .next()
        .map(|(_, value)| value)
        .expect("rotated session must be returned on terminal rejection");
    assert!(set_cookies.next().is_none());
    assert!(!set_cookie.contains('\n'));
    let state = oidc_session_state_from_set_cookie_for_test(&plugin, set_cookie)
        .expect("rotated session cookie must open");
    assert_eq!(state.access_token, "new-access-token");
    assert_eq!(
        state.refresh_token.as_deref(),
        Some("rotated-refresh-token")
    );
    assert!(state.refresh_after_unix > now);
}

#[tokio::test]
async fn oidc_scope_rejection_persists_refresh_failure_backoff() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({"error": "invalid_grant"})))
        .expect(1)
        .mount(&server)
        .await;
    let plugin = refresh_rejection_plugin(&format!("{}/token", server.uri()));
    let now = chrono::Utc::now().timestamp();
    let cookie = oidc_sealed_due_refresh_session_cookie_for_test(
        &plugin,
        json!({
            "sub": "oidc-subject",
            "email": "rejected@example.test",
            "scope": "viewer",
            "exp": now + 3600
        }),
        "original-refresh-token",
    )
    .unwrap();
    let mut first_ctx = ctx_with_session_cookie(&cookie);

    let PluginResult::Reject {
        status_code,
        headers,
        ..
    } = plugin
        .authenticate(&mut first_ctx, &ConsumerIndex::new(&[]))
        .await
    else {
        panic!("scope-rejected OIDC session must reject");
    };
    assert_eq!(status_code, 403);
    let set_cookie = headers
        .get("set-cookie")
        .expect("refresh backoff must be returned on terminal rejection");
    let state = oidc_session_state_from_set_cookie_for_test(&plugin, set_cookie)
        .expect("backoff session cookie must open");
    assert_eq!(state.access_token, "test-access-token");
    assert_eq!(
        state.refresh_token.as_deref(),
        Some("original-refresh-token")
    );
    assert!(state.refresh_after_unix >= now + 20);

    let mut second_ctx = ctx_with_session_cookie(set_cookie);
    let PluginResult::Reject {
        status_code,
        headers,
        ..
    } = plugin
        .authenticate(&mut second_ctx, &ConsumerIndex::new(&[]))
        .await
    else {
        panic!("scope-rejected OIDC session must reject");
    };
    assert_eq!(status_code, 403);
    assert!(
        !headers.contains_key("set-cookie"),
        "a backed-off session must not be re-sealed again immediately"
    );
    assert_eq!(
        server.received_requests().await.unwrap().len(),
        1,
        "the persisted backoff must suppress an immediate second refresh"
    );
}

#[tokio::test]
async fn oidc_multi_auth_preserves_rotated_cookie_when_later_credential_rejects() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "new-access-token",
            "token_type": "Bearer",
            "refresh_token": "rotated-refresh-token",
            "expires_in": 3600
        })))
        .expect(1)
        .mount(&server)
        .await;
    let mut config = base_config();
    config["providers"][0]["token_endpoint"] = json!(format!("{}/token", server.uri()));
    config["providers"][0]["required_roles"] = json!(["admin"]);
    config["providers"][0]["consumer_identity_claim"] = json!("email");
    config["providers"][0]["claim_headers"] = json!({"roles": "X-Untrusted-Roles"});
    let oidc = Arc::new(OidcRelyingParty::new(&config, PluginHttpClient::default()).unwrap());
    let key_auth: Arc<dyn Plugin> =
        Arc::new(KeyAuth::new(&json!({"key_location": "header:X-API-Key"})).unwrap());
    let consumers = [create_test_consumer()];
    let consumer_index = ConsumerIndex::new(&consumers);
    let now = chrono::Utc::now().timestamp();
    let cookie = oidc_sealed_due_refresh_session_cookie_for_test(
        &oidc,
        json!({
            "sub": "oidc-subject",
            "email": "rejected@example.test",
            "roles": ["viewer"],
            "exp": now + 3600
        }),
        "original-refresh-token",
    )
    .unwrap();
    let mut ctx = ctx_with_session_cookie(&cookie);
    ctx.headers
        .insert("x-api-key".to_string(), "invalid-api-key".to_string());
    let oidc_plugin: Arc<dyn Plugin> = oidc.clone();

    let (status_code, body, mut response_headers) = run_authentication_phase(
        AuthMode::Multi,
        &[oidc_plugin, key_auth],
        &mut ctx,
        &consumer_index,
    )
    .await
    .expect("later invalid API key must keep the request rejected");
    assert_eq!(
        status_code, 401,
        "the later client rejection must still win"
    );
    assert_eq!(&body[..], br#"{"error":"Invalid API key"}"#);
    assert!(ctx.identified_consumer.is_none());
    assert!(ctx.authenticated_identity.is_none());
    assert!(ctx.authenticated_identity_header.is_none());
    assert!(ctx.auth_method.is_none());
    assert!(
        ctx.metadata
            .keys()
            .all(|key| !key.contains("rejection_set_cookie"))
    );

    let mut request_headers = HashMap::new();
    assert_continue(oidc.before_proxy(&mut ctx, &mut request_headers).await);
    assert!(
        !request_headers.contains_key("x-untrusted-roles"),
        "the rejected OIDC attempt must not publish claim headers"
    );

    let set_cookie = response_headers
        .iter()
        .find_map(|(name, value)| {
            name.eq_ignore_ascii_case("set-cookie")
                .then_some(value.clone())
        })
        .expect("the earlier rotated session must survive the later rejection");
    assert!(!set_cookie.contains('\n'));
    let state = oidc_session_state_from_set_cookie_for_test(&oidc, &set_cookie)
        .expect("rotated session cookie must open");
    assert_eq!(state.access_token, "new-access-token");
    assert_eq!(
        state.refresh_token.as_deref(),
        Some("rotated-refresh-token")
    );

    assert_continue(
        oidc.after_proxy(&mut ctx, status_code, &mut response_headers)
            .await,
    );
    assert_eq!(
        response_headers
            .keys()
            .filter(|name| name.eq_ignore_ascii_case("set-cookie"))
            .count(),
        1,
        "reject finalization must emit exactly one session cookie"
    );
    assert_eq!(
        response_headers
            .iter()
            .find_map(|(name, value)| { name.eq_ignore_ascii_case("set-cookie").then_some(value) }),
        Some(&set_cookie)
    );
    assert_eq!(server.received_requests().await.unwrap().len(), 1);
}

#[tokio::test]
async fn oidc_multi_auth_preserves_distinct_rejected_session_cookies() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/first-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "first-access-token",
            "token_type": "Bearer",
            "refresh_token": "first-rotated-refresh-token",
            "expires_in": 3600
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/second-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "second-access-token",
            "token_type": "Bearer",
            "refresh_token": "second-rotated-refresh-token",
            "expires_in": 3600
        })))
        .expect(1)
        .mount(&server)
        .await;

    let rejection_plugin = |cookie_name: &str, token_path: &str| {
        let mut config = base_config();
        config["providers"][0]["token_endpoint"] = json!(format!("{}{token_path}", server.uri()));
        config["providers"][0]["required_scopes"] = json!(["admin"]);
        config["providers"][0]["consumer_identity_claim"] = json!("email");
        config["session"]["cookie_name"] = json!(cookie_name);
        OidcRelyingParty::new(&config, PluginHttpClient::default()).unwrap()
    };
    let first = Arc::new(rejection_plugin("first_session", "/first-token"));
    let second = Arc::new(rejection_plugin("second_session", "/second-token"));
    let now = chrono::Utc::now().timestamp();
    let claims = json!({
        "sub": "oidc-subject",
        "email": "rejected@example.test",
        "scope": "viewer",
        "exp": now + 3600
    });
    let first_cookie = oidc_sealed_due_refresh_session_cookie_for_test(
        &first,
        claims.clone(),
        "first-original-refresh-token",
    )
    .unwrap();
    let second_cookie = oidc_sealed_due_refresh_session_cookie_for_test(
        &second,
        claims,
        "second-original-refresh-token",
    )
    .unwrap();
    let first_pair = first_cookie.split(';').next().expect("first cookie pair");
    let second_pair = second_cookie.split(';').next().expect("second cookie pair");
    let mut ctx = RequestContext::new("127.0.0.1".into(), "GET".into(), "/app".into());
    ctx.request_is_secure = true;
    ctx.headers
        .insert("cookie".to_string(), format!("{first_pair}; {second_pair}"));
    let first_plugin: Arc<dyn Plugin> = first.clone();
    let second_plugin: Arc<dyn Plugin> = second.clone();

    let (status_code, _, headers) = run_authentication_phase(
        AuthMode::Multi,
        &[first_plugin, second_plugin],
        &mut ctx,
        &ConsumerIndex::new(&[]),
    )
    .await
    .expect("both scope-rejected sessions must reject");
    assert_eq!(status_code, 403);
    let mut set_cookies = headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("set-cookie"));
    let set_cookie = set_cookies
        .next()
        .map(|(_, value)| value)
        .expect("both rejected session cookies must reach the client");
    assert!(set_cookies.next().is_none());
    let cookies: Vec<&str> = set_cookie.split('\n').collect();
    assert_eq!(cookies.len(), 2);
    assert!(cookies[0].starts_with("second_session="));
    assert!(cookies[1].starts_with("first_session="));
    assert_eq!(
        cookies
            .iter()
            .filter(|cookie| cookie.starts_with("first_session="))
            .count(),
        1
    );
    assert_eq!(
        cookies
            .iter()
            .filter(|cookie| cookie.starts_with("second_session="))
            .count(),
        1
    );
    let first_state = oidc_session_state_from_set_cookie_for_test(&first, set_cookie)
        .expect("first rejected session cookie must open with its owner");
    assert_eq!(first_state.access_token, "first-access-token");
    assert_eq!(
        first_state.refresh_token.as_deref(),
        Some("first-rotated-refresh-token")
    );
    let second_state = oidc_session_state_from_set_cookie_for_test(&second, set_cookie)
        .expect("second rejected session cookie must open with its owner");
    assert_eq!(second_state.access_token, "second-access-token");
    assert_eq!(
        second_state.refresh_token.as_deref(),
        Some("second-rotated-refresh-token")
    );
    assert_eq!(server.received_requests().await.unwrap().len(), 2);
}

#[tokio::test]
async fn oidc_multi_auth_uses_later_same_name_rejected_session_cookie() {
    let server = MockServer::start().await;
    let response_number = Arc::new(AtomicUsize::new(0));
    let response_number_for_mock = Arc::clone(&response_number);
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(move |_: &Request| {
            let response_number = response_number_for_mock.fetch_add(1, Ordering::SeqCst);
            let (access_token, refresh_token) = if response_number == 0 {
                ("first-access-token", "first-rotated-refresh-token")
            } else {
                ("second-access-token", "second-rotated-refresh-token")
            };
            ResponseTemplate::new(200).set_body_json(json!({
                "access_token": access_token,
                "token_type": "Bearer",
                "refresh_token": refresh_token,
                "expires_in": 3600
            }))
        })
        .expect(2)
        .mount(&server)
        .await;

    let mut config = base_config();
    config["providers"][0]["token_endpoint"] = json!(format!("{}/token", server.uri()));
    config["providers"][0]["required_scopes"] = json!(["admin"]);
    config["providers"][0]["consumer_identity_claim"] = json!("email");
    config["session"]["cookie_name"] = json!("shared_session");
    let first = Arc::new(
        OidcRelyingParty::new(&config, PluginHttpClient::default())
            .expect("first OIDC config must be valid"),
    );
    let second = Arc::new(
        OidcRelyingParty::new(&config, PluginHttpClient::default())
            .expect("second OIDC config must be valid"),
    );
    let now = chrono::Utc::now().timestamp();
    let cookie = oidc_sealed_due_refresh_session_cookie_for_test(
        &first,
        json!({
            "sub": "oidc-subject",
            "email": "rejected@example.test",
            "scope": "viewer",
            "exp": now + 3600
        }),
        "original-refresh-token",
    )
    .unwrap();
    let cookie_pair = cookie.split(';').next().expect("session cookie pair");
    let mut ctx = RequestContext::new("127.0.0.1".into(), "GET".into(), "/app".into());
    ctx.request_is_secure = true;
    ctx.headers
        .insert("cookie".to_string(), cookie_pair.to_string());
    let first_plugin: Arc<dyn Plugin> = first;
    let second_plugin: Arc<dyn Plugin> = second.clone();

    let (status_code, _, headers) = run_authentication_phase(
        AuthMode::Multi,
        &[first_plugin, second_plugin],
        &mut ctx,
        &ConsumerIndex::new(&[]),
    )
    .await
    .expect("both scope-rejected sessions must reject");
    assert_eq!(status_code, 403);
    let mut set_cookies = headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("set-cookie"));
    let set_cookie = set_cookies
        .next()
        .map(|(_, value)| value)
        .expect("the later rejected session cookie must reach the client");
    assert!(set_cookies.next().is_none());
    assert!(!set_cookie.contains('\n'));
    assert!(set_cookie.starts_with("shared_session="));
    let state = oidc_session_state_from_set_cookie_for_test(&second, set_cookie)
        .expect("the later rejected session cookie must remain readable");
    assert_eq!(state.access_token, "second-access-token");
    assert_eq!(
        state.refresh_token.as_deref(),
        Some("second-rotated-refresh-token")
    );
    assert_eq!(response_number.load(Ordering::SeqCst), 2);
    assert_eq!(server.received_requests().await.unwrap().len(), 2);
}

#[tokio::test]
async fn oidc_multi_auth_preserves_selected_rejection_cookie() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "new-access-token",
            "token_type": "Bearer",
            "refresh_token": "rotated-refresh-token",
            "expires_in": 3600
        })))
        .expect(1)
        .mount(&server)
        .await;

    let mut first_config = base_config();
    first_config["providers"][0]["token_endpoint"] = json!(format!("{}/token", server.uri()));
    first_config["providers"][0]["required_scopes"] = json!(["admin"]);
    first_config["providers"][0]["consumer_identity_claim"] = json!("email");
    // The selected correlation cookie starts with `ferrum_`; the shorter
    // requester cookie name proves conflict checks use the complete name.
    first_config["session"]["cookie_name"] = json!("ferrum");
    let first =
        Arc::new(OidcRelyingParty::new(&first_config, PluginHttpClient::default()).unwrap());
    let mut second_config = base_config();
    second_config["session"]["cookie_name"] = json!("second_session");
    let second =
        Arc::new(OidcRelyingParty::new(&second_config, PluginHttpClient::default()).unwrap());
    let now = chrono::Utc::now().timestamp();
    let first_cookie = oidc_sealed_due_refresh_session_cookie_for_test(
        &first,
        json!({
            "sub": "oidc-subject",
            "email": "rejected@example.test",
            "scope": "viewer",
            "exp": now + 3600
        }),
        "original-refresh-token",
    )
    .unwrap();
    let first_pair = first_cookie.split(';').next().expect("session cookie pair");
    let mut ctx = html_ctx();
    ctx.headers
        .insert("cookie".to_string(), first_pair.to_string());
    let first_plugin: Arc<dyn Plugin> = first.clone();
    let second_plugin: Arc<dyn Plugin> = second.clone();

    let (status_code, _, mut headers) = run_authentication_phase(
        AuthMode::Multi,
        &[first_plugin, second_plugin],
        &mut ctx,
        &ConsumerIndex::new(&[]),
    )
    .await
    .expect("the later browser challenge must reject");
    assert_eq!(status_code, 302);
    assert!(
        headers
            .get("location")
            .is_some_and(|location| location.starts_with("https://issuer.example.com/authorize"))
    );
    let set_cookie = headers
        .iter()
        .find_map(|(name, value)| {
            name.eq_ignore_ascii_case("set-cookie")
                .then_some(value.clone())
        })
        .expect("both response-owned cookies must reach the client");
    let cookies: Vec<&str> = set_cookie.split('\n').collect();
    assert_eq!(cookies.len(), 2);
    assert!(cookies[0].contains("Path=/oauth/callback"));
    assert!(cookies[1].starts_with("ferrum="));
    assert_eq!(
        cookies
            .iter()
            .filter(|cookie| cookie.starts_with("ferrum="))
            .count(),
        1
    );
    let state = oidc_session_state_from_set_cookie_for_test(&first, &set_cookie)
        .expect("rotated requester session cookie must remain readable");
    assert_eq!(state.access_token, "new-access-token");
    assert_eq!(
        state.refresh_token.as_deref(),
        Some("rotated-refresh-token")
    );
    assert!(
        ctx.metadata
            .keys()
            .all(|key| !key.contains("rejection_set_cookie"))
    );

    assert_continue(first.after_proxy(&mut ctx, status_code, &mut headers).await);
    assert_continue(
        second
            .after_proxy(&mut ctx, status_code, &mut headers)
            .await,
    );
    assert_eq!(
        headers
            .iter()
            .find_map(|(name, value)| { name.eq_ignore_ascii_case("set-cookie").then_some(value) })
            .map(|value| value.split('\n').count()),
        Some(2),
        "reject finalization must not duplicate either cookie"
    );
    assert_eq!(server.received_requests().await.unwrap().len(), 1);
}

#[tokio::test]
async fn oidc_multi_auth_keeps_later_clear_for_shared_session_cookie() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "new-access-token",
            "token_type": "Bearer",
            "refresh_token": "rotated-refresh-token",
            "expires_in": 3600
        })))
        .expect(1)
        .mount(&server)
        .await;

    let mut first_config = base_config();
    first_config["providers"][0]["token_endpoint"] = json!(format!("{}/token", server.uri()));
    first_config["providers"][0]["required_scopes"] = json!(["admin"]);
    first_config["providers"][0]["consumer_identity_claim"] = json!("email");
    first_config["session"]["cookie_name"] = json!("ferrum");
    let first =
        Arc::new(OidcRelyingParty::new(&first_config, PluginHttpClient::default()).unwrap());
    let mut second_config = base_config();
    second_config["session"]["cookie_name"] = json!("ferrum");
    let second =
        Arc::new(OidcRelyingParty::new(&second_config, PluginHttpClient::default()).unwrap());
    let now = chrono::Utc::now().timestamp();
    let first_cookie = oidc_sealed_due_refresh_session_cookie_for_test(
        &first,
        json!({
            "sub": "oidc-subject",
            "email": "rejected@example.test",
            "scope": "viewer",
            "exp": now + 3600
        }),
        "original-refresh-token",
    )
    .unwrap();
    let first_pair = first_cookie.split(';').next().expect("session cookie pair");
    let mut ctx = html_ctx();
    ctx.headers
        .insert("cookie".to_string(), first_pair.to_string());
    let first_plugin: Arc<dyn Plugin> = first.clone();
    let second_plugin: Arc<dyn Plugin> = second;

    let (status_code, _, headers) = run_authentication_phase(
        AuthMode::Multi,
        &[first_plugin, second_plugin],
        &mut ctx,
        &ConsumerIndex::new(&[]),
    )
    .await
    .expect("the later browser challenge must reject");
    assert_eq!(status_code, 302);
    assert!(
        headers
            .get("location")
            .is_some_and(|location| location.starts_with("https://issuer.example.com/authorize"))
    );
    let set_cookie = headers
        .iter()
        .find_map(|(name, value)| {
            name.eq_ignore_ascii_case("set-cookie")
                .then_some(value.as_str())
        })
        .expect("the selected challenge cookies must reach the client");
    let cookies: Vec<&str> = set_cookie.split('\n').collect();
    assert_eq!(cookies.len(), 2);
    assert!(cookies[0].starts_with("ferrum_oidc_state_"));
    assert!(cookies[0].contains("Path=/oauth/callback"));
    assert_eq!(
        cookies[1],
        "ferrum=; Max-Age=0; Path=/; SameSite=lax; Secure; HttpOnly"
    );
    assert!(oidc_session_state_from_set_cookie_for_test(&first, set_cookie).is_none());
    assert!(
        ctx.metadata
            .keys()
            .all(|key| !key.contains("rejection_set_cookie"))
    );
    assert_eq!(server.received_requests().await.unwrap().len(), 1);
}

#[tokio::test]
async fn oidc_multi_auth_preserves_refresh_backoff_when_later_credential_rejects() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({"error": "invalid_grant"})))
        .expect(1)
        .mount(&server)
        .await;
    let oidc = Arc::new(refresh_rejection_plugin(&format!("{}/token", server.uri())));
    let oidc_plugin: Arc<dyn Plugin> = oidc.clone();
    let key_auth: Arc<dyn Plugin> =
        Arc::new(KeyAuth::new(&json!({"key_location": "header:X-API-Key"})).unwrap());
    let auth_plugins = [oidc_plugin, key_auth];
    let consumers = [create_test_consumer()];
    let consumer_index = ConsumerIndex::new(&consumers);
    let now = chrono::Utc::now().timestamp();
    let cookie = oidc_sealed_due_refresh_session_cookie_for_test(
        &oidc,
        json!({
            "sub": "oidc-subject",
            "email": "rejected@example.test",
            "role": "viewer",
            "scope": "viewer",
            "exp": now + 3600
        }),
        "original-refresh-token",
    )
    .unwrap();
    let mut first_ctx = ctx_with_session_cookie(&cookie);
    first_ctx
        .headers
        .insert("x-api-key".to_string(), "invalid-api-key".to_string());

    let (status_code, _, headers) = run_authentication_phase(
        AuthMode::Multi,
        &auth_plugins,
        &mut first_ctx,
        &consumer_index,
    )
    .await
    .expect("later invalid API key must keep the request rejected");
    assert_eq!(status_code, 401);
    let set_cookie = headers
        .iter()
        .find_map(|(name, value)| {
            name.eq_ignore_ascii_case("set-cookie")
                .then_some(value.as_str())
        })
        .expect("refresh backoff must survive the later rejection");
    let state = oidc_session_state_from_set_cookie_for_test(&oidc, set_cookie)
        .expect("backoff session cookie must open");
    assert_eq!(state.access_token, "test-access-token");
    assert_eq!(
        state.refresh_token.as_deref(),
        Some("original-refresh-token")
    );
    assert!(state.refresh_after_unix >= now + 20);

    let mut second_ctx = ctx_with_session_cookie(set_cookie);
    second_ctx
        .headers
        .insert("x-api-key".to_string(), "invalid-api-key".to_string());
    let (status_code, _, headers) = run_authentication_phase(
        AuthMode::Multi,
        &auth_plugins,
        &mut second_ctx,
        &consumer_index,
    )
    .await
    .expect("backed-off session and invalid API key must reject");
    assert_eq!(status_code, 401);
    assert!(
        headers
            .keys()
            .all(|name| !name.eq_ignore_ascii_case("set-cookie")),
        "a no-refresh attempt must not fabricate a response cookie"
    );
    assert_eq!(
        server.received_requests().await.unwrap().len(),
        1,
        "the persisted backoff must suppress an immediate second refresh"
    );
}

#[tokio::test]
async fn oidc_multi_auth_discards_scope_rejection_refresh_cookie_on_later_success() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "new-access-token",
            "token_type": "Bearer",
            "refresh_token": "rotated-refresh-token",
            "expires_in": 3600
        })))
        .expect(1)
        .mount(&server)
        .await;
    let oidc = Arc::new(refresh_rejection_plugin(&format!("{}/token", server.uri())));
    let key_auth: Arc<dyn Plugin> =
        Arc::new(KeyAuth::new(&json!({"key_location": "header:X-API-Key"})).unwrap());
    let consumers = [create_test_consumer()];
    let consumer_index = ConsumerIndex::new(&consumers);
    let now = chrono::Utc::now().timestamp();
    let cookie = oidc_sealed_due_refresh_session_cookie_for_test(
        &oidc,
        json!({
            "sub": "oidc-subject",
            "email": "rejected@example.test",
            "role": "attacker",
            "scope": "viewer",
            "exp": now + 3600
        }),
        "original-refresh-token",
    )
    .unwrap();
    let mut ctx = ctx_with_session_cookie(&cookie);
    ctx.headers
        .insert("x-api-key".to_string(), "test-api-key".to_string());
    let oidc_plugin: Arc<dyn Plugin> = oidc.clone();

    let rejection = run_authentication_phase(
        AuthMode::Multi,
        &[oidc_plugin, key_auth],
        &mut ctx,
        &consumer_index,
    )
    .await;
    assert!(rejection.is_none(), "later key_auth must authenticate");
    assert_eq!(ctx.auth_method, Some("key_auth"));
    assert_eq!(
        ctx.identified_consumer
            .as_ref()
            .map(|consumer| consumer.username.as_str()),
        Some("testuser")
    );
    assert!(ctx.authenticated_identity.is_none());
    assert!(ctx.authenticated_identity_header.is_none());
    assert!(
        ctx.metadata
            .keys()
            .all(|key| !key.contains("rejection_set_cookie"))
    );

    let mut request_headers = HashMap::new();
    assert_continue(oidc.before_proxy(&mut ctx, &mut request_headers).await);
    assert!(
        !request_headers.contains_key("x-untrusted-role"),
        "the rejected OIDC attempt must not publish claim headers"
    );
    let mut response_headers = HashMap::new();
    assert_continue(oidc.after_proxy(&mut ctx, 200, &mut response_headers).await);
    assert!(
        !response_headers.contains_key("set-cookie"),
        "a successful later credential must discard the rejected OIDC cookie"
    );
    assert_eq!(server.received_requests().await.unwrap().len(), 1);
}

#[tokio::test]
async fn oidc_multi_auth_discards_uncommitted_attempt_metadata() {
    let mut config = base_config();
    config["providers"][0]["consumer_identity_claim"] = json!("email");
    config["providers"][0]["claim_headers"] = json!({"role": "X-Untrusted-Role"});
    config["providers"][0]["required_scopes"] = json!(["admin"]);
    let oidc = Arc::new(OidcRelyingParty::new(&config, PluginHttpClient::default()).unwrap());
    let key_auth: Arc<dyn Plugin> =
        Arc::new(KeyAuth::new(&json!({"key_location": "header:X-API-Key"})).unwrap());
    let consumers = [create_test_consumer()];
    let consumer_index = ConsumerIndex::new(&consumers);
    let now = chrono::Utc::now().timestamp();
    let attempted_cookies = [
        oidc_sealed_session_cookie_for_test(
            &oidc,
            json!({
                "sub": "oidc-subject",
                "email": "   ",
                "role": "attacker",
                "scope": "admin",
                "exp": now + 3600
            }),
            true,
        )
        .unwrap(),
        oidc_sealed_session_cookie_for_test(
            &oidc,
            json!({
                "sub": "oidc-subject",
                "role": "attacker",
                "scope": "admin",
                "exp": now + 3600
            }),
            true,
        )
        .unwrap(),
        oidc_sealed_session_cookie_for_test(
            &oidc,
            json!({
                "sub": "oidc-subject",
                "email": "rejected@example.test",
                "role": "attacker",
                "scope": "viewer",
                "exp": now + 3600
            }),
            true,
        )
        .unwrap(),
        "ferrum_session=invalid-session".to_string(),
    ];

    for attempted_cookie in attempted_cookies {
        let mut ctx = RequestContext::new("127.0.0.1".into(), "GET".into(), "/app".into());
        ctx.headers.insert(
            "cookie".to_string(),
            attempted_cookie.split(';').next().unwrap().to_string(),
        );
        ctx.headers
            .insert("x-api-key".to_string(), "test-api-key".to_string());
        let oidc_plugin: Arc<dyn Plugin> = oidc.clone();

        let rejection = run_authentication_phase(
            AuthMode::Multi,
            &[oidc_plugin, Arc::clone(&key_auth)],
            &mut ctx,
            &consumer_index,
        )
        .await;
        assert!(rejection.is_none(), "later key_auth must authenticate");
        assert_eq!(ctx.auth_method, Some("key_auth"));

        let mut request_headers = HashMap::new();
        assert_continue(oidc.before_proxy(&mut ctx, &mut request_headers).await);
        assert!(!request_headers.contains_key("x-untrusted-role"));
        let mut response_headers = HashMap::new();
        assert_continue(oidc.after_proxy(&mut ctx, 200, &mut response_headers).await);
        assert!(
            !response_headers.contains_key("set-cookie"),
            "an uncommitted OIDC attempt must not publish rolling session state"
        );
    }
}

#[test]
fn new_rejects_missing_openid_scope() {
    let mut config = base_config();
    config["providers"][0]["scopes"] = json!(["profile"]);
    assert!(OidcRelyingParty::new(&config, PluginHttpClient::default()).is_err());
}

#[test]
fn new_rejects_same_site_none_without_secure() {
    let mut config = base_config();
    config["session"]["same_site"] = json!("none");
    config["session"]["secure"] = json!(false);
    assert!(OidcRelyingParty::new(&config, PluginHttpClient::default()).is_err());
}

#[test]
fn new_rejects_invalid_state_admission_limits() {
    for (field, value) in [
        ("state_ttl_secs", json!(0)),
        ("state_ttl_secs", json!(3601)),
        ("state_cache_max_entries", json!(0)),
        ("state_cache_max_entries_per_source", json!(0)),
    ] {
        let mut config = base_config();
        config["behavior"][field] = value;
        assert!(
            OidcRelyingParty::new(&config, PluginHttpClient::default()).is_err(),
            "{field} must reject invalid value"
        );
    }

    let mut config = base_config();
    config["behavior"]["state_cache_max_entries"] = json!(4);
    config["behavior"]["state_cache_max_entries_per_source"] = json!(5);
    assert!(OidcRelyingParty::new(&config, PluginHttpClient::default()).is_err());
}

#[test]
fn new_rejects_redis_session_store_until_implemented() {
    let mut config = base_config();
    config["session"]["store"] = json!("redis");
    config["session"]["redis_url"] = json!("redis://127.0.0.1:6379/0");
    assert!(OidcRelyingParty::new(&config, PluginHttpClient::default()).is_err());
}

#[test]
fn new_rejects_none_client_auth_for_remote_token_endpoint() {
    let mut config = base_config();
    config["providers"][0]["client_auth"] = json!({"method": "none"});
    let error = match OidcRelyingParty::new(&config, PluginHttpClient::default()) {
        Ok(_) => panic!("remote none client auth should be rejected"),
        Err(error) => error,
    };
    assert!(error.contains("client_auth.method='none'"));
}

#[test]
fn new_rejects_trailing_dot_redirect_host_for_host_only_cookie_scope() {
    let mut config = base_config();
    config["providers"][0]["redirect_uri"] = json!("https://app.example.com./oauth/callback");
    let error = OidcRelyingParty::new(&config, PluginHttpClient::default())
        .err()
        .expect("trailing-dot callback host must be rejected");
    assert!(error.contains("valid cookie host"));
}

#[tokio::test]
async fn new_accepts_uppercase_same_site_from_schema() {
    let mut config = base_config();
    config["session"]["same_site"] = json!("Lax");
    assert!(OidcRelyingParty::new(&config, PluginHttpClient::default()).is_ok());
}

#[tokio::test]
async fn unauthenticated_html_get_returns_302() {
    let plugin = OidcRelyingParty::new(&base_config(), PluginHttpClient::default()).unwrap();
    let mut ctx = html_ctx();
    let result = plugin
        .authenticate(&mut ctx, &ConsumerIndex::new(&[]))
        .await;
    match result {
        ferrum_edge::plugins::PluginResult::Reject {
            status_code,
            headers,
            ..
        } => {
            assert_eq!(status_code, 302);
            assert!(headers.get("location").is_some_and(|value| {
                value.starts_with("https://issuer.example.com/authorize")
            }));
        }
        _ => panic!("expected redirect"),
    }
}

#[tokio::test]
async fn browser_challenge_accepts_same_host_with_normalized_names_ips_and_ports() {
    for (redirect_uri, request_host) in [
        (
            "https://app.example.com/oauth/callback",
            "APP.EXAMPLE.COM:8443",
        ),
        (
            "https://app.example.com:443/oauth/callback",
            "app.example.com",
        ),
        (
            "https://[2001:db8::1]:443/oauth/callback",
            "[2001:0db8:0:0:0:0:0:1]:8443",
        ),
    ] {
        let mut config = base_config();
        config["providers"][0]["redirect_uri"] = json!(redirect_uri);
        let plugin = OidcRelyingParty::new(&config, PluginHttpClient::default()).unwrap();
        let mut ctx = html_ctx();
        ctx.headers
            .insert("host".to_string(), request_host.to_string());

        let challenge = issue_browser_challenge_for_context(&plugin, ctx).await;
        assert_host_only_correlation_cookie(&challenge.cookie, "600");
    }
}

#[tokio::test]
async fn loopback_http_challenge_remains_available_on_the_same_host() {
    for (redirect_uri, request_host) in [
        ("http://localhost:3000/oauth/callback", "LOCALHOST:5173"),
        ("http://127.0.0.1:3000/oauth/callback", "127.0.0.1:5173"),
        ("http://[::1]:3000/oauth/callback", "[0:0:0:0:0:0:0:1]:5173"),
    ] {
        let mut config = base_config();
        config["providers"][0]["redirect_uri"] = json!(redirect_uri);
        config["session"]["secure"] = json!(false);
        let plugin = OidcRelyingParty::new(&config, PluginHttpClient::default()).unwrap();
        let mut ctx = html_ctx();
        ctx.headers
            .insert("host".to_string(), request_host.to_string());
        ctx.metadata
            .insert("ferrum.frontend_scheme".to_string(), "http".to_string());

        let challenge = issue_browser_challenge_for_context(&plugin, ctx).await;
        assert_eq!(cookie_attribute(&challenge.cookie, "domain"), None);
        assert_eq!(
            cookie_attribute(&challenge.cookie, "path"),
            Some(Some("/oauth/callback"))
        );
        assert_eq!(cookie_attribute(&challenge.cookie, "secure"), None);
    }
}

#[tokio::test]
async fn central_sibling_callback_host_fails_before_state_or_cookie_issuance() {
    let mut config = base_config();
    config["providers"][0]["redirect_uri"] = json!("https://auth.example.com/oauth/callback");
    config["session"]["domain"] = json!("example.com");
    config["behavior"]["state_cache_max_entries"] = json!(1);
    config["behavior"]["state_cache_max_entries_per_source"] = json!(1);
    let plugin = OidcRelyingParty::new(&config, PluginHttpClient::default()).unwrap();
    let mut app_request = html_ctx();
    app_request
        .headers
        .insert("host".to_string(), "app.example.com".to_string());
    app_request.headers.insert(
        "x-forwarded-host".to_string(),
        "auth.example.com".to_string(),
    );

    assert_browser_challenge_fails_closed(&plugin, app_request, AUTHORITY_MISMATCH_ERROR).await;

    // The mismatch must be rejected before a flow consumes the one-entry
    // admission budget. A request on the configured callback host can still
    // start the flow, and the durable session Domain setting remains separate.
    let mut callback_host_request = html_ctx();
    callback_host_request
        .headers
        .insert("host".to_string(), "auth.example.com".to_string());
    let challenge = issue_browser_challenge_for_context(&plugin, callback_host_request).await;
    assert_host_only_correlation_cookie(&challenge.cookie, "600");
}

#[tokio::test]
async fn missing_or_malformed_request_authority_fails_before_browser_challenge() {
    let mut config = base_config();
    config["behavior"]["state_cache_max_entries"] = json!(1);
    config["behavior"]["state_cache_max_entries_per_source"] = json!(1);
    let plugin = OidcRelyingParty::new(&config, PluginHttpClient::default()).unwrap();
    let mut contexts = Vec::new();

    let mut missing = html_ctx();
    missing.headers.remove("host");
    missing.headers.insert(
        "x-forwarded-host".to_string(),
        "app.example.com".to_string(),
    );
    contexts.push(missing);

    for host in [
        "app.example.com.",
        "app.example.com,auth.example.com",
        "user@app.example.com",
        "2001:db8::1",
        "[2001:db8::1]:65536",
    ] {
        let mut malformed = html_ctx();
        malformed
            .headers
            .insert("host".to_string(), host.to_string());
        contexts.push(malformed);
    }

    for ctx in contexts {
        assert_browser_challenge_fails_closed(&plugin, ctx, INVALID_AUTHORITY_ERROR).await;
    }

    // Invalid authorities must not consume the one-entry admission budget.
    let challenge = issue_browser_challenge(&plugin).await;
    assert_host_only_correlation_cookie(&challenge.cookie, "600");
}

#[tokio::test]
async fn correlation_cookie_ignores_configured_session_domain() {
    let mut config = base_config();
    config["session"]["domain"] = json!("example.com");
    let plugin = OidcRelyingParty::new(&config, PluginHttpClient::default()).unwrap();
    let challenge = issue_browser_challenge(&plugin).await;

    assert_host_only_correlation_cookie(&challenge.cookie, "600");
}

#[tokio::test]
async fn successful_callback_clears_host_only_correlation_cookie_and_preserves_session_domain() {
    let server = MockServer::start().await;
    let public_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_public.pem");
    let private_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_private.pem");
    Mock::given(method("GET"))
        .and(path("/jwks"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(build_rsa_jwks_from_pem(public_key_pem)),
        )
        .mount(&server)
        .await;

    let mut config = base_config();
    config["providers"][0]["token_endpoint"] = json!(format!("{}/token", server.uri()));
    config["providers"][0]["jwks_uri"] = json!(format!("{}/jwks", server.uri()));
    config["session"]["domain"] = json!("example.com");
    let plugin = OidcRelyingParty::new(&config, PluginHttpClient::default()).unwrap();
    let challenge = issue_browser_challenge(&plugin).await;
    let id_token = create_rs256_token(
        &json!({
            "iss": "https://issuer.example.com",
            "aud": "ferrum-gateway",
            "sub": "user-1",
            "nonce": challenge.nonce.as_str(),
        }),
        private_key_pem,
    );
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "access-token",
            "token_type": "Bearer",
            "expires_in": 3600,
            "id_token": id_token,
        })))
        .mount(&server)
        .await;

    let mut callback = callback_context(&challenge);
    callback
        .query_params
        .insert("code".to_string(), "authorization-code".to_string());
    let PluginResult::Reject {
        status_code,
        headers,
        ..
    } = plugin.on_request_received(&mut callback).await
    else {
        panic!("expected successful callback redirect");
    };
    assert_eq!(status_code, 302);
    let cookies: Vec<&str> = headers
        .get("set-cookie")
        .expect("session and correlation cookies")
        .lines()
        .collect();
    let session_cookie = cookies
        .iter()
        .copied()
        .find(|cookie| cookie.starts_with("ferrum_session="))
        .expect("durable session cookie");
    let correlation_cookie_name = cookie_name(&challenge.cookie);
    let cleared_correlation_cookie = cookies
        .iter()
        .copied()
        .find(|cookie| cookie_name(cookie) == correlation_cookie_name)
        .expect("cleared correlation cookie");

    assert_eq!(
        cookie_attribute(session_cookie, "domain"),
        Some(Some("example.com")),
        "durable session cookie must retain its configured domain"
    );
    assert_host_only_correlation_cookie(cleared_correlation_cookie, "0");
    assert_same_correlation_scope(&challenge.cookie, cleared_correlation_cookie);
}

#[tokio::test]
async fn unauthenticated_api_post_returns_401() {
    let plugin = OidcRelyingParty::new(&base_config(), PluginHttpClient::default()).unwrap();
    let mut ctx = RequestContext::new("127.0.0.1".into(), "POST".into(), "/api".into());
    let result = plugin
        .authenticate(&mut ctx, &ConsumerIndex::new(&[]))
        .await;
    assert_reject(result, Some(401));
}

#[test]
fn rejects_unknown_fields_at_every_config_boundary() {
    for (scope, config) in [
        ("config.typo", {
            let mut config = base_config();
            config["typo"] = json!(true);
            config
        }),
        ("provider[0].required_scope", {
            let mut config = base_config();
            config["providers"][0]["required_scope"] = json!(["admin"]);
            config
        }),
        ("provider[0].client_auth.client_secert", {
            let mut config = base_config();
            config["providers"][0]["client_auth"]["client_secert"] = json!("typo");
            config
        }),
        ("session.securee", {
            let mut config = base_config();
            config["session"]["securee"] = json!(true);
            config
        }),
        ("behavior.state_ttl_second", {
            let mut config = base_config();
            config["behavior"]["state_ttl_second"] = json!(600);
            config
        }),
    ] {
        let error = OidcRelyingParty::new(&config, PluginHttpClient::default())
            .err()
            .expect("unknown field must be rejected");
        assert!(
            error.contains(scope),
            "unexpected error for {scope}: {error}"
        );
    }
}

#[test]
fn shared_validation_entrypoint_rejects_authorization_policy_typo() {
    let mut config = base_config();
    config["providers"][0]["required_role"] = json!(["admin"]);

    let error = validate_plugin_config("oidc_relying_party", &config)
        .expect_err("validation must reject unknown authorization fields");
    assert!(error.contains("provider[0].required_role"));
}

#[test]
fn remote_cleartext_provider_endpoints_are_rejected() {
    for field in [
        "issuer",
        "authorization_endpoint",
        "token_endpoint",
        "userinfo_endpoint",
        "jwks_uri",
        "end_session_endpoint",
        "post_logout_redirect_uri",
    ] {
        let mut config = base_config();
        config["providers"][0][field] = json!(format!("http://idp.example.com/{field}"));
        let error = OidcRelyingParty::new(&config, PluginHttpClient::default())
            .err()
            .expect("remote HTTP endpoint must be rejected");
        assert!(
            error.contains(field),
            "unexpected error for {field}: {error}"
        );
        assert!(
            error.contains("https"),
            "unexpected error for {field}: {error}"
        );
    }
}

#[tokio::test]
async fn loopback_http_provider_endpoints_remain_available_for_development() {
    let config = json!({
        "providers": [{
            "issuer": "http://127.0.0.1:8080",
            "authorization_endpoint": "http://127.0.0.1:8080/authorize",
            "token_endpoint": "http://127.0.0.1:8080/token",
            "userinfo_endpoint": "http://127.0.0.1:8080/userinfo",
            "jwks_uri": "http://127.0.0.1:8080/jwks",
            "end_session_endpoint": "http://127.0.0.1:8080/logout",
            "post_logout_redirect_uri": "http://localhost:3000/goodbye",
            "client_id": "local-client",
            "client_auth": {"method": "client_secret_basic", "client_secret": "secret"},
            "scopes": ["openid"],
            "redirect_uri": "http://localhost:3000/oauth/callback",
            "callback_path": "/oauth/callback"
        }],
        "session": {"encryption_secret": "01234567890123456789012345678901"}
    });

    assert!(OidcRelyingParty::new(&config, PluginHttpClient::default()).is_ok());
}

#[tokio::test]
async fn callback_hook_materializes_decoded_query_before_processing() {
    let mut config = base_config();
    config["session"]["domain"] = json!("example.com");
    let plugin = OidcRelyingParty::new(&config, PluginHttpClient::default()).unwrap();
    let mut ctx = RequestContext::new("127.0.0.1".into(), "GET".into(), "/oauth/callback".into());
    ctx.set_raw_query_string("state=encoded%2Bstate&code=example".to_string());

    let reject = plugin.on_request_received(&mut ctx).await;
    assert_eq!(
        ctx.query_params.get("state").map(String::as_str),
        Some("encoded+state")
    );
    match reject {
        PluginResult::Reject {
            status_code,
            body,
            headers,
        } => {
            assert_eq!(status_code, 400);
            assert_eq!(body, r#"{"error":"Invalid state"}"#);
            assert_host_only_correlation_cookie(&headers["set-cookie"], "0");
        }
        other => panic!("expected invalid-state reject, got {other:?}"),
    }

    let mut missing =
        RequestContext::new("127.0.0.1".into(), "GET".into(), "/oauth/callback".into());
    match plugin.on_request_received(&mut missing).await {
        PluginResult::Reject {
            status_code, body, ..
        } => {
            assert_eq!(status_code, 400);
            assert_eq!(body, r#"{"error":"Missing state"}"#);
        }
        other => panic!("expected missing-state reject, got {other:?}"),
    }
}

#[tokio::test]
async fn browser_state_cookie_blocks_cross_browser_callback_without_consuming_flow() {
    let mut config = base_config();
    config["session"]["domain"] = json!("example.com");
    let plugin = OidcRelyingParty::new(&config, PluginHttpClient::default()).unwrap();
    let challenge = issue_browser_challenge(&plugin).await;
    let state = challenge.state.clone();
    let correlation_cookie = &challenge.cookie;
    assert_host_only_correlation_cookie(correlation_cookie, "600");

    let mut attacker_ctx = RequestContext::new(
        "198.51.100.9".into(),
        "GET".into(),
        "/oauth/callback".into(),
    );
    let correlation_cookie_name = cookie_name(correlation_cookie);
    attacker_ctx.headers.insert(
        "cookie".to_string(),
        format!("{correlation_cookie_name}=wrong-browser-binding"),
    );
    attacker_ctx
        .query_params
        .insert("state".to_string(), state.clone());
    match plugin.on_request_received(&mut attacker_ctx).await {
        PluginResult::Reject {
            status_code,
            headers,
            ..
        } => {
            assert_eq!(status_code, 400);
            let cleared = headers
                .get("set-cookie")
                .expect("wrong-binding correlation cookie clear");
            assert_host_only_correlation_cookie(cleared, "0");
            assert_same_correlation_scope(correlation_cookie, cleared);
        }
        other => panic!("expected wrong-binding rejection, got {other:?}"),
    }

    // The wrong browser must not consume the valid state. The initiating
    // browser reaches the next callback validation step (missing code).
    let cookie_pair = cookie_pair(correlation_cookie).to_string();
    let mut browser_ctx =
        RequestContext::new("127.0.0.1".into(), "GET".into(), "/oauth/callback".into());
    browser_ctx
        .headers
        .insert("cookie".to_string(), cookie_pair);
    browser_ctx.query_params.insert("state".to_string(), state);
    match plugin.on_request_received(&mut browser_ctx).await {
        PluginResult::Reject { body, headers, .. } => {
            assert_eq!(body, r#"{"error":"Missing code"}"#);
            let cleared = &headers["set-cookie"];
            assert_host_only_correlation_cookie(cleared, "0");
            assert_same_correlation_scope(correlation_cookie, cleared);
        }
        other => panic!("expected missing-code rejection, got {other:?}"),
    }
}

#[tokio::test]
async fn pending_login_admission_is_bounded_per_source() {
    let mut config = base_config();
    config["behavior"]["state_cache_max_entries"] = json!(4);
    config["behavior"]["state_cache_max_entries_per_source"] = json!(1);
    let plugin = OidcRelyingParty::new(&config, PluginHttpClient::default()).unwrap();

    let mut first = html_ctx();
    assert_reject(
        plugin
            .authenticate(&mut first, &ConsumerIndex::new(&[]))
            .await,
        Some(302),
    );
    let mut same_source = html_ctx();
    assert_reject(
        plugin
            .authenticate(&mut same_source, &ConsumerIndex::new(&[]))
            .await,
        Some(503),
    );
    let mut other_source = html_ctx();
    other_source.client_ip = "192.0.2.10".to_string();
    assert_reject(
        plugin
            .authenticate(&mut other_source, &ConsumerIndex::new(&[]))
            .await,
        Some(302),
    );
}

#[tokio::test]
async fn pending_login_admission_is_bounded_globally_across_sources() {
    let mut config = base_config();
    config["behavior"]["state_cache_max_entries"] = json!(1);
    config["behavior"]["state_cache_max_entries_per_source"] = json!(1);
    let plugin = OidcRelyingParty::new(&config, PluginHttpClient::default()).unwrap();

    let mut first = html_ctx();
    assert_reject(
        plugin
            .authenticate(&mut first, &ConsumerIndex::new(&[]))
            .await,
        Some(302),
    );
    let mut distributed = html_ctx();
    distributed.client_ip = "192.0.2.99".to_string();
    assert_reject(
        plugin
            .authenticate(&mut distributed, &ConsumerIndex::new(&[]))
            .await,
        Some(503),
    );
}

#[tokio::test]
async fn explicit_jwks_uri_is_reported_as_active() {
    let plugin = OidcRelyingParty::new(&base_config(), PluginHttpClient::default()).unwrap();
    assert_eq!(
        plugin.active_jwks_uris(),
        vec!["https://issuer.example.com/jwks".to_string()]
    );
}

async fn mount_token_and_jwks(server: &MockServer, id_token: &str) {
    let public_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_public.pem");
    Mock::given(method("GET"))
        .and(path("/jwks"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(build_rsa_jwks_from_pem(public_key_pem)),
        )
        .mount(server)
        .await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "access-token",
            "token_type": "Bearer",
            "expires_in": 3600,
            "id_token": id_token,
        })))
        .mount(server)
        .await;
}

fn plugin_pair_for_server(
    server: &MockServer,
) -> (serde_json::Value, OidcRelyingParty, OidcRelyingParty) {
    let mut config = base_config();
    config["providers"][0]["token_endpoint"] = json!(format!("{}/token", server.uri()));
    config["providers"][0]["jwks_uri"] = json!(format!("{}/jwks", server.uri()));
    let starter = OidcRelyingParty::new(&config, PluginHttpClient::default()).unwrap();
    let completer = OidcRelyingParty::new(&config, PluginHttpClient::default()).unwrap();
    (config, starter, completer)
}

async fn complete_callback(
    plugin: &OidcRelyingParty,
    challenge: &BrowserChallenge,
    code: &str,
) -> PluginResult {
    let mut callback = callback_context(challenge);
    callback
        .query_params
        .insert("code".to_string(), code.to_string());
    plugin.on_request_received(&mut callback).await
}

#[tokio::test]
async fn cross_replica_callback_accepts_sealed_pending_flow() {
    let server = MockServer::start().await;
    let (_, starter, completer) = plugin_pair_for_server(&server);
    let challenge = issue_browser_challenge(&starter).await;
    let private_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_private.pem");
    let id_token = create_rs256_token(
        &json!({
            "iss": "https://issuer.example.com",
            "aud": "ferrum-gateway",
            "sub": "user-1",
            "nonce": challenge.nonce.as_str(),
        }),
        private_key_pem,
    );
    mount_token_and_jwks(&server, &id_token).await;

    match complete_callback(&completer, &challenge, "authorization-code").await {
        PluginResult::Reject {
            status_code,
            headers,
            ..
        } => {
            assert_eq!(status_code, 302);
            assert!(
                headers
                    .get("set-cookie")
                    .is_some_and(|value| value.contains("ferrum_session=")),
                "cross-replica callback must issue a session cookie"
            );
        }
        other => panic!("expected cross-replica success, got {other:?}"),
    }
}

#[tokio::test]
async fn same_instance_callback_still_completes_with_sealed_pending_flow() {
    let server = MockServer::start().await;
    let (_, plugin, _) = plugin_pair_for_server(&server);
    let challenge = issue_browser_challenge(&plugin).await;
    let private_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_private.pem");
    let id_token = create_rs256_token(
        &json!({
            "iss": "https://issuer.example.com",
            "aud": "ferrum-gateway",
            "sub": "user-1",
            "nonce": challenge.nonce.as_str(),
        }),
        private_key_pem,
    );
    mount_token_and_jwks(&server, &id_token).await;

    match complete_callback(&plugin, &challenge, "authorization-code").await {
        PluginResult::Reject { status_code, .. } => assert_eq!(status_code, 302),
        other => panic!("expected same-instance success, got {other:?}"),
    }
}

#[tokio::test]
async fn cross_replica_callback_rejects_wrong_encryption_secret() {
    let server = MockServer::start().await;
    let (mut config, starter, _) = plugin_pair_for_server(&server);
    let challenge = issue_browser_challenge(&starter).await;
    config["session"]["encryption_secret"] = json!("abcdefghijklmnopqrstuvwxyz123456");
    let wrong_secret = OidcRelyingParty::new(&config, PluginHttpClient::default()).unwrap();

    match complete_callback(&wrong_secret, &challenge, "authorization-code").await {
        PluginResult::Reject {
            status_code, body, ..
        } => {
            assert_eq!(status_code, 400);
            assert_eq!(body, r#"{"error":"Invalid state"}"#);
        }
        other => panic!("expected wrong-secret rejection, got {other:?}"),
    }
}

#[tokio::test]
async fn cross_replica_callback_rejects_wrong_session_context() {
    let server = MockServer::start().await;
    let (mut config, starter, _) = plugin_pair_for_server(&server);
    let challenge = issue_browser_challenge(&starter).await;
    config["providers"][0]["client_id"] = json!("other-client");
    let other_context = OidcRelyingParty::new(&config, PluginHttpClient::default()).unwrap();

    match complete_callback(&other_context, &challenge, "authorization-code").await {
        PluginResult::Reject {
            status_code, body, ..
        } => {
            assert_eq!(status_code, 400);
            assert_eq!(body, r#"{"error":"Invalid state"}"#);
        }
        other => panic!("expected wrong-context rejection, got {other:?}"),
    }
}

#[tokio::test]
async fn sealed_pending_flow_rejects_tampered_correlation_cookie() {
    let server = MockServer::start().await;
    let (_, plugin, _) = plugin_pair_for_server(&server);
    let challenge = issue_browser_challenge(&plugin).await;
    let mut tampered = challenge.clone();
    let pair = cookie_pair(&challenge.cookie);
    let (name, value) = pair.split_once('=').expect("cookie pair");
    let mut chars: Vec<char> = value.chars().collect();
    let last = chars.last_mut().expect("non-empty sealed value");
    *last = if *last == 'A' { 'B' } else { 'A' };
    tampered.cookie = format!(
        "{}={};{}",
        name,
        chars.into_iter().collect::<String>(),
        challenge
            .cookie
            .split_once(';')
            .map(|(_, rest)| rest)
            .unwrap_or("")
    );

    match complete_callback(&plugin, &tampered, "authorization-code").await {
        PluginResult::Reject {
            status_code, body, ..
        } => {
            assert_eq!(status_code, 400);
            assert_eq!(body, r#"{"error":"Invalid state"}"#);
        }
        other => panic!("expected tamper rejection, got {other:?}"),
    }
}

#[tokio::test]
async fn sealed_pending_flow_rejects_expired_state() {
    let server = MockServer::start().await;
    let mut config = base_config();
    config["providers"][0]["token_endpoint"] = json!(format!("{}/token", server.uri()));
    config["providers"][0]["jwks_uri"] = json!(format!("{}/jwks", server.uri()));
    config["behavior"]["state_ttl_secs"] = json!(1);
    let plugin = OidcRelyingParty::new(&config, PluginHttpClient::default()).unwrap();
    let challenge = issue_browser_challenge(&plugin).await;
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

    match complete_callback(&plugin, &challenge, "authorization-code").await {
        PluginResult::Reject {
            status_code, body, ..
        } => {
            assert_eq!(status_code, 400);
            assert_eq!(body, r#"{"error":"Invalid state"}"#);
        }
        other => panic!("expected expiry rejection, got {other:?}"),
    }
}

#[tokio::test]
async fn sealed_pending_flow_rejects_oversized_correlation_cookie() {
    let plugin = OidcRelyingParty::new(&base_config(), PluginHttpClient::default()).unwrap();
    let challenge = issue_browser_challenge(&plugin).await;
    let name = cookie_name(&challenge.cookie);
    let oversized = format!("{name}={}", "A".repeat(9000));
    let mut callback =
        RequestContext::new("127.0.0.1".into(), "GET".into(), "/oauth/callback".into());
    callback.request_is_secure = true;
    callback.headers.insert("cookie".to_string(), oversized);
    callback
        .query_params
        .insert("state".to_string(), challenge.state.clone());
    callback
        .query_params
        .insert("code".to_string(), "authorization-code".to_string());

    match plugin.on_request_received(&mut callback).await {
        PluginResult::Reject {
            status_code, body, ..
        } => {
            assert_eq!(status_code, 400);
            assert_eq!(body, r#"{"error":"Invalid state"}"#);
        }
        other => panic!("expected oversized rejection, got {other:?}"),
    }
}

#[tokio::test]
async fn same_instance_rejects_replay_after_sealed_state_is_accepted() {
    let server = MockServer::start().await;
    let (_, plugin, _) = plugin_pair_for_server(&server);
    let challenge = issue_browser_challenge(&plugin).await;
    let private_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_private.pem");
    let id_token = create_rs256_token(
        &json!({
            "iss": "https://issuer.example.com",
            "aud": "ferrum-gateway",
            "sub": "user-1",
            "nonce": challenge.nonce.as_str(),
        }),
        private_key_pem,
    );
    mount_token_and_jwks(&server, &id_token).await;

    assert!(matches!(
        complete_callback(&plugin, &challenge, "authorization-code").await,
        PluginResult::Reject {
            status_code: 302,
            ..
        }
    ));
    match complete_callback(&plugin, &challenge, "authorization-code").await {
        PluginResult::Reject {
            status_code, body, ..
        } => {
            assert_eq!(status_code, 400);
            assert_eq!(body, r#"{"error":"Invalid state"}"#);
        }
        other => panic!("expected replay rejection, got {other:?}"),
    }
}

#[tokio::test]
async fn provider_authorization_code_remains_one_time_across_replicas() {
    let server = MockServer::start().await;
    let public_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_public.pem");
    let private_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_private.pem");
    let mut config = base_config();
    config["providers"][0]["token_endpoint"] = json!(format!("{}/token", server.uri()));
    config["providers"][0]["jwks_uri"] = json!(format!("{}/jwks", server.uri()));
    let starter = OidcRelyingParty::new(&config, PluginHttpClient::default()).unwrap();
    let completer = OidcRelyingParty::new(&config, PluginHttpClient::default()).unwrap();
    let challenge = issue_browser_challenge(&starter).await;
    let id_token = create_rs256_token(
        &json!({
            "iss": "https://issuer.example.com",
            "aud": "ferrum-gateway",
            "sub": "user-1",
            "nonce": challenge.nonce.as_str(),
        }),
        private_key_pem,
    );

    Mock::given(method("GET"))
        .and(path("/jwks"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(build_rsa_jwks_from_pem(public_key_pem)),
        )
        .mount(&server)
        .await;
    let exchanges = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&exchanges);
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(move |_: &Request| {
            let prior = counter.fetch_add(1, Ordering::SeqCst);
            if prior == 0 {
                ResponseTemplate::new(200).set_body_json(json!({
                    "access_token": "access-token",
                    "token_type": "Bearer",
                    "expires_in": 3600,
                    "id_token": id_token,
                }))
            } else {
                ResponseTemplate::new(400).set_body_json(json!({"error":"invalid_grant"}))
            }
        })
        .mount(&server)
        .await;

    match complete_callback(&completer, &challenge, "one-time-code").await {
        PluginResult::Reject { status_code, .. } => assert_eq!(status_code, 302),
        other => panic!("expected first replica success, got {other:?}"),
    }
    match complete_callback(&starter, &challenge, "one-time-code").await {
        PluginResult::Reject {
            status_code, body, ..
        } => {
            assert_eq!(status_code, 400);
            assert_eq!(body, r#"{"error":"Token exchange failed"}"#);
        }
        other => panic!("expected one-time code rejection on second replica, got {other:?}"),
    }
    assert_eq!(exchanges.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn previous_encryption_secret_accepts_pending_flow_during_rotation() {
    let server = MockServer::start().await;
    let old_secret = "01234567890123456789012345678901";
    let new_secret = "abcdefghijklmnopqrstuvwxyz123456";
    let mut starter_config = base_config();
    starter_config["providers"][0]["token_endpoint"] = json!(format!("{}/token", server.uri()));
    starter_config["providers"][0]["jwks_uri"] = json!(format!("{}/jwks", server.uri()));
    starter_config["session"]["encryption_secret"] = json!(old_secret);
    let mut completer_config = starter_config.clone();
    completer_config["session"]["encryption_secret"] = json!(new_secret);
    completer_config["session"]["encryption_secret_previous"] = json!(old_secret);

    let starter = OidcRelyingParty::new(&starter_config, PluginHttpClient::default()).unwrap();
    let completer = OidcRelyingParty::new(&completer_config, PluginHttpClient::default()).unwrap();
    let challenge = issue_browser_challenge(&starter).await;
    let private_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_private.pem");
    let id_token = create_rs256_token(
        &json!({
            "iss": "https://issuer.example.com",
            "aud": "ferrum-gateway",
            "sub": "user-1",
            "nonce": challenge.nonce.as_str(),
        }),
        private_key_pem,
    );
    mount_token_and_jwks(&server, &id_token).await;

    match complete_callback(&completer, &challenge, "authorization-code").await {
        PluginResult::Reject { status_code, .. } => assert_eq!(status_code, 302),
        other => panic!("expected previous-secret rotation success, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Discovery-backed trust health parity with jwks_auth (issue #3739)
// ---------------------------------------------------------------------------

/// `oidc_relying_party` resolves its JWKS endpoint from an OIDC discovery
/// document on a background task. That store must join the active trust
/// aggregate as soon as its generation commits — the same guarantee a directly
/// configured `jwks_uri` gets at publication — and must leave it again when the
/// generation retires.
#[tokio::test]
async fn oidc_discovered_jwks_store_joins_active_trust_health_after_commit() {
    use ferrum_edge::plugins::utils::jwks_cache::{
        cached_requirement, clear_jwks_cache, retain_active_requirements, trust_health_snapshot,
    };
    use std::time::Duration;

    let public_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_public.pem");
    let server = MockServer::start().await;
    let jwks_uri = format!("{}/oidc-trust/jwks.json", server.uri());
    Mock::given(method("GET"))
        .and(path("/oidc-trust/jwks.json"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(build_rsa_jwks_from_pem(public_key_pem)),
        )
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/oidc-trust/openid-configuration"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "authorization_endpoint": format!("{}/oidc-trust/authorize", server.uri()),
            "token_endpoint": format!("{}/oidc-trust/token", server.uri()),
            "jwks_uri": jwks_uri,
        })))
        .mount(&server)
        .await;

    let _guard = super::jwks_cache_tests::cache_test_lock().lock().await;
    clear_jwks_cache();

    let mut config = base_config();
    config["providers"][0] = json!({
        "issuer": "https://issuer.example.com",
        "discovery_url": format!("{}/oidc-trust/openid-configuration", server.uri()),
        "client_id": "ferrum-gateway",
        "client_auth": {"method": "client_secret_basic", "client_secret": "secret"},
        "scopes": ["openid", "profile"],
        "redirect_uri": "https://app.example.com/oauth/callback",
        "callback_path": "/oauth/callback",
        "logout_path": "/oauth/logout"
    });
    let plugin = OidcRelyingParty::new(&config, PluginHttpClient::default()).unwrap();

    // The generation is published with no JWKS requirement — discovery has not
    // resolved yet — and only then committed.
    retain_active_requirements(&HashMap::new());
    plugin.commit_background_tasks();

    let deadline = tokio::time::Instant::now() + tokio::time::Duration::from_secs(3);
    loop {
        let snapshot = trust_health_snapshot();
        let total = snapshot.fresh + snapshot.grace + snapshot.expired;
        if total == 1 || tokio::time::Instant::now() >= deadline {
            assert_eq!(
                total, 1,
                "a committed OIDC discovery-backed store must join the active trust aggregate"
            );
            break;
        }
        tokio::time::sleep(tokio::time::Duration::from_millis(20)).await;
    }
    assert_eq!(
        cached_requirement(&jwks_uri).map(|requirement| requirement.max_stale),
        Some(Duration::from_secs(3_600)),
        "the discovered store must carry oidc_relying_party's finite max-stale bound"
    );

    drop(plugin);
    let retired = trust_health_snapshot();
    assert_eq!(
        (retired.fresh, retired.grace, retired.expired),
        (0, 0, 0),
        "retiring the owning generation must withdraw its contribution"
    );
    clear_jwks_cache();
}

/// A staged `oidc_relying_party` generation that is never committed must not
/// reach readiness or metrics even after its discovery task publishes.
#[tokio::test]
async fn oidc_staged_discovery_store_is_not_exposed_before_commit() {
    use ferrum_edge::plugins::utils::jwks_cache::{clear_jwks_cache, trust_health_snapshot};

    let public_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_public.pem");
    let server = MockServer::start().await;
    let jwks_uri = format!("{}/oidc-staged/jwks.json", server.uri());
    Mock::given(method("GET"))
        .and(path("/oidc-staged/jwks.json"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(build_rsa_jwks_from_pem(public_key_pem)),
        )
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/oidc-staged/openid-configuration"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "authorization_endpoint": format!("{}/oidc-staged/authorize", server.uri()),
            "token_endpoint": format!("{}/oidc-staged/token", server.uri()),
            "jwks_uri": jwks_uri,
        })))
        .mount(&server)
        .await;

    let _guard = super::jwks_cache_tests::cache_test_lock().lock().await;
    clear_jwks_cache();

    let mut config = base_config();
    config["providers"][0] = json!({
        "issuer": "https://issuer.example.com",
        "discovery_url": format!("{}/oidc-staged/openid-configuration", server.uri()),
        "client_id": "ferrum-gateway",
        "client_auth": {"method": "client_secret_basic", "client_secret": "secret"},
        "scopes": ["openid", "profile"],
        "redirect_uri": "https://app.example.com/oauth/callback",
        "callback_path": "/oauth/callback",
        "logout_path": "/oauth/logout"
    });
    let plugin = OidcRelyingParty::new(&config, PluginHttpClient::default()).unwrap();

    // Give discovery time to publish into the plugin's local slot.
    tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;
    let staged = trust_health_snapshot();
    assert_eq!(
        (staged.fresh, staged.grace, staged.expired),
        (0, 0, 0),
        "an unpublished generation must not reach readiness or metrics"
    );

    // Committing the same generation publishes it immediately, with no reload.
    plugin.commit_background_tasks();
    let committed = trust_health_snapshot();
    assert_eq!(
        committed.fresh + committed.grace + committed.expired,
        1,
        "commit must adopt a store discovery resolved while the generation was staged"
    );

    drop(plugin);
    clear_jwks_cache();
}
