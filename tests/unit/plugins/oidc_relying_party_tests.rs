use chrono::Utc;
use ferrum_edge::_test_support::{
    oidc_open_session_cookie_for_test, oidc_resolve_discovery_for_test,
    oidc_resolved_discovery_endpoints_for_test, oidc_sealed_due_refresh_session_cookie_for_test,
    oidc_sealed_refresh_session_cookie_for_test, oidc_sealed_session_cookie_for_test,
    oidc_session_state_from_set_cookie_for_test, request_credential_deadline_remaining,
};
use ferrum_edge::ConsumerIndex;
use ferrum_edge::config::types::{AuthMode, GatewayConfig, PluginConfig, PluginScope};
use ferrum_edge::plugins::validate_plugin_config;
use ferrum_edge::plugins::{
    Plugin, PluginHttpClient, PluginResult, RequestContext, key_auth::KeyAuth,
    oidc_relying_party::OidcRelyingParty, priority,
};
use ferrum_edge::proxy::run_authentication_phase_with_envelope;
use serde_json::json;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use url::Url;
use wiremock::matchers::{basic_auth, body_string_contains, header, method, path};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

use super::jwks_auth_support::{
    build_rsa_jwks_from_pem, build_rsa_jwks_from_pem_with_kid, create_rs256_token,
    create_rs256_token_no_kid, create_rs256_token_with_kid,
};
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

#[tokio::test(flavor = "current_thread")]
async fn discovery_transport_errors_use_the_redacted_endpoint() {
    let (logs, _guard) = super::plugin_utils::capture_logs();
    // An unsupported scheme fails before network I/O.
    let endpoint = concat!(
        "unsupported://test-user:test-password@example.test/",
        "private-path?key=test-query#test-fragment"
    );
    let error = oidc_resolve_discovery_for_test(&PluginHttpClient::default(), endpoint, None, None)
        .await
        .expect_err("unsupported transport must fail");
    assert!(error.contains("discovery request failed"), "{error}");
    assert!(error.contains("example.test/redacted"), "{error}");
    let diagnostics = format!("{error}\n{}", logs.contents());
    for component in [
        "test-user",
        "test-password",
        "private-path",
        "test-query",
        "test-fragment",
    ] {
        assert!(!diagnostics.contains(component), "{diagnostics}");
    }
}

#[test]
fn every_oidc_provider_call_uses_the_shared_redacted_error_boundary() {
    let source = include_str!("../../../src/plugins/oidc_relying_party.rs");
    assert!(!source.contains(".execute("));
    for label in ["oidc_rp_token", "oidc_rp_userinfo", "oidc_rp_discovery"] {
        let call = source
            .split(".execute_redacted(")
            .skip(1)
            .find(|call| call.split(".await").next().unwrap().contains(label))
            .unwrap_or_else(|| panic!("{label} must redact returned errors"));
        assert!(
            call.split(".await")
                .next()
                .unwrap()
                .contains("redacted_endpoint_url_str("),
            "{label} must redact its endpoint label"
        );
    }
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

fn callback_config() -> serde_json::Value {
    let mut config = base_config();
    // Callback tests exercise cookie binding, not expiry. Allow the maximum
    // state lifetime so coverage instrumentation does not consume the budget.
    config["behavior"]["state_ttl_secs"] = json!(3600);
    config
}

async fn prepare_callback_jwks(server: &MockServer) {
    // Callers hold jwks_remote_global_cache: another test must not clear the
    // store or abort its refresh while this fixture is using it.
    let uri = format!("{}/jwks", server.uri());
    let store = ferrum_edge::plugins::utils::jwks_cache::cached_store(&uri)
        .expect("callback plugin registered its JWKS store");
    // Await real readiness, not a sleep or a callback retry (state is one-use).
    // The default client allows 30s to connect and 60s per JWKS request. The
    // token exchange has its own production 10s timeout; its mock has no delay.
    // Fetch the mounted document even if wiremock reused a previous server's
    // address and the global cache retained that fixture's keys.
    tokio::time::timeout(Duration::from_secs(120), store.fetch_keys())
        .await
        .expect("callback JWKS fixture must become ready")
        .expect("callback JWKS fixture must publish valid keys");
    assert!(store.has_keys(), "callback JWKS fixture has no keys");
}

fn assert_callback_redirect(result: PluginResult) -> HashMap<String, String> {
    let PluginResult::Reject {
        status_code,
        body,
        headers,
    } = result
    else {
        panic!("expected callback redirect, got {result:?}");
    };
    assert_eq!(status_code, 302, "body: {body}; headers: {headers:?}");
    headers
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
        body,
        headers,
    } = plugin
        .authenticate(&mut ctx, &ConsumerIndex::new(&[]))
        .await
    else {
        panic!("expected browser challenge");
    };
    assert_eq!(status_code, 302, "body: {body}; headers: {headers:?}");
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
    assert!(
        cookie_name(cookie).starts_with("__Host-ferrum_oidc_state_"),
        "{cookie}"
    );
    assert_eq!(cookie_attribute(cookie, "domain"), None, "{cookie}");
    assert_eq!(
        cookie_attribute(cookie, "path"),
        Some(Some("/")),
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
        run_authentication_phase_with_envelope(
            AuthMode::Single,
            &[key_auth_plugin, oidc_plugin],
            &mut ctx,
            &ConsumerIndex::new(&[create_test_consumer()]),
            false,
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
async fn concurrent_refresh_due_requests_share_one_rotation_and_never_reseal_the_spent_token() {
    let server = MockServer::start().await;
    // Single-use rotating token endpoint with reversed timing: the first grant
    // rotates after a short delay; any duplicate submission of the same token
    // fails with `invalid_grant` even later, so a racing loser (should one ever
    // run) would be the response the browser applies last.
    let calls = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&calls);
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(move |_: &Request| {
            if counter.fetch_add(1, Ordering::SeqCst) == 0 {
                ResponseTemplate::new(200)
                    .set_delay(Duration::from_millis(150))
                    .set_body_json(json!({
                        "access_token": "new-access-token",
                        "refresh_token": "rotated-refresh-token",
                        "token_type": "Bearer",
                        "expires_in": 3600
                    }))
            } else {
                ResponseTemplate::new(400)
                    .set_delay(Duration::from_millis(600))
                    .set_body_json(json!({"error": "invalid_grant"}))
            }
        })
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
    let consumer_index = ConsumerIndex::new(&[]);
    let mut first = session_ctx(&cookie);
    let mut second = session_ctx(&cookie);

    // Both requests decrypt the same pre-rotation cookie and are polled in one
    // task: the first inserts its flight before its token POST suspends, so the
    // second is deterministically a follower of that flight.
    let (first_result, second_result) = tokio::join!(
        plugin.authenticate(&mut first, &consumer_index),
        plugin.authenticate(&mut second, &consumer_index),
    );
    assert_continue(first_result);
    assert_continue(second_result);
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "one token generation must reach the token endpoint exactly once"
    );
    for ctx in [&mut first, &mut second] {
        let rolled = rolling_cookie(&plugin, ctx)
            .await
            .expect("every coalesced request emits the rotated session");
        let payload =
            oidc_open_session_cookie_for_test(&plugin, &rolled).expect("rolling cookie opens");
        assert_eq!(payload["refresh_token_b64"], json!("rotated-refresh-token"));
        assert_eq!(payload["access_token_b64"], json!("new-access-token"));
    }

    // Completion racing admission: a request that decrypted the spent cookie
    // after the winner published adopts the rotation instead of re-submitting.
    let mut late = session_ctx(&cookie);
    assert_continue(plugin.authenticate(&mut late, &consumer_index).await);
    let late_cookie = rolling_cookie(&plugin, &mut late)
        .await
        .expect("a late request with the spent cookie re-issues the rotated session");
    let payload =
        oidc_open_session_cookie_for_test(&plugin, &late_cookie).expect("late cookie opens");
    assert_eq!(payload["refresh_token_b64"], json!("rotated-refresh-token"));
    assert_eq!(payload["access_token_b64"], json!("new-access-token"));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(server.received_requests().await.expect("requests").len(), 1);

    // The rotated cookie is not due, so it does not join the retained flight.
    let mut rotated = session_ctx(&late_cookie);
    assert_continue(plugin.authenticate(&mut rotated, &consumer_index).await);
    assert!(rolling_cookie(&plugin, &mut rotated).await.is_none());
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn spent_refresh_token_rejection_emits_no_cookie_and_is_not_resubmitted() {
    // Cross-replica shape: another replica already rotated this generation, so
    // the provider answers `invalid_grant`. The browser holds the winner's
    // cookie; this instance must not overwrite it with the spent credential.
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({"error": "invalid_grant"})))
        .expect(1)
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
        Some("spent-refresh-token".to_string()),
        true,
        false,
    )
    .expect("session seals");
    let consumer_index = ConsumerIndex::new(&[]);

    let mut first = session_ctx(&cookie);
    assert_continue(plugin.authenticate(&mut first, &consumer_index).await);
    assert!(
        rolling_cookie(&plugin, &mut first).await.is_none(),
        "a spent refresh token must never be re-sealed into a Set-Cookie"
    );

    // The same stale cookie again: the spent-credential record suppresses a
    // second submission for the backoff window without any cookie update.
    let mut repeated = session_ctx(&cookie);
    assert_continue(plugin.authenticate(&mut repeated, &consumer_index).await);
    assert!(rolling_cookie(&plugin, &mut repeated).await.is_none());
    assert_eq!(server.received_requests().await.expect("requests").len(), 1);
}

#[tokio::test]
async fn concurrent_requests_share_one_transient_refresh_failure_and_backoff() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(
            ResponseTemplate::new(503)
                .set_delay(Duration::from_millis(150))
                .set_body_json(json!({"error": "temporarily_unavailable"})),
        )
        .expect(1)
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
        Some("live-refresh-token".to_string()),
        true,
        false,
    )
    .expect("session seals");
    let consumer_index = ConsumerIndex::new(&[]);
    let mut first = session_ctx(&cookie);
    let mut second = session_ctx(&cookie);

    let (first_result, second_result) = tokio::join!(
        plugin.authenticate(&mut first, &consumer_index),
        plugin.authenticate(&mut second, &consumer_index),
    );
    assert_continue(first_result);
    assert_continue(second_result);
    // The token is not known to be spent, so both carry the unchanged
    // credential forward with a persisted backoff instead of retrying.
    for ctx in [&mut first, &mut second] {
        let backed_off = rolling_cookie(&plugin, ctx)
            .await
            .expect("a shared transient failure still persists its backoff");
        let payload =
            oidc_open_session_cookie_for_test(&plugin, &backed_off).expect("backoff cookie opens");
        assert_eq!(payload["refresh_token_b64"], json!("live-refresh-token"));
        assert!(
            payload["refresh_after_unix"]
                .as_i64()
                .is_some_and(|next| next > now)
        );
    }
    assert_eq!(server.received_requests().await.expect("requests").len(), 1);
}

#[tokio::test]
async fn oidc_session_keeps_its_cap_for_a_far_future_id_token_expiry() {
    // Issue #5420 turned the shared Unix-to-monotonic conversion into an
    // `Option`, so this call site now forwards it unwrapped. Unlike the JWT and
    // introspection sites, it clamps the claim expiry to the session
    // `ttl_secs` / `idle_ttl_secs` window BEFORE converting, so its input stays
    // representable and the published bound must be unchanged: a missing
    // deadline here would mean the session lost its cap entirely.
    let plugin = OidcRelyingParty::new(&base_config(), PluginHttpClient::default()).unwrap();
    let set_cookie = oidc_sealed_session_cookie_for_test(
        &plugin,
        json!({"sub": "oidc-subject", "exp": i64::MAX}),
        false,
    )
    .expect("session seals");
    let mut ctx = session_ctx(&set_cookie);

    let result = plugin
        .authenticate(&mut ctx, &ConsumerIndex::new(&[]))
        .await;
    assert_continue(result);
    assert_eq!(ctx.authenticated_identity.as_deref(), Some("oidc-subject"));

    let remaining = request_credential_deadline_remaining(&ctx)
        .expect("the default 1800s idle window still bounds the credential");
    assert!(
        remaining > Duration::from_secs(1_700) && remaining <= Duration::from_secs(1_800),
        "the deadline must stay the idle-TTL cap, not the far-future claim: {remaining:?}"
    );
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
    let (status_code, _, headers) = run_authentication_phase_with_envelope(
        AuthMode::Single,
        &[plugin_for_phase],
        &mut ctx,
        &ConsumerIndex::new(&[]),
        false,
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
        .respond_with(
            ResponseTemplate::new(503).set_body_json(json!({"error": "temporarily_unavailable"})),
        )
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

    let (status_code, body, mut response_headers) = run_authentication_phase_with_envelope(
        AuthMode::Multi,
        &[oidc_plugin, key_auth],
        &mut ctx,
        &consumer_index,
        false,
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

    let (status_code, _, headers) = run_authentication_phase_with_envelope(
        AuthMode::Multi,
        &[first_plugin, second_plugin],
        &mut ctx,
        &ConsumerIndex::new(&[]),
        false,
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

    let (status_code, _, headers) = run_authentication_phase_with_envelope(
        AuthMode::Multi,
        &[first_plugin, second_plugin],
        &mut ctx,
        &ConsumerIndex::new(&[]),
        false,
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
    // The selected correlation cookie starts with `__Secure-ferrum_`; the shorter
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

    let (status_code, _, mut headers) = run_authentication_phase_with_envelope(
        AuthMode::Multi,
        &[first_plugin, second_plugin],
        &mut ctx,
        &ConsumerIndex::new(&[]),
        false,
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
    assert!(cookies[0].contains("Path=/"));
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

    let (status_code, _, headers) = run_authentication_phase_with_envelope(
        AuthMode::Multi,
        &[first_plugin, second_plugin],
        &mut ctx,
        &ConsumerIndex::new(&[]),
        false,
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
    assert!(cookies[0].starts_with("__Host-ferrum_oidc_state_"));
    assert!(cookies[0].contains("Path=/"));
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
        .respond_with(
            ResponseTemplate::new(503).set_body_json(json!({"error": "temporarily_unavailable"})),
        )
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

    let (status_code, _, headers) = run_authentication_phase_with_envelope(
        AuthMode::Multi,
        &auth_plugins,
        &mut first_ctx,
        &consumer_index,
        false,
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
    let (status_code, _, headers) = run_authentication_phase_with_envelope(
        AuthMode::Multi,
        &auth_plugins,
        &mut second_ctx,
        &consumer_index,
        false,
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

    let rejection = run_authentication_phase_with_envelope(
        AuthMode::Multi,
        &[oidc_plugin, key_auth],
        &mut ctx,
        &consumer_index,
        false,
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

        let rejection = run_authentication_phase_with_envelope(
            AuthMode::Multi,
            &[oidc_plugin, Arc::clone(&key_auth)],
            &mut ctx,
            &consumer_index,
            false,
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
        // Without `Secure` the cookie cannot claim a prefix at all.
        assert!(
            cookie_name(&challenge.cookie).starts_with("ferrum_oidc_state_"),
            "{}",
            challenge.cookie
        );
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

#[serial_test::serial(jwks_remote_global_cache)]
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

    let mut config = callback_config();
    config["providers"][0]["token_endpoint"] = json!(format!("{}/token", server.uri()));
    config["providers"][0]["jwks_uri"] = json!(format!("{}/jwks", server.uri()));
    config["session"]["domain"] = json!("example.com");
    let plugin = OidcRelyingParty::new(&config, PluginHttpClient::default()).unwrap();
    prepare_callback_jwks(&server).await;
    let challenge = issue_browser_challenge(&plugin).await;
    let id_token = create_rs256_token(&oidc_id_token_claims(&challenge), private_key_pem);
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
    let headers = assert_callback_redirect(plugin.on_request_received(&mut callback).await);
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
    mount_token_and_jwks_document(server, build_rsa_jwks_from_pem(public_key_pem), id_token).await;
}

async fn mount_token_and_jwks_document(
    server: &MockServer,
    jwks: serde_json::Value,
    id_token: &str,
) {
    Mock::given(method("GET"))
        .and(path("/jwks"))
        .respond_with(ResponseTemplate::new(200).set_body_json(jwks))
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
    prepare_callback_jwks(server).await;
}

async fn plugin_pair_for_server(
    server: &MockServer,
) -> (serde_json::Value, OidcRelyingParty, OidcRelyingParty) {
    let public_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_public.pem");
    plugin_pair_for_jwks(server, build_rsa_jwks_from_pem(public_key_pem)).await
}

async fn plugin_pair_for_jwks(
    server: &MockServer,
    jwks: serde_json::Value,
) -> (serde_json::Value, OidcRelyingParty, OidcRelyingParty) {
    // Construction starts background fetching, so publish the mock first.
    Mock::given(method("GET"))
        .and(path("/jwks"))
        .respond_with(ResponseTemplate::new(200).set_body_json(jwks))
        .mount(server)
        .await;
    let mut config = callback_config();
    config["providers"][0]["token_endpoint"] = json!(format!("{}/token", server.uri()));
    config["providers"][0]["jwks_uri"] = json!(format!("{}/jwks", server.uri()));
    let starter = OidcRelyingParty::new(&config, PluginHttpClient::default()).unwrap();
    let completer = OidcRelyingParty::new(&config, PluginHttpClient::default()).unwrap();
    prepare_callback_jwks(server).await;
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

#[serial_test::serial(jwks_remote_global_cache)]
#[tokio::test]
async fn cross_replica_callback_accepts_sealed_pending_flow() {
    let server = MockServer::start().await;
    let (_, starter, completer) = plugin_pair_for_server(&server).await;
    let challenge = issue_browser_challenge(&starter).await;
    let private_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_private.pem");
    let id_token = create_rs256_token(&oidc_id_token_claims(&challenge), private_key_pem);
    mount_token_and_jwks(&server, &id_token).await;

    match complete_callback(&completer, &challenge, "authorization-code").await {
        PluginResult::Reject {
            status_code,
            body,
            headers,
        } => {
            assert_eq!(status_code, 302, "body: {body}; headers: {headers:?}");
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

#[serial_test::serial(jwks_remote_global_cache)]
#[tokio::test]
async fn same_instance_callback_still_completes_with_sealed_pending_flow() {
    let server = MockServer::start().await;
    let (_, plugin, _) = plugin_pair_for_server(&server).await;
    let challenge = issue_browser_challenge(&plugin).await;
    let private_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_private.pem");
    let id_token = create_rs256_token(&oidc_id_token_claims(&challenge), private_key_pem);
    mount_token_and_jwks(&server, &id_token).await;

    match complete_callback(&plugin, &challenge, "authorization-code").await {
        PluginResult::Reject {
            status_code,
            body,
            headers,
        } => assert_eq!(status_code, 302, "body: {body}; headers: {headers:?}"),
        other => panic!("expected same-instance success, got {other:?}"),
    }
}

#[serial_test::serial(jwks_remote_global_cache)]
#[tokio::test]
async fn callback_fixture_waits_for_delayed_jwks_before_issuing_state() {
    let server = MockServer::start().await;
    let public_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_public.pem");
    Mock::given(method("GET"))
        .and(path("/jwks"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(build_rsa_jwks_from_pem(public_key_pem))
                .set_delay(Duration::from_millis(250)),
        )
        .mount(&server)
        .await;
    let mut config = callback_config();
    config["providers"][0]["token_endpoint"] = json!(format!("{}/token", server.uri()));
    config["providers"][0]["jwks_uri"] = json!(format!("{}/jwks", server.uri()));
    let plugin = OidcRelyingParty::new(&config, PluginHttpClient::default()).unwrap();
    prepare_callback_jwks(&server).await;

    let challenge = issue_browser_challenge(&plugin).await;
    let id_token = create_rs256_token(
        &oidc_id_token_claims(&challenge),
        include_bytes!("../../../tests/fixtures/test_rsa_private.pem"),
    );
    mount_token_and_jwks(&server, &id_token).await;
    assert_callback_redirect(complete_callback(&plugin, &challenge, "authorization-code").await);
}

fn two_key_oidc_jwks() -> serde_json::Value {
    let key1 = build_rsa_jwks_from_pem_with_kid(
        include_bytes!("../../../tests/fixtures/test_rsa_public.pem"),
        "key-1",
    );
    let key2 = build_rsa_jwks_from_pem_with_kid(
        include_bytes!("../../../tests/fixtures/test_rsa_public_other.pem"),
        "key-2",
    );
    json!({
        "keys": [key1["keys"][0].clone(), key2["keys"][0].clone()]
    })
}

fn oidc_id_token_claims(challenge: &BrowserChallenge) -> serde_json::Value {
    // No iat/nbf boundary is needed by these cookie/kid tests. Keep exp far
    // beyond setup and callback work, including instrumented coverage builds.
    json!({
        "iss": "https://issuer.example.com",
        "aud": "ferrum-gateway",
        "sub": "user-1",
        "nonce": challenge.nonce.as_str(),
        "exp": chrono::Utc::now().timestamp() + 86_400,
    })
}

fn assert_invalid_id_token(result: PluginResult) {
    match result {
        PluginResult::Reject {
            status_code, body, ..
        } => {
            assert_eq!(status_code, 400);
            assert_eq!(body, r#"{"error":"Invalid ID token"}"#);
            assert!(
                !body.to_ascii_lowercase().contains("kid"),
                "generic ID token error must not echo kid"
            );
        }
        other => panic!("expected invalid ID token rejection, got {other:?}"),
    }
}

#[serial_test::serial(jwks_remote_global_cache)]
#[tokio::test]
async fn oidc_callback_rejects_id_token_without_kid() {
    let server = MockServer::start().await;
    let (_, plugin, _) = plugin_pair_for_jwks(&server, two_key_oidc_jwks()).await;
    let challenge = issue_browser_challenge(&plugin).await;
    let id_token = create_rs256_token_no_kid(
        &oidc_id_token_claims(&challenge),
        include_bytes!("../../../tests/fixtures/test_rsa_private.pem"),
    );
    mount_token_and_jwks_document(&server, two_key_oidc_jwks(), &id_token).await;
    assert_invalid_id_token(complete_callback(&plugin, &challenge, "authorization-code").await);
}

#[serial_test::serial(jwks_remote_global_cache)]
#[tokio::test]
async fn oidc_callback_rejects_unknown_kid_even_when_another_published_key_verifies() {
    let server = MockServer::start().await;
    let (_, plugin, _) = plugin_pair_for_jwks(&server, two_key_oidc_jwks()).await;
    let challenge = issue_browser_challenge(&plugin).await;
    let id_token = create_rs256_token_with_kid(
        &oidc_id_token_claims(&challenge),
        include_bytes!("../../../tests/fixtures/test_rsa_private.pem"),
        "no-such-kid",
    );
    mount_token_and_jwks_document(&server, two_key_oidc_jwks(), &id_token).await;
    assert_invalid_id_token(complete_callback(&plugin, &challenge, "authorization-code").await);
}

#[serial_test::serial(jwks_remote_global_cache)]
#[tokio::test]
async fn oidc_callback_rejects_known_kid_signed_by_a_different_published_key() {
    let server = MockServer::start().await;
    let (_, plugin, _) = plugin_pair_for_jwks(&server, two_key_oidc_jwks()).await;
    let challenge = issue_browser_challenge(&plugin).await;
    let id_token = create_rs256_token_with_kid(
        &oidc_id_token_claims(&challenge),
        include_bytes!("../../../tests/fixtures/test_rsa_private_other.pem"),
        "key-1",
    );
    mount_token_and_jwks_document(&server, two_key_oidc_jwks(), &id_token).await;
    assert_invalid_id_token(complete_callback(&plugin, &challenge, "authorization-code").await);
}

/// The relying party has no JWKS knob of its own: it consumes the shared
/// store, so an ID token naming an unknown `kid` reaches the same rate-limited
/// on-demand refetch trigger `jwks_auth` uses (issue #4508).
#[serial_test::serial(jwks_remote_global_cache)]
#[tokio::test]
async fn oidc_unknown_kid_reaches_the_shared_store_on_demand_refetch() {
    let server = MockServer::start().await;
    let (_, plugin, _) = plugin_pair_for_jwks(&server, two_key_oidc_jwks()).await;
    let jwks_uri = format!("{}/jwks", server.uri());
    let store = ferrum_edge::plugins::utils::jwks_cache::cached_store(&jwks_uri)
        .expect("the relying party shares the process-wide JWKS store");
    assert_eq!(store.kid_miss_refresh_requests(), 0);
    assert_ne!(
        store.kid_miss_cooldown(),
        std::time::Duration::ZERO,
        "the inherited shared-store cooldown must leave the refetch enabled"
    );

    let challenge = issue_browser_challenge(&plugin).await;
    let id_token = create_rs256_token_with_kid(
        &oidc_id_token_claims(&challenge),
        include_bytes!("../../../tests/fixtures/test_rsa_private.pem"),
        "rotated-kid",
    );
    mount_token_and_jwks_document(&server, two_key_oidc_jwks(), &id_token).await;
    assert_invalid_id_token(complete_callback(&plugin, &challenge, "authorization-code").await);

    assert_eq!(
        store.kid_miss_refresh_requests(),
        1,
        "an unknown kid on the OIDC path must request one out-of-band refresh"
    );
}

#[serial_test::serial(jwks_remote_global_cache)]
#[tokio::test]
async fn oidc_callback_accepts_id_token_with_matching_kid() {
    let server = MockServer::start().await;
    let (_, plugin, _) = plugin_pair_for_jwks(&server, two_key_oidc_jwks()).await;
    let challenge = issue_browser_challenge(&plugin).await;
    let id_token = create_rs256_token_with_kid(
        &oidc_id_token_claims(&challenge),
        include_bytes!("../../../tests/fixtures/test_rsa_private.pem"),
        "key-1",
    );
    mount_token_and_jwks_document(&server, two_key_oidc_jwks(), &id_token).await;
    match complete_callback(&plugin, &challenge, "authorization-code").await {
        PluginResult::Reject {
            status_code,
            body,
            headers,
        } => assert_eq!(status_code, 302, "body: {body}; headers: {headers:?}"),
        other => panic!("expected matching-kid callback success, got {other:?}"),
    }
}

#[serial_test::serial(jwks_remote_global_cache)]
#[tokio::test]
async fn cross_replica_callback_rejects_wrong_encryption_secret() {
    let server = MockServer::start().await;
    let (mut config, starter, _) = plugin_pair_for_server(&server).await;
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

#[serial_test::serial(jwks_remote_global_cache)]
#[tokio::test]
async fn cross_replica_callback_rejects_wrong_session_context() {
    let server = MockServer::start().await;
    let (mut config, starter, _) = plugin_pair_for_server(&server).await;
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

#[serial_test::serial(jwks_remote_global_cache)]
#[tokio::test]
async fn sealed_pending_flow_rejects_tampered_correlation_cookie() {
    let server = MockServer::start().await;
    let (_, plugin, _) = plugin_pair_for_server(&server).await;
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

#[serial_test::serial(jwks_remote_global_cache)]
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

#[serial_test::serial(jwks_remote_global_cache)]
#[tokio::test]
async fn same_instance_rejects_replay_after_sealed_state_is_accepted() {
    let server = MockServer::start().await;
    let (_, plugin, _) = plugin_pair_for_server(&server).await;
    let challenge = issue_browser_challenge(&plugin).await;
    let private_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_private.pem");
    let id_token = create_rs256_token(&oidc_id_token_claims(&challenge), private_key_pem);
    mount_token_and_jwks(&server, &id_token).await;

    assert_callback_redirect(complete_callback(&plugin, &challenge, "authorization-code").await);
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

#[serial_test::serial(jwks_remote_global_cache)]
#[tokio::test]
async fn provider_authorization_code_remains_one_time_across_replicas() {
    let server = MockServer::start().await;
    let public_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_public.pem");
    let private_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_private.pem");
    let mut config = callback_config();
    config["providers"][0]["token_endpoint"] = json!(format!("{}/token", server.uri()));
    config["providers"][0]["jwks_uri"] = json!(format!("{}/jwks", server.uri()));
    Mock::given(method("GET"))
        .and(path("/jwks"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(build_rsa_jwks_from_pem(public_key_pem)),
        )
        .mount(&server)
        .await;
    let starter = OidcRelyingParty::new(&config, PluginHttpClient::default()).unwrap();
    let completer = OidcRelyingParty::new(&config, PluginHttpClient::default()).unwrap();
    prepare_callback_jwks(&server).await;
    let challenge = issue_browser_challenge(&starter).await;
    let id_token = create_rs256_token(&oidc_id_token_claims(&challenge), private_key_pem);

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
        PluginResult::Reject {
            status_code,
            body,
            headers,
        } => assert_eq!(status_code, 302, "body: {body}; headers: {headers:?}"),
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

#[serial_test::serial(jwks_remote_global_cache)]
#[tokio::test]
async fn previous_encryption_secret_accepts_pending_flow_during_rotation() {
    let server = MockServer::start().await;
    let old_secret = "01234567890123456789012345678901";
    let new_secret = "abcdefghijklmnopqrstuvwxyz123456";
    let (starter_config, starter, _) = plugin_pair_for_server(&server).await;
    assert_eq!(starter_config["session"]["encryption_secret"], old_secret);
    let mut completer_config = starter_config.clone();
    completer_config["session"]["encryption_secret"] = json!(new_secret);
    completer_config["session"]["encryption_secret_previous"] = json!(old_secret);

    let completer = OidcRelyingParty::new(&completer_config, PluginHttpClient::default()).unwrap();
    let challenge = issue_browser_challenge(&starter).await;
    let private_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_private.pem");
    let id_token = create_rs256_token(&oidc_id_token_claims(&challenge), private_key_pem);
    mount_token_and_jwks(&server, &id_token).await;

    match complete_callback(&completer, &challenge, "authorization-code").await {
        PluginResult::Reject {
            status_code,
            body,
            headers,
        } => assert_eq!(status_code, 302, "body: {body}; headers: {headers:?}"),
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
#[serial_test::serial(jwks_remote_global_cache)]
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
#[serial_test::serial(jwks_remote_global_cache)]
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

/// Explicit `userinfo_endpoint` / `end_session_endpoint` fill in the two
/// optional endpoints when the discovery document omits them.
#[tokio::test]
async fn explicit_optional_endpoints_fill_discovery_gaps() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/.well-known/openid-configuration"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "authorization_endpoint": format!("{}/authorize", server.uri()),
            "token_endpoint": format!("{}/token", server.uri()),
            "jwks_uri": format!("{}/jwks", server.uri())
        })))
        .mount(&server)
        .await;

    let (userinfo, end_session) = oidc_resolve_discovery_for_test(
        &PluginHttpClient::default(),
        &format!("{}/.well-known/openid-configuration", server.uri()),
        Some("https://idp.example.com/userinfo".to_string()),
        Some("https://idp.example.com/end_session".to_string()),
    )
    .await
    .expect("discovery resolves");

    assert_eq!(
        userinfo.as_deref(),
        Some("https://idp.example.com/userinfo")
    );
    assert_eq!(
        end_session.as_deref(),
        Some("https://idp.example.com/end_session")
    );
}

/// Explicitly configured optional endpoints win over the values the discovery
/// document advertises.
#[tokio::test]
async fn explicit_optional_endpoints_override_discovered_values() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/.well-known/openid-configuration"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "authorization_endpoint": format!("{}/authorize", server.uri()),
            "token_endpoint": format!("{}/token", server.uri()),
            "jwks_uri": format!("{}/jwks", server.uri()),
            "userinfo_endpoint": format!("{}/userinfo", server.uri()),
            "end_session_endpoint": format!("{}/end_session", server.uri())
        })))
        .mount(&server)
        .await;

    let (userinfo, end_session) = oidc_resolve_discovery_for_test(
        &PluginHttpClient::default(),
        &format!("{}/.well-known/openid-configuration", server.uri()),
        Some("https://explicit.example.com/userinfo".to_string()),
        Some("https://explicit.example.com/end_session".to_string()),
    )
    .await
    .expect("discovery resolves");

    assert_eq!(
        userinfo.as_deref(),
        Some("https://explicit.example.com/userinfo")
    );
    assert_eq!(
        end_session.as_deref(),
        Some("https://explicit.example.com/end_session")
    );
}

/// With no explicit overrides, the discovery document's advertised optional
/// endpoints are used unchanged.
#[tokio::test]
async fn discovered_optional_endpoints_used_without_overrides() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/.well-known/openid-configuration"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "authorization_endpoint": format!("{}/authorize", server.uri()),
            "token_endpoint": format!("{}/token", server.uri()),
            "jwks_uri": format!("{}/jwks", server.uri()),
            "userinfo_endpoint": format!("{}/userinfo", server.uri()),
            "end_session_endpoint": format!("{}/end_session", server.uri())
        })))
        .mount(&server)
        .await;

    let (userinfo, end_session) = oidc_resolve_discovery_for_test(
        &PluginHttpClient::default(),
        &format!("{}/.well-known/openid-configuration", server.uri()),
        None,
        None,
    )
    .await
    .expect("discovery resolves");

    let expected_userinfo = format!("{}/userinfo", server.uri());
    let expected_end_session = format!("{}/end_session", server.uri());
    assert_eq!(userinfo.as_deref(), Some(expected_userinfo.as_str()));
    assert_eq!(end_session.as_deref(), Some(expected_end_session.as_str()));
}

/// A config with `discovery_url` plus explicit optional endpoints must retain
/// them in the resolved discovery document, even when the provider's discovery
/// document omits both fields.
#[serial_test::serial(jwks_remote_global_cache)]
#[tokio::test]
async fn discovery_config_retains_explicit_optional_endpoints() {
    use ferrum_edge::plugins::utils::jwks_cache::clear_jwks_cache;

    let public_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_public.pem");
    let server = MockServer::start().await;
    let jwks_uri = format!("{}/oidc-overrides/jwks.json", server.uri());
    Mock::given(method("GET"))
        .and(path("/oidc-overrides/jwks.json"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(build_rsa_jwks_from_pem(public_key_pem)),
        )
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/oidc-overrides/openid-configuration"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "authorization_endpoint": format!("{}/oidc-overrides/authorize", server.uri()),
            "token_endpoint": format!("{}/oidc-overrides/token", server.uri()),
            "jwks_uri": jwks_uri,
        })))
        .mount(&server)
        .await;

    let _guard = super::jwks_cache_tests::cache_test_lock().lock().await;
    clear_jwks_cache();

    let mut config = base_config();
    config["providers"][0] = json!({
        "issuer": "https://issuer.example.com",
        "discovery_url": format!("{}/oidc-overrides/openid-configuration", server.uri()),
        "userinfo_endpoint": "https://issuer.example.com/userinfo",
        "end_session_endpoint": "https://issuer.example.com/end_session",
        "client_id": "ferrum-gateway",
        "client_auth": {"method": "client_secret_basic", "client_secret": "secret"},
        "scopes": ["openid", "profile"],
        "redirect_uri": "https://app.example.com/oauth/callback",
        "callback_path": "/oauth/callback",
        "logout_path": "/oauth/logout"
    });
    let plugin = OidcRelyingParty::new(&config, PluginHttpClient::default())
        .expect("discovery config with explicit optional endpoints is valid");

    let (userinfo, end_session) = oidc_resolved_discovery_endpoints_for_test(plugin)
        .await
        .expect("discovery task resolved a document");

    assert_eq!(
        userinfo.as_deref(),
        Some("https://issuer.example.com/userinfo")
    );
    assert_eq!(
        end_session.as_deref(),
        Some("https://issuer.example.com/end_session")
    );

    clear_jwks_cache();
}

#[tokio::test]
async fn generated_session_cookies_enforce_prefix_attributes_and_allow_explicit_names() {
    // A cookie prefix is only legal when the emitted attributes satisfy it:
    // `__Secure-` requires `Secure`, and `__Host-` additionally requires no
    // `Domain` and `Path=/`. A prefix a browser would reject is worse than none.
    for (secure, domain, path, explicit_name, expected_prefix) in [
        (true, None, "/", None, "__Host-ferrum_session_"),
        (
            true,
            Some("example.com"),
            "/",
            None,
            "__Secure-ferrum_session_",
        ),
        (true, None, "/app", None, "__Secure-ferrum_session_"),
        (false, None, "/", None, "ferrum_session_"),
        (false, Some("example.com"), "/", None, "ferrum_session_"),
        (false, None, "/app", None, "ferrum_session_"),
        (true, None, "/", Some("custom_session"), "custom_session="),
        (false, None, "/", Some("custom_session"), "custom_session="),
    ] {
        let mut config = base_config();
        config["session"]
            .as_object_mut()
            .unwrap()
            .remove("cookie_name");
        config["session"]["path"] = json!(path);
        config["session"]["secure"] = json!(secure);
        if let Some(domain) = domain {
            config["session"]["domain"] = json!(domain);
        }
        if let Some(name) = explicit_name {
            config["session"]["cookie_name"] = json!(name);
        }
        let plugin = OidcRelyingParty::new(&config, PluginHttpClient::default()).unwrap();
        let cookie =
            oidc_sealed_session_cookie_for_test(&plugin, json!({"sub": "alice"}), false).unwrap();
        assert!(cookie.starts_with(expected_prefix), "{cookie}");
        assert_eq!(cookie_attribute(&cookie, "path"), Some(Some(path)));
        assert_eq!(cookie_attribute(&cookie, "domain"), domain.map(Some));
        assert_eq!(
            cookie_attribute(&cookie, "secure"),
            secure.then_some(None),
            "{cookie}"
        );

        // Secure correlation cookies use browser-enforced host-only scope;
        // insecure loopback development retains callback-path scoping.
        let challenge = issue_browser_challenge(&plugin).await;
        if secure {
            assert_host_only_correlation_cookie(&challenge.cookie, "600");
        } else {
            assert!(
                cookie_name(&challenge.cookie).starts_with("ferrum_oidc_state_"),
                "{}",
                challenge.cookie
            );
            assert_eq!(cookie_attribute(&challenge.cookie, "domain"), None);
            assert_eq!(
                cookie_attribute(&challenge.cookie, "path"),
                Some(Some("/oauth/callback"))
            );
            assert_eq!(cookie_attribute(&challenge.cookie, "secure"), None);
            assert_eq!(cookie_attribute(&challenge.cookie, "httponly"), Some(None));
        }
    }
}

#[tokio::test]
async fn root_scoped_secure_correlation_cookie_uses_the_host_prefix() {
    let mut config = base_config();
    config["providers"][0]["redirect_uri"] = json!("https://app.example.com/");
    config["providers"][0]["callback_path"] = json!("/");
    let plugin = OidcRelyingParty::new(&config, PluginHttpClient::default()).unwrap();
    let challenge = issue_browser_challenge(&plugin).await;

    assert!(
        cookie_name(&challenge.cookie).starts_with("__Host-ferrum_oidc_state_"),
        "{}",
        challenge.cookie
    );
    assert_eq!(cookie_attribute(&challenge.cookie, "domain"), None);
    assert_eq!(cookie_attribute(&challenge.cookie, "path"), Some(Some("/")));
    assert_eq!(cookie_attribute(&challenge.cookie, "secure"), Some(None));
    assert_eq!(cookie_attribute(&challenge.cookie, "httponly"), Some(None));
}

#[tokio::test]
async fn logout_requires_a_sealed_session_and_encodes_the_id_token_hint() {
    for post_logout_uri in [None, Some("https://app.example.com/goodbye")] {
        let mut config = base_config();
        config["providers"][0]["end_session_endpoint"] =
            json!("https://issuer.example.com/logout?existing=keep");
        if let Some(uri) = post_logout_uri {
            config["providers"][0]["post_logout_redirect_uri"] = json!(uri);
        }
        let plugin = OidcRelyingParty::new(&config, PluginHttpClient::default()).unwrap();
        let cookie =
            oidc_sealed_session_cookie_for_test(&plugin, json!({"sub": "alice"}), false).unwrap();
        for session in [
            None,
            Some("ferrum_session=tampered"),
            Some(cookie_pair(&cookie)),
        ] {
            let mut ctx = html_ctx();
            ctx.path = "/oauth/logout".to_string();
            if let Some(session) = session {
                ctx.headers
                    .insert("cookie".to_string(), session.to_string());
            }
            let PluginResult::Reject {
                status_code,
                body,
                headers,
            } = plugin.on_request_received(&mut ctx).await
            else {
                panic!("logout must terminate locally");
            };
            assert_eq!(
                cookie_attribute(&headers["set-cookie"], "max-age"),
                Some(Some("0"))
            );
            if session == Some(cookie_pair(&cookie)) {
                assert_eq!(status_code, 302);
                let location = Url::parse(&headers["location"]).unwrap();
                let query: HashMap<_, _> = location.query_pairs().into_owned().collect();
                assert_eq!(query["id_token_hint"], "test-id-token");
                assert_eq!(query["client_id"], "ferrum-gateway");
                assert_eq!(query["existing"], "keep");
                assert_eq!(
                    query.get("post_logout_redirect_uri").map(String::as_str),
                    post_logout_uri
                );
            } else {
                assert_eq!(status_code, 200);
                assert!(body.contains("Logged out"));
                assert!(!headers.contains_key("location"));
            }
        }
    }
}

#[tokio::test]
async fn logout_revokes_discovered_refresh_tokens_with_best_effort_client_auth() {
    for (status, delay_secs) in [(200, 0), (503, 0), (200, 6)] {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/discovery"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "authorization_endpoint": format!("{}/authorize", server.uri()),
                "token_endpoint": format!("{}/token", server.uri()),
                "jwks_uri": format!("{}/jwks", server.uri()),
                "end_session_endpoint": format!("{}/logout", server.uri()),
                "revocation_endpoint": format!("{}/revoke", server.uri()),
            })))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/revoke"))
            .and(basic_auth("ferrum-gateway", "secret"))
            .and(body_string_contains("token=refresh%2Btoken"))
            .and(body_string_contains("token_type_hint=refresh_token"))
            .respond_with(ResponseTemplate::new(status).set_delay(Duration::from_secs(delay_secs)))
            .expect(1)
            .mount(&server)
            .await;
        let mut config = base_config();
        let provider = config["providers"][0].as_object_mut().unwrap();
        for key in ["authorization_endpoint", "token_endpoint", "jwks_uri"] {
            provider.remove(key);
        }
        provider.insert(
            "discovery_url".to_string(),
            json!(format!("{}/discovery", server.uri())),
        );
        let plugin = OidcRelyingParty::new(&config, PluginHttpClient::default()).unwrap();
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let mut ctx = html_ctx();
                if matches!(
                    plugin
                        .authenticate(&mut ctx, &ConsumerIndex::new(&[]))
                        .await,
                    PluginResult::Reject {
                        status_code: 302,
                        ..
                    }
                ) {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("discovery must become ready");
        let cookie = oidc_sealed_due_refresh_session_cookie_for_test(
            &plugin,
            json!({"sub": "alice"}),
            "refresh+token",
        )
        .unwrap();
        let mut ctx = html_ctx();
        ctx.path = "/oauth/logout".to_string();
        ctx.headers
            .insert("cookie".to_string(), cookie_pair(&cookie).to_string());
        let PluginResult::Reject {
            status_code,
            headers,
            ..
        } = tokio::time::timeout(
            Duration::from_millis(5500),
            plugin.on_request_received(&mut ctx),
        )
        .await
        .expect("revocation must not exceed its five-second bound")
        else {
            panic!("logout must terminate locally");
        };
        assert_eq!(status_code, 302);
        let location = Url::parse(&headers["location"]).unwrap();
        assert!(
            location
                .query_pairs()
                .any(|(key, value)| key == "id_token_hint" && value == "test-id-token")
        );
        server.verify().await;
    }
}

#[tokio::test]
async fn discovery_rejects_untrusted_revocation_endpoints() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/discovery"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "authorization_endpoint": format!("{}/authorize", server.uri()),
            "token_endpoint": format!("{}/token", server.uri()),
            "jwks_uri": format!("{}/jwks", server.uri()),
            "revocation_endpoint": "https://untrusted.example.com/revoke",
        })))
        .mount(&server)
        .await;
    assert!(
        oidc_resolve_discovery_for_test(
            &PluginHttpClient::default(),
            &format!("{}/discovery", server.uri()),
            None,
            None,
        )
        .await
        .is_err()
    );
}

/// `ferrum-edge validate` runs the shared plugin-composition gate synchronously,
/// with no Tokio reactor on the calling thread. That gate constructs every
/// security-composition candidate, so a valid enabled OIDC plugin used to abort
/// the CLI with "there is no reactor running" for a configuration that starts
/// cleanly under `run` (issue #5024).
///
/// This is deliberately a plain `#[test]`: a regression that reintroduces
/// `tokio::spawn` during admission panics here instead of passing under a
/// runtime the CLI never has.
#[test]
fn cli_config_validation_admits_oidc_without_a_tokio_runtime() {
    for (case, provider) in [
        (
            "discovery",
            json!({
                "issuer": "https://issuer.example.com",
                "discovery_url": "https://issuer.example.com/.well-known/openid-configuration",
                "client_id": "ferrum-gateway",
                "client_auth": {"client_secret": "0123456789abcdef"},
                "redirect_uri": "https://app.example.com/oauth/callback",
                "scopes": ["openid"]
            }),
        ),
        (
            "explicit",
            json!({
                "issuer": "https://issuer.example.com",
                "authorization_endpoint": "https://issuer.example.com/authorize",
                "token_endpoint": "https://issuer.example.com/token",
                "jwks_uri": "https://issuer.example.com/jwks",
                "client_id": "ferrum-gateway",
                "client_auth": {"client_secret": "0123456789abcdef"},
                "redirect_uri": "https://app.example.com/oauth/callback",
                "scopes": ["openid"]
            }),
        ),
    ] {
        let config = GatewayConfig {
            plugin_configs: vec![PluginConfig {
                id: format!("oidc-{case}"),
                plugin_name: "oidc_relying_party".to_string(),
                namespace: "default".to_string(),
                config: json!({
                    "providers": [provider],
                    "session": {"encryption_secret": "01234567890123456789012345678901"}
                }),
                scope: PluginScope::Global,
                proxy_id: None,
                enabled: true,
                priority_override: None,
                trigger: None,
                api_spec_id: None,
                created_at: Utc::now(),
                updated_at: Utc::now(),
            }],
            ..GatewayConfig::default()
        };

        let errors =
            ferrum_edge::_test_support::collect_rejecting_runtime_config_errors_for_test(&config);
        assert!(
            errors.is_empty(),
            "{case} endpoints must validate without a runtime: {errors:?}"
        );
    }
}

/// Session lifetimes are added to a Unix timestamp on every authenticated
/// request, so an unrepresentable `u64` must be refused at admission rather
/// than overflowing that addition later (issue #5028).
#[test]
fn new_rejects_session_lifetimes_that_cannot_take_part_in_timestamp_arithmetic() {
    const MAX_SESSION_TTL_SECS: u64 = 365 * 24 * 60 * 60;
    for field in ["ttl_secs", "idle_ttl_secs"] {
        for value in [json!(0), json!(MAX_SESSION_TTL_SECS + 1), json!(u64::MAX)] {
            let mut config = base_config();
            config["session"][field] = value.clone();
            let error = OidcRelyingParty::new(&config, PluginHttpClient::default())
                .err()
                .unwrap_or_else(|| panic!("session.{field}={value} must be rejected"));
            assert!(
                error.contains(&format!("session.{field}")),
                "unexpected error for session.{field}={value}: {error}"
            );
        }

        // The largest representable value is still accepted.
        let mut config = base_config();
        config["session"][field] = json!(MAX_SESSION_TTL_SECS);
        config["behavior"]["refresh_skew_secs"] = json!(1);
        assert!(
            validate_plugin_config("oidc_relying_party", &config).is_ok(),
            "session.{field}={MAX_SESSION_TTL_SECS} must remain accepted"
        );
    }
}

/// `id_token_clock_skew_secs` is leeway added to every claims-expiry
/// comparison; an unbounded value has the same overflow reach (issue #5028).
#[test]
fn new_rejects_unbounded_id_token_clock_skew() {
    let mut config = base_config();
    config["providers"][0]["id_token_clock_skew_secs"] = json!(3601);
    let error = OidcRelyingParty::new(&config, PluginHttpClient::default())
        .err()
        .expect("an hour-plus clock skew must be rejected");
    assert!(
        error.contains("id_token_clock_skew_secs"),
        "unexpected error: {error}"
    );

    let mut config = base_config();
    config["providers"][0]["id_token_clock_skew_secs"] = json!(3600);
    assert!(validate_plugin_config("oidc_relying_party", &config).is_ok());
}

/// A hostile or buggy provider controls `expires_in` outright. Neither an
/// absurd nor a negative duration may reach the unchecked timestamp addition
/// that used to panic the request path (issue #5028).
#[tokio::test]
async fn unrepresentable_provider_expires_in_does_not_panic_the_session_path() {
    for expires_in in [json!(i64::MAX), json!(-1)] {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "access_token": "rotated-access-token",
                "token_type": "Bearer",
                "refresh_token": "rotated-refresh-token",
                "expires_in": expires_in
            })))
            .mount(&server)
            .await;

        let plugin = OidcRelyingParty::new(
            &refresh_config(&format!("{}/token", server.uri())),
            PluginHttpClient::default(),
        )
        .expect("refresh plugin");
        let now = chrono::Utc::now().timestamp();
        let cookie = oidc_sealed_due_refresh_session_cookie_for_test(
            &plugin,
            json!({
                "sub": "oidc-subject",
                "email": "alice@example.test",
                "exp": now + 3600
            }),
            "original-refresh-token",
        )
        .expect("session seals");
        let mut ctx = ctx_with_session_cookie(&cookie);

        // Completing the request at all is the assertion: the unchecked
        // addition used to abort the worker with "attempt to add with overflow".
        let consumers = ConsumerIndex::new(&[]);
        assert_continue(plugin.authenticate(&mut ctx, &consumers).await);
    }
}

/// A spent refresh token must suppress the sliding-idle cookie too. The
/// documented multi-replica contract is that the `invalid_grant` loser emits no
/// `Set-Cookie` at all; before issue #5025 an ordinary active-browser request
/// whose idle window happened to be due re-sealed and published the already
/// spent credential, overwriting the winner's rotated cookie.
#[tokio::test]
async fn spent_refresh_token_suppresses_the_rolling_idle_cookie() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({"error": "invalid_grant"})))
        .expect(1)
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
        Some("spent-refresh-token".to_string()),
        // Both refresh AND the idle slide are due on this request.
        true,
        true,
    )
    .expect("session seals");
    let consumer_index = ConsumerIndex::new(&[]);

    let mut first = session_ctx(&cookie);
    assert_continue(plugin.authenticate(&mut first, &consumer_index).await);
    assert!(
        rolling_cookie(&plugin, &mut first).await.is_none(),
        "an idle slide must not publish a spent refresh token"
    );

    // The cached SpentCredential follower takes the same branch without a
    // second grant.
    let mut repeated = session_ctx(&cookie);
    assert_continue(plugin.authenticate(&mut repeated, &consumer_index).await);
    assert!(
        rolling_cookie(&plugin, &mut repeated).await.is_none(),
        "a cached spent-credential follower must not publish a cookie either"
    );
    assert_eq!(server.received_requests().await.expect("requests").len(), 1);
}

/// RFC 6749 §2.3.1 requires `client_secret_basic` to form-url-encode the client
/// identifier and secret BEFORE the HTTP Basic encoding. Feeding the raw values
/// to a generic Basic encoder made every token, refresh, and revocation POST
/// fail against a conforming provider whenever a credential contained `:`, `+`,
/// a space, or a non-ASCII character (issue #5026).
#[tokio::test]
async fn client_secret_basic_form_encodes_credentials_before_basic_encoding() {
    // base64("audit%3Aclient+%2B:p%2Bss%3Aword+%2F") — the RFC 6749 §2.3.1 form.
    const EXPECTED: &str = "Basic YXVkaXQlM0FjbGllbnQrJTJCOnAlMkJzcyUzQXdvcmQrJTJG";

    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .and(header("authorization", EXPECTED))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "rotated-access-token",
            "token_type": "Bearer",
            "refresh_token": "rotated-refresh-token",
            "expires_in": 3600
        })))
        .expect(1)
        .mount(&server)
        .await;

    let mut config = refresh_config(&format!("{}/token", server.uri()));
    config["providers"][0]["client_id"] = json!("audit:client +");
    config["providers"][0]["client_auth"] = json!({
        "method": "client_secret_basic",
        "client_secret": "p+ss:word /"
    });
    let plugin =
        OidcRelyingParty::new(&config, PluginHttpClient::default()).expect("valid refresh config");
    let now = chrono::Utc::now().timestamp();
    let cookie = oidc_sealed_due_refresh_session_cookie_for_test(
        &plugin,
        json!({
            "sub": "oidc-subject",
            "email": "alice@example.test",
            "exp": now + 3600
        }),
        "original-refresh-token",
    )
    .expect("session seals");
    let mut ctx = session_ctx(&cookie);

    let consumers = ConsumerIndex::new(&[]);
    assert_continue(plugin.authenticate(&mut ctx, &consumers).await);
    let set_cookie = rolling_cookie(&plugin, &mut ctx)
        .await
        .expect("a punctuation-bearing client secret must still authenticate the grant");
    let state = oidc_session_state_from_set_cookie_for_test(&plugin, &set_cookie)
        .expect("rotated session cookie must open");
    assert_eq!(state.access_token, "rotated-access-token");
    server.verify().await;
}

/// `session.cookie_name`, `session.path`, and `session.domain` are concatenated
/// into `Set-Cookie` verbatim, so a delimiter or control character injects an
/// attribute instead of producing a cookie the browser merely ignores. The
/// demonstrated case put `;` into `session.path` and appended `Max-Age=0`,
/// deleting every session the gateway issued (issue #5027).
#[test]
fn new_rejects_cookie_names_paths_and_domains_that_are_not_cookie_syntax() {
    for (field, value) in [
        ("cookie_name", json!("bad;cookie")),
        ("cookie_name", json!("bad\r\ncookie")),
        ("cookie_name", json!("bad cookie")),
        ("cookie_name", json!("bad=cookie")),
        ("cookie_name", json!("ünicode")),
        ("path", json!("/; Max-Age=0")),
        ("path", json!("relative")),
        ("path", json!("/tab\there")),
        ("domain", json!("https://example.test")),
        ("domain", json!("example.test; Max-Age=0")),
        ("domain", json!("example.test:8443")),
        ("domain", json!("example..test")),
        ("domain", json!("example.test.")),
    ] {
        let mut config = base_config();
        config["session"][field] = value.clone();
        let error = validate_plugin_config("oidc_relying_party", &config)
            .err()
            .unwrap_or_else(|| panic!("session.{field}={value} must be rejected"));
        assert!(
            error.contains(&format!("session.{field}")),
            "unexpected error for session.{field}={value}: {error}"
        );
    }

    // Valid explicit values stay supported.
    for (field, value) in [
        ("cookie_name", json!("custom_session")),
        ("path", json!("/app")),
        ("domain", json!(".example.test")),
    ] {
        let mut config = base_config();
        config["session"][field] = value.clone();
        assert!(
            validate_plugin_config("oidc_relying_party", &config).is_ok(),
            "session.{field}={value} must remain accepted"
        );
    }
}

/// A browser silently discards a `__Host-`/`__Secure-` cookie whose attributes
/// violate the prefix rules, so admitting the combination produces a login loop
/// with no gateway-side signal (issue #5027).
#[test]
fn new_rejects_explicit_cookie_prefixes_that_contradict_their_attributes() {
    for (name, secure, domain, path) in [
        ("__Host-invalid", false, None, "/"),
        ("__Host-invalid", true, Some("example.test"), "/"),
        ("__Host-invalid", true, None, "/app"),
        ("__Secure-invalid", false, None, "/"),
    ] {
        let mut config = base_config();
        config["session"]["cookie_name"] = json!(name);
        config["session"]["secure"] = json!(secure);
        config["session"]["path"] = json!(path);
        if let Some(domain) = domain {
            config["session"]["domain"] = json!(domain);
        }
        let error = validate_plugin_config("oidc_relying_party", &config)
            .err()
            .unwrap_or_else(|| panic!("{name} must be rejected for secure={secure}"));
        assert!(error.contains("cookie_name"), "unexpected error: {error}");
    }

    let mut config = base_config();
    config["session"]["cookie_name"] = json!("__Host-valid");
    config["session"]["secure"] = json!(true);
    assert!(validate_plugin_config("oidc_relying_party", &config).is_ok());
}

/// `providers[].callback_path` becomes the correlation cookie's `Path`
/// attribute, so it carries the same delimiter rules (issue #5027).
#[test]
fn new_rejects_callback_and_logout_paths_that_are_not_cookie_paths() {
    for field in ["callback_path", "logout_path"] {
        let mut config = base_config();
        config["providers"][0][field] = json!("/oauth/x;Max-Age=0");
        let error = validate_plugin_config("oidc_relying_party", &config)
            .err()
            .unwrap_or_else(|| panic!("provider[0].{field} must be rejected"));
        assert!(error.contains(field), "unexpected error: {error}");
    }
}

/// `session.max_cookie_bytes` had an upper bound but no usable lower bound, so
/// `0` started a fail-closed authentication plugin whose browser challenge can
/// never seal even its own pending flow: every login answered 503 (issue #5029).
#[test]
fn new_rejects_cookie_size_caps_that_cannot_seal_a_pending_flow() {
    for value in [json!(0), json!(1), json!(1023)] {
        let mut config = base_config();
        config["session"]["max_cookie_bytes"] = value.clone();
        let error = validate_plugin_config("oidc_relying_party", &config)
            .err()
            .unwrap_or_else(|| panic!("max_cookie_bytes={value} must be rejected"));
        assert!(
            error.contains("max_cookie_bytes"),
            "unexpected error for max_cookie_bytes={value}: {error}"
        );
    }

    for value in [json!(1024), json!(8000)] {
        let mut config = base_config();
        config["session"]["max_cookie_bytes"] = value.clone();
        assert!(
            validate_plugin_config("oidc_relying_party", &config).is_ok(),
            "max_cookie_bytes={value} must remain accepted"
        );
    }
}

/// The documented minimum must actually be able to start a login, not merely
/// pass admission (issue #5029).
#[tokio::test]
async fn minimum_cookie_size_cap_can_still_seal_a_browser_challenge() {
    let mut config = base_config();
    config["session"]["max_cookie_bytes"] = json!(1024);
    let plugin = OidcRelyingParty::new(&config, PluginHttpClient::default())
        .expect("the documented minimum must be accepted");
    let mut ctx = html_ctx();
    let PluginResult::Reject {
        status_code,
        headers,
        ..
    } = plugin
        .authenticate(&mut ctx, &ConsumerIndex::new(&[]))
        .await
    else {
        panic!("a browser request without a session must be challenged");
    };
    assert_eq!(status_code, 302, "headers: {headers:?}");
    assert!(headers.contains_key("set-cookie"));
}

/// `on_request_received` checks the callback branch before the logout branch,
/// so a `logout_path` that routing delivers as the callback path makes logout
/// unreachable: it answers "Missing state" and the configured handler never
/// runs (issue #5030).
#[test]
fn new_rejects_logout_paths_that_collide_with_the_callback_path() {
    for logout_path in ["/oauth/callback", "/oauth/callback/", "/oauth//callback"] {
        let mut config = base_config();
        config["providers"][0]["logout_path"] = json!(logout_path);
        let error = validate_plugin_config("oidc_relying_party", &config)
            .err()
            .unwrap_or_else(|| panic!("logout_path={logout_path} must be rejected"));
        assert!(
            error.contains("logout_path"),
            "unexpected error for logout_path={logout_path}: {error}"
        );
    }
}

/// Every accepted `logout_path` must actually reach local cookie deletion
/// (issue #5030).
#[tokio::test]
async fn accepted_logout_paths_reach_local_cookie_deletion() {
    let mut config = base_config();
    config["providers"][0]["logout_path"] = json!("/oauth/sign-out");
    let plugin = OidcRelyingParty::new(&config, PluginHttpClient::default()).expect("valid config");
    let mut ctx = html_ctx();
    ctx.path = "/oauth/sign-out".to_string();
    let PluginResult::Reject {
        status_code,
        headers,
        ..
    } = plugin.on_request_received(&mut ctx).await
    else {
        panic!("logout must terminate locally");
    };
    assert_eq!(status_code, 200);
    assert!(
        headers
            .get("set-cookie")
            .is_some_and(|cookie| cookie.contains("Max-Age=0")),
        "logout must expire the session cookie: {headers:?}"
    );
}

/// RFC 6749 §3.1.2 forbids a fragment on the redirection endpoint: a lenient
/// provider appends the authorization response query after it, so the browser
/// never transmits `state`/`code` and every callback fails (issue #5031).
#[test]
fn new_rejects_redirect_uris_carrying_a_fragment() {
    for redirect_uri in [
        "https://app.example.com/oauth/callback#fragment",
        "https://app.example.com/oauth/callback#",
    ] {
        let mut config = base_config();
        config["providers"][0]["redirect_uri"] = json!(redirect_uri);
        let error = validate_plugin_config("oidc_relying_party", &config)
            .err()
            .unwrap_or_else(|| panic!("{redirect_uri} must be rejected"));
        assert!(error.contains("redirect_uri"), "unexpected error: {error}");
    }

    // A fixed query component stays supported: it is not a fragment, and the
    // provider appends the response parameters after it.
    let mut config = base_config();
    config["providers"][0]["redirect_uri"] =
        json!("https://app.example.com/oauth/callback?rp=edge");
    assert!(validate_plugin_config("oidc_relying_party", &config).is_ok());
}

/// `EncodingKey::from_ec_pem` only proves the PEM is a well-formed EC key, not
/// that its curve matches the selected algorithm. An ES256 client with a P-384
/// key started cleanly and then failed to sign the first client assertion —
/// after the browser's one-time authorization code had already been consumed
/// and with the token endpoint never contacted (issue #5032).
#[test]
fn private_key_jwt_requires_a_key_that_supports_the_selected_algorithm() {
    let p256 = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
        .expect("P-256 key")
        .serialize_pem();
    let p384 = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384)
        .expect("P-384 key")
        .serialize_pem();
    let rsa = rcgen::KeyPair::generate_for(&rcgen::PKCS_RSA_SHA256)
        .expect("RSA key")
        .serialize_pem();
    let ed25519 = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519)
        .expect("Ed25519 key")
        .serialize_pem();

    let config_for = |alg: &str, pem: &str| {
        let mut config = base_config();
        config["providers"][0]["client_auth"] = json!({
            "method": "private_key_jwt",
            "private_key_jwt_alg": alg,
            "private_key_pem": pem
        });
        config
    };

    for (alg, pem, label) in [
        ("ES256", &p384, "ES256 with a P-384 key"),
        ("ES384", &p256, "ES384 with a P-256 key"),
    ] {
        let error = validate_plugin_config("oidc_relying_party", &config_for(alg, pem))
            .err()
            .unwrap_or_else(|| panic!("{label} must be rejected"));
        assert!(
            error.contains("private_key"),
            "unexpected error for {label}: {error}"
        );
    }

    for (alg, pem, label) in [
        ("ES256", &p256, "ES256 with a P-256 key"),
        ("ES384", &p384, "ES384 with a P-384 key"),
        ("RS256", &rsa, "RS256 with an RSA key"),
        ("EdDSA", &ed25519, "EdDSA with an Ed25519 key"),
    ] {
        assert!(
            validate_plugin_config("oidc_relying_party", &config_for(alg, pem)).is_ok(),
            "{label} must remain accepted"
        );
    }
}

/// An explicit optional endpoint replaces the advertised value outright, so an
/// advertisement this deployment will never call must not fail the whole
/// discovery fetch. Validating it first made a valid explicit override unusable
/// and left every login answering 503 (issue #5033).
#[tokio::test]
async fn cross_origin_advertisements_do_not_block_their_explicit_overrides() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/discovery"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "authorization_endpoint": format!("{}/authorize", server.uri()),
            "token_endpoint": format!("{}/token", server.uri()),
            "jwks_uri": format!("{}/jwks", server.uri()),
            // Advertised on a different origin than discovery_url, and never
            // called because both are explicitly overridden below.
            "userinfo_endpoint": "https://elsewhere.example.com/userinfo",
            "end_session_endpoint": "https://elsewhere.example.com/end_session",
        })))
        .mount(&server)
        .await;

    let (userinfo, end_session) = oidc_resolve_discovery_for_test(
        &PluginHttpClient::default(),
        &format!("{}/discovery", server.uri()),
        Some("https://issuer.example.com/userinfo".to_string()),
        Some("https://issuer.example.com/end_session".to_string()),
    )
    .await
    .expect("a discarded advertisement must not fail discovery");
    assert_eq!(
        userinfo.as_deref(),
        Some("https://issuer.example.com/userinfo")
    );
    assert_eq!(
        end_session.as_deref(),
        Some("https://issuer.example.com/end_session")
    );
}

/// A selected discovered optional endpoint keeps its fail-closed same-origin
/// validation: only the discarded advertisement is skipped (issue #5033).
#[tokio::test]
async fn selected_discovered_optional_endpoints_stay_fail_closed() {
    for field in ["userinfo_endpoint", "end_session_endpoint"] {
        let server = MockServer::start().await;
        let mut document = json!({
            "authorization_endpoint": format!("{}/authorize", server.uri()),
            "token_endpoint": format!("{}/token", server.uri()),
            "jwks_uri": format!("{}/jwks", server.uri()),
        });
        document[field] = json!("https://elsewhere.example.com/endpoint");
        Mock::given(method("GET"))
            .and(path("/discovery"))
            .respond_with(ResponseTemplate::new(200).set_body_json(document))
            .mount(&server)
            .await;

        assert!(
            oidc_resolve_discovery_for_test(
                &PluginHttpClient::default(),
                &format!("{}/discovery", server.uri()),
                None,
                None,
            )
            .await
            .is_err(),
            "a selected cross-origin {field} must still fail closed"
        );
    }
}

/// The sealed gateway session cookie is a complete, replayable credential.
/// Encryption hides its contents from a backend but does nothing to stop that
/// backend from presenting the captured value to any other route governed by
/// the same OIDC policy. It must not reach the upstream at all, while unrelated
/// application cookies are preserved untouched (GHSA-75w5-f79c-7697).
#[tokio::test]
async fn the_gateway_session_cookie_is_hidden_from_the_backend_by_default() {
    let plugin = OidcRelyingParty::new(&base_config(), PluginHttpClient::default())
        .expect("valid oidc config");
    let challenge = issue_browser_challenge(&plugin).await;
    let correlation_pair = cookie_pair(&challenge.cookie);
    let sealed = oidc_sealed_session_cookie_for_test(&plugin, json!({"sub": "alice"}), false)
        .expect("session seals");
    let session_pair = cookie_pair(&sealed);

    for header_name in ["cookie", "Cookie"] {
        let mut ctx = html_ctx();
        let mut headers = HashMap::new();
        headers.insert(
            header_name.to_string(),
            format!("theme=dark; {session_pair}; {correlation_pair}; cart=7"),
        );
        assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
        let forwarded = headers
            .get(header_name)
            .expect("unrelated cookies must survive");
        assert_eq!(forwarded, "theme=dark; cart=7");
    }

    // A header that carried only this plugin's cookies is removed outright
    // rather than forwarded empty.
    let mut ctx = html_ctx();
    let mut headers = HashMap::new();
    headers.insert("cookie".to_string(), session_pair.to_string());
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
    assert!(!headers.contains_key("cookie"));
}

/// The strip does not depend on the credential having been accepted: a
/// tampered, expired, or wrong-context cookie is still a value the backend must
/// not receive (GHSA-75w5-f79c-7697).
#[tokio::test]
async fn an_unusable_gateway_session_cookie_is_hidden_too() {
    let plugin = OidcRelyingParty::new(&base_config(), PluginHttpClient::default())
        .expect("valid oidc config");
    let mut ctx = html_ctx();
    let mut headers = HashMap::new();
    headers.insert(
        "cookie".to_string(),
        "ferrum_session=not-a-sealed-value; theme=dark".to_string(),
    );
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
    let forwarded = headers.get("cookie").map(String::as_str);
    assert_eq!(forwarded, Some("theme=dark"));
}

/// Passthrough remains available, but only as an explicit opt-in
/// (GHSA-75w5-f79c-7697).
#[tokio::test]
async fn session_cookie_passthrough_requires_an_explicit_opt_in() {
    let mut config = base_config();
    config["session"]["hide_session_cookie"] = json!(false);
    let plugin =
        OidcRelyingParty::new(&config, PluginHttpClient::default()).expect("valid oidc config");
    let sealed = oidc_sealed_session_cookie_for_test(&plugin, json!({"sub": "alice"}), false)
        .expect("session seals");
    let session_pair = cookie_pair(&sealed);

    let forwarded = format!("theme=dark; {session_pair}");
    let mut ctx = html_ctx();
    let mut headers = HashMap::new();
    headers.insert("cookie".to_string(), forwarded.clone());
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
    assert_eq!(headers.get("cookie"), Some(&forwarded));
}

/// Hiding the credential must not disturb the verified identity and claim
/// headers the upstream actually relies on (GHSA-75w5-f79c-7697).
#[tokio::test]
async fn hiding_the_session_cookie_preserves_claim_header_fan_out() {
    let mut config = base_config();
    config["providers"][0]["claim_headers"] = json!({"email": "X-Authenticated-Email"});
    let plugin =
        OidcRelyingParty::new(&config, PluginHttpClient::default()).expect("valid oidc config");
    let sealed = oidc_sealed_session_cookie_for_test(
        &plugin,
        json!({"sub": "alice", "email": "alice@example.test"}),
        false,
    )
    .expect("session seals");
    let mut ctx = session_ctx(&sealed);
    let consumers = ConsumerIndex::new(&[]);
    assert_continue(plugin.authenticate(&mut ctx, &consumers).await);

    let mut headers = ctx.headers.clone();
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
    assert!(!headers.contains_key("cookie"));
    assert_eq!(
        headers.get("x-authenticated-email").map(String::as_str),
        Some("alice@example.test")
    );
}

/// Both advertised minimal examples must actually construct. They previously
/// omitted the required `scopes` (including `openid`) and paired an
/// `/oidc/callback` `redirect_uri` with the default `/oauth/callback`
/// `callback_path`, so an operator who copied either one got a config the
/// gateway refuses (issue #5034).
#[test]
fn the_documented_minimal_examples_pass_admission() {
    for (source, doc) in [
        ("docs/oidc_relying_party.md", DEDICATED_DOC),
        ("docs/plugins.md", CATALOG_DOC),
    ] {
        let example = first_oidc_yaml_example(doc)
            .unwrap_or_else(|| panic!("{source} must document an oidc_relying_party example"));
        let document: serde_json::Value =
            serde_yaml::from_str(&example).unwrap_or_else(|e| panic!("{source} example: {e}"));
        assert_eq!(document["plugin_name"], json!("oidc_relying_party"));
        validate_plugin_config("oidc_relying_party", &document["config"])
            .unwrap_or_else(|e| panic!("{source} example must be admissible: {e}"));
    }
}

const DEDICATED_DOC: &str = include_str!("../../../docs/oidc_relying_party.md");
const CATALOG_DOC: &str = include_str!("../../../docs/plugins.md");

/// Extract the first fenced YAML block whose `plugin_name` is this plugin,
/// substituting the documented `${...}` environment placeholders with fixture
/// values so admission exercises the shape rather than the operator's secrets.
fn first_oidc_yaml_example(doc: &str) -> Option<String> {
    let mut remaining = doc;
    while let Some(start) = remaining.find("```yaml\n") {
        let body = &remaining[start + "```yaml\n".len()..];
        let end = body.find("\n```")?;
        let block = &body[..end];
        remaining = &body[end..];
        if !block.starts_with("plugin_name: oidc_relying_party") {
            continue;
        }
        return Some(
            block
                .replace("${OIDC_CLIENT_SECRET}", "fixture-client-secret")
                .replace(
                    "${OIDC_SESSION_SECRET_32_BYTES_MIN}",
                    "01234567890123456789012345678901",
                ),
        );
    }
    None
}

/// The published `OidcRelyingPartyConfig` component and constructor admission
/// must agree on what a valid plugin config is. The component previously
/// accepted missing scopes, missing or conflicting endpoint sets, missing client
/// credentials, short encryption secrets, disallowed statuses, oversized
/// cookies, negative durations, and invalid cross-field combinations, while
/// rejecting the runtime-supported capitalized `SameSite` and nullable optional
/// values (issue #5035).
///
/// Only constraints a JSON Schema can express are listed here. Cross-object
/// rules the constructor also enforces (`refresh_skew_secs <= ttl_secs / 2`,
/// `callback_path` against `redirect_uri`, `logout_path` collisions, and
/// key/algorithm pairing) stay constructor-only by design and have their own
/// tests.
#[test]
fn the_config_component_agrees_with_constructor_admission() {
    let spec: serde_json::Value =
        serde_yaml::from_str(include_str!("../../../openapi.yaml")).expect("openapi.yaml parses");
    let schema = json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$ref": "#/components/schemas/OidcRelyingPartyConfig",
        "components": spec["components"].clone()
    });
    let validator = jsonschema::draft202012::options()
        .build(&schema)
        .expect("OidcRelyingPartyConfig compiles");

    let case = |label: &str, config: serde_json::Value, admitted: bool| {
        assert_eq!(
            validator.is_valid(&config),
            admitted,
            "schema verdict for '{label}' disagrees with the constructor contract"
        );
        assert_eq!(
            validate_plugin_config("oidc_relying_party", &config).is_ok(),
            admitted,
            "constructor verdict for '{label}' disagrees with the schema"
        );
    };
    let drop_provider = |key: &str| {
        let mut config = base_config();
        config["providers"][0]
            .as_object_mut()
            .expect("provider object")
            .remove(key);
        config
    };
    let provider = |key: &str, value: serde_json::Value| {
        let mut config = base_config();
        config["providers"][0][key] = value;
        config
    };
    let session = |key: &str, value: serde_json::Value| {
        let mut config = base_config();
        config["session"][key] = value;
        config
    };
    let behavior = |key: &str, value: serde_json::Value| {
        let mut config = base_config();
        config["behavior"][key] = value;
        config
    };

    let mut no_endpoints = base_config();
    for key in ["authorization_endpoint", "token_endpoint", "jwks_uri"] {
        no_endpoints["providers"][0]
            .as_object_mut()
            .expect("provider object")
            .remove(key);
    }
    let discovery_conflict = provider(
        "discovery_url",
        json!("https://issuer.example.com/.well-known/openid-configuration"),
    );
    let mut same_site_none_insecure = session("same_site", json!("none"));
    same_site_none_insecure["session"]["secure"] = json!(false);
    let mut null_behavior = base_config();
    null_behavior["behavior"] = json!(null);
    let fragment_redirect = provider(
        "redirect_uri",
        json!("https://app.example.com/oauth/callback#x"),
    );
    let mut redirect_param_without_hosts = base_config();
    redirect_param_without_hosts["behavior"]
        .as_object_mut()
        .expect("behavior object")
        .remove("trusted_redirect_hosts");

    case("valid base config", base_config(), true);
    case("scopes omitted", drop_provider("scopes"), false);
    case(
        "scopes without openid",
        provider("scopes", json!(["profile"])),
        false,
    );
    case("no endpoint set", no_endpoints, false);
    case(
        "discovery plus explicit endpoints",
        discovery_conflict,
        false,
    );
    case("client_auth omitted", drop_provider("client_auth"), false);
    case(
        "client_auth without a secret",
        provider("client_auth", json!({})),
        false,
    );
    case(
        "private_key_jwt without a key",
        provider("client_auth", json!({"method": "private_key_jwt"})),
        false,
    );
    case(
        "non-string client_auth.method",
        provider("client_auth", json!({"method": 9, "client_secret": "s"})),
        false,
    );
    case("redirect_uri with a fragment", fragment_redirect, false);
    case(
        "clock skew above the bound",
        provider("id_token_clock_skew_secs", json!(3601)),
        false,
    );
    case(
        "null optional endpoint",
        provider("userinfo_endpoint", json!(null)),
        true,
    );
    case(
        "short encryption secret",
        session("encryption_secret", json!("too-short")),
        false,
    );
    case("negative ttl", session("ttl_secs", json!(-1)), false);
    case("zero ttl", session("ttl_secs", json!(0)), false);
    case(
        "oversized cookie cap",
        session("max_cookie_bytes", json!(9000)),
        false,
    );
    case(
        "zero cookie cap",
        session("max_cookie_bytes", json!(0)),
        false,
    );
    case(
        "unsupported session store",
        session("store", json!("redis")),
        false,
    );
    case(
        "cookie name with a delimiter",
        session("cookie_name", json!("bad;cookie")),
        false,
    );
    case(
        "domain carrying a scheme",
        session("domain", json!("https://example.test")),
        false,
    );
    case(
        "SameSite=None without secure",
        same_site_none_insecure,
        false,
    );
    case(
        "capitalized SameSite",
        session("same_site", json!("Lax")),
        true,
    );
    case("null behavior object", null_behavior, true);
    case(
        "disallowed challenge status",
        behavior("challenge_html_status", json!(200)),
        false,
    );
    case(
        "disallowed API challenge status",
        behavior("challenge_api_status", json!(500)),
        false,
    );
    case(
        "state ttl above the bound",
        behavior("state_ttl_secs", json!(3601)),
        false,
    );
    case(
        "redirect param without trusted hosts",
        redirect_param_without_hosts,
        false,
    );
    case(
        "unknown session field",
        session("redis_url", json!("redis://x")),
        false,
    );
}
