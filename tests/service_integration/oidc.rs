//! Live OIDC relying-party coverage against Ory Hydra.
//!
//! Drives the real `oidc_relying_party` plugin through discovery, browser
//! authorization-code + PKCE, callback/session establishment, claim headers,
//! idle/absolute lifetime, refresh, and logout. Negative cases cover state /
//! correlation, nonce, issuer (signed-token), audience, and signature failure
//! against the live provider (wrong JWKS). Secrets and tokens are never logged.
//!
//! Live coverage notes (keep claims evidence-based):
//! - Subject is proven positively via successful login (`consumer_identity_claim`).
//! - `azp` multi-audience enforcement remains unit-covered; Hydra's single-aud
//!   ID tokens do not provide a practical live wrong-`azp` vector here.
//! - Absolute/idle expiry are proven with margin sleeps that do not slide the
//!   cookie before the assertion.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use ferrum_edge::ConsumerIndex;
use ferrum_edge::plugins::{Plugin, PluginResult, RequestContext, create_plugin};
use serde_json::{Value, json};
use serial_test::serial;
use url::Url;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use crate::common::containers::{fail_in_ci_else_skip, fixture_http_client};
use crate::common::hydra::{
    FIXTURE_EMAIL, FIXTURE_ROLE, FIXTURE_SUBJECT, HydraClient, HydraContainer,
    TokenEndpointAuthMethod, rewrite_authorization_nonce, start_hydra_container,
};

const SESSION_SECRET: &str = "9f3a7c1e5b2d8406a1c9e7f3b5d20486";
const REDIRECT_PATH: &str = "/oauth/callback";
const LOGOUT_PATH: &str = "/oauth/logout";

fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::WARN)
        .with_test_writer()
        .try_init();
}

async fn hydra_ready(test: &str) -> Option<HydraContainer> {
    init_tracing();
    match start_hydra_container().await {
        Ok(c) => Some(c),
        Err(e) => {
            fail_in_ci_else_skip(test, "Hydra", &e);
            None
        }
    }
}

fn oidc_plugin(config: Value) -> Arc<dyn Plugin> {
    create_plugin("oidc_relying_party", &config)
        .expect("oidc_relying_party config should validate")
        .expect("oidc_relying_party should be registered")
}

fn base_oidc_config(hydra: &HydraContainer, client: &HydraClient) -> Value {
    json!({
        "providers": [{
            "issuer": hydra.issuer,
            "discovery_url": hydra.discovery_url(),
            "client_id": client.client_id,
            "client_auth": {
                "method": "client_secret_basic",
                "client_secret": client.client_secret
            },
            "scopes": ["openid", "offline_access", "profile", "email", "roles"],
            "redirect_uri": client.redirect_uri,
            "callback_path": REDIRECT_PATH,
            "logout_path": LOGOUT_PATH,
            "post_logout_redirect_uri": "http://127.0.0.1/".to_string(),
            "consumer_identity_claim": "email",
            "claim_headers": {
                "email": "X-Authenticated-Email",
                "roles": "X-Authenticated-Roles"
            }
        }],
        "session": {
            "store": "cookie",
            "cookie_name": "ferrum_oidc_si",
            "encryption_secret": SESSION_SECRET,
            "secure": false,
            "ttl_secs": 3600,
            "idle_ttl_secs": 1800
        },
        "behavior": {
            "trusted_redirect_hosts": ["127.0.0.1"],
            "post_login_default_path": "/app",
            "rp_initiated_logout": true,
            "refresh_skew_secs": 30
        }
    })
}

/// Explicit Hydra endpoints (no discovery) so issuer/JWKS negatives reach the
/// signed-token callback path instead of stalling on discovery mismatch.
fn explicit_oidc_config(
    hydra: &HydraContainer,
    client: &HydraClient,
    discovery: &Value,
    issuer: &str,
    jwks_uri: Option<&str>,
) -> Value {
    let mut cfg = base_oidc_config(hydra, client);
    let provider = cfg["providers"][0].as_object_mut().unwrap();
    provider.remove("discovery_url");
    provider.insert("issuer".to_string(), json!(issuer));
    provider.insert(
        "authorization_endpoint".to_string(),
        discovery["authorization_endpoint"].clone(),
    );
    provider.insert(
        "token_endpoint".to_string(),
        discovery["token_endpoint"].clone(),
    );
    provider.insert(
        "userinfo_endpoint".to_string(),
        discovery["userinfo_endpoint"].clone(),
    );
    provider.insert(
        "end_session_endpoint".to_string(),
        discovery
            .get("end_session_endpoint")
            .cloned()
            .unwrap_or(Value::Null),
    );
    provider.insert(
        "jwks_uri".to_string(),
        json!(jwks_uri.unwrap_or_else(|| discovery["jwks_uri"].as_str().unwrap())),
    );
    cfg
}

fn html_ctx(path: &str) -> RequestContext {
    let mut ctx = RequestContext::new("127.0.0.1".into(), "GET".into(), path.into());
    ctx.request_is_secure = false;
    ctx.headers
        .insert("accept".to_string(), "text/html".to_string());
    ctx.headers
        .insert("host".to_string(), "127.0.0.1".to_string());
    ctx.metadata
        .insert("ferrum.frontend_scheme".to_string(), "http".to_string());
    ctx
}

struct BrowserChallenge {
    state: String,
    nonce: String,
    cookie: String,
    location: String,
}

fn cookie_pair(set_cookie: &str) -> &str {
    set_cookie.split(';').next().expect("cookie pair")
}

fn cookie_name(set_cookie: &str) -> &str {
    cookie_pair(set_cookie)
        .split_once('=')
        .map(|(n, _)| n)
        .expect("cookie name")
}

fn assert_cookie_cleared(headers: &HashMap<String, String>, name: &str) {
    let set_cookie = headers.get("set-cookie").expect("logout Set-Cookie");
    let empty_pair = format!("{name}=");
    assert!(
        set_cookie.lines().any(|line| {
            line.split(';')
                .next()
                .is_some_and(|pair| pair.trim() == empty_pair)
                && line
                    .split(';')
                    .skip(1)
                    .any(|attribute| attribute.trim().eq_ignore_ascii_case("max-age=0"))
        }),
        "logout must expire an empty {name} cookie"
    );
}

fn assert_loopback_cookie_security(set_cookie: &str, expected_path: &str) {
    let attributes: Vec<&str> = set_cookie.split(';').skip(1).map(str::trim).collect();
    let expected_path_attribute = format!("Path={expected_path}");
    assert!(
        attributes
            .iter()
            .any(|attribute| attribute.eq_ignore_ascii_case("httponly")),
        "OIDC cookies must be HttpOnly"
    );
    assert!(
        attributes
            .iter()
            .any(|attribute| attribute.eq_ignore_ascii_case("samesite=lax")),
        "OIDC cookies must use SameSite=Lax in this flow"
    );
    assert!(
        attributes
            .iter()
            .any(|attribute| *attribute == expected_path_attribute),
        "OIDC cookie path must match its configured scope"
    );
    assert!(
        !attributes
            .iter()
            .any(|attribute| attribute.to_ascii_lowercase().starts_with("domain=")),
        "loopback OIDC cookies must remain host-only"
    );
    assert!(
        !attributes
            .iter()
            .any(|attribute| attribute.eq_ignore_ascii_case("secure")),
        "the HTTP loopback fixture explicitly configures secure=false"
    );
}

async fn wait_for_browser_challenge(plugin: &Arc<dyn Plugin>) -> BrowserChallenge {
    let mut last = String::new();
    for _ in 0..60 {
        let mut ctx = html_ctx("/app");
        match plugin
            .authenticate(&mut ctx, &ConsumerIndex::new(&[]))
            .await
        {
            PluginResult::Reject {
                status_code: 302,
                headers,
                ..
            } => {
                let location = headers
                    .get("location")
                    .cloned()
                    .expect("authorization Location");
                let url = Url::parse(&location).expect("authorization URL");
                let state = url
                    .query_pairs()
                    .find_map(|(k, v)| (k == "state").then(|| v.into_owned()))
                    .expect("state");
                let nonce = url
                    .query_pairs()
                    .find_map(|(k, v)| (k == "nonce").then(|| v.into_owned()))
                    .expect("nonce");
                let cookie = headers
                    .get("set-cookie")
                    .cloned()
                    .expect("correlation cookie");
                assert_loopback_cookie_security(&cookie, REDIRECT_PATH);
                assert!(
                    url.query_pairs().any(|(k, _)| k == "code_challenge"),
                    "PKCE code_challenge required"
                );
                assert!(
                    url.query_pairs()
                        .any(|(k, v)| k == "code_challenge_method" && v == "S256"),
                    "PKCE S256 required"
                );
                return BrowserChallenge {
                    state,
                    nonce,
                    cookie,
                    location,
                };
            }
            PluginResult::Reject {
                status_code, body, ..
            } => {
                last = format!("HTTP {status_code}");
                let _ = body; // never log body — may contain provider details
            }
            other => last = format!("unexpected {other:?}"),
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    panic!("OIDC discovery/browser challenge not ready: {last}");
}

async fn complete_login(
    hydra: &HydraContainer,
    plugin: &Arc<dyn Plugin>,
    client: &HydraClient,
    challenge: &BrowserChallenge,
) -> String {
    let callback = hydra
        .complete_authorization_redirect(
            &challenge.location,
            &client.redirect_uri,
            &challenge.state,
        )
        .await
        .expect("Hydra authorization-code redirect");
    assert_eq!(
        callback.state, challenge.state,
        "provider must echo Ferrum state"
    );
    let _ = &challenge.nonce; // nonce validated inside the plugin against the ID token

    let mut ctx = html_ctx(REDIRECT_PATH);
    ctx.headers.insert(
        "cookie".to_string(),
        cookie_pair(&challenge.cookie).to_string(),
    );
    ctx.query_params.insert("state".to_string(), callback.state);
    ctx.query_params.insert("code".to_string(), callback.code);

    let PluginResult::Reject {
        status_code,
        headers,
        ..
    } = plugin.on_request_received(&mut ctx).await
    else {
        panic!("expected post-login redirect");
    };
    assert_eq!(status_code, 302, "successful callback redirects");
    assert_eq!(
        headers.get("location").map(String::as_str),
        Some("http://127.0.0.1/app"),
        "callback must return to the exact trusted original target"
    );
    assert_cookie_cleared(&headers, cookie_name(&challenge.cookie));
    let set_cookie = headers.get("set-cookie").expect("session Set-Cookie");
    let session_cookie = set_cookie
        .lines()
        .find(|line| line.contains("ferrum_oidc_si="))
        .expect("encrypted session cookie");
    assert_loopback_cookie_security(session_cookie, "/");
    session_cookie.to_string()
}

fn session_ctx(set_cookie: &str, path: &str) -> RequestContext {
    let mut ctx = html_ctx(path);
    ctx.headers
        .insert("cookie".to_string(), cookie_pair(set_cookie).to_string());
    ctx
}

fn assert_continue(result: PluginResult) {
    assert!(
        matches!(result, PluginResult::Continue),
        "expected Continue, got reject"
    );
}

fn assert_rechallenge(result: PluginResult, what: &str) {
    match result {
        PluginResult::Reject {
            status_code: 302, ..
        }
        | PluginResult::Reject {
            status_code: 401, ..
        } => {}
        other => panic!("{what} should re-challenge, got {other:?}"),
    }
}

/// Sleep past an integer-second `now > issued+ttl` boundary with margin.
/// Does not touch the session cookie (no authenticate/slide).
async fn sleep_past_ttl_secs(ttl_secs: u64) {
    // Integer-second comparisons need strictly greater than issued+ttl; add a
    // full extra second plus 250ms so boundary equality cannot flake.
    tokio::time::sleep(Duration::from_secs(ttl_secs + 1) + Duration::from_millis(250)).await;
}

async fn fetch_hydra_discovery(hydra: &HydraContainer) -> Value {
    fixture_http_client()
        .get(hydra.discovery_url())
        .send()
        .await
        .expect("discovery")
        .json()
        .await
        .expect("discovery json")
}

#[tokio::test]
#[serial]
async fn oidc_live_discovery_login_session_and_claims() {
    let Some(hydra) = hydra_ready("oidc_live_discovery_login_session_and_claims").await else {
        return;
    };
    let redirect_uri = format!("http://127.0.0.1{REDIRECT_PATH}");
    let client = hydra
        .create_client(
            "oidc",
            &redirect_uri,
            TokenEndpointAuthMethod::ClientSecretBasic,
            &["authorization_code", "refresh_token"],
        )
        .await
        .expect("seed OIDC client");

    // Reserved header mapping must fail closed at construction.
    let mut bad = base_oidc_config(&hydra, &client);
    bad["providers"][0]["claim_headers"] = json!({"email": "Authorization"});
    assert!(
        create_plugin("oidc_relying_party", &bad).is_err(),
        "reserved claim header targets must be rejected"
    );

    let plugin = oidc_plugin(base_oidc_config(&hydra, &client));
    let challenge = wait_for_browser_challenge(&plugin).await;
    let session_cookie = complete_login(&hydra, &plugin, &client, &challenge).await;

    // Authenticated session: identity + claim headers + correlation cleared.
    let mut ctx = session_ctx(&session_cookie, "/app");
    // Client-supplied claim destination must not stick; reserved Authorization
    // must be preserved through claim fan-out.
    ctx.headers
        .insert("x-authenticated-email".to_string(), "evil@attacker".into());
    ctx.headers
        .insert("authorization".to_string(), "Bearer attacker".into());
    assert_continue(
        plugin
            .authenticate(&mut ctx, &ConsumerIndex::new(&[]))
            .await,
    );
    assert_eq!(
        ctx.authenticated_identity.as_deref(),
        Some(FIXTURE_EMAIL),
        "consumer_identity_claim=email"
    );
    assert_eq!(ctx.auth_method, Some("oidc_relying_party"));

    let mut upstream = ctx.headers.clone();
    assert_continue(plugin.before_proxy(&mut ctx, &mut upstream).await);
    assert_eq!(
        upstream.get("x-authenticated-email").map(String::as_str),
        Some(FIXTURE_EMAIL)
    );
    let roles = upstream
        .get("x-authenticated-roles")
        .map(String::as_str)
        .unwrap_or_default();
    assert!(
        roles.contains(FIXTURE_ROLE),
        "roles claim must reach upstream"
    );
    assert_eq!(
        upstream.get("authorization").map(String::as_str),
        Some("Bearer attacker"),
        "claim fan-out must preserve client-supplied Authorization"
    );

    // Negative: wrong state / missing correlation cookie.
    let challenge2 = wait_for_browser_challenge(&plugin).await;
    let callback = hydra
        .complete_authorization_redirect(
            &challenge2.location,
            &client.redirect_uri,
            &challenge2.state,
        )
        .await
        .expect("second auth code");
    let mut bad_state = html_ctx(REDIRECT_PATH);
    bad_state.headers.insert(
        "cookie".to_string(),
        cookie_pair(&challenge2.cookie).to_string(),
    );
    bad_state
        .query_params
        .insert("state".to_string(), "not-the-real-state".into());
    bad_state
        .query_params
        .insert("code".to_string(), callback.code.clone());
    match plugin.on_request_received(&mut bad_state).await {
        PluginResult::Reject { status_code, .. } => assert_eq!(status_code, 400),
        other => panic!("expected state rejection, got {other:?}"),
    }

    let mut bad_corr = html_ctx(REDIRECT_PATH);
    bad_corr
        .query_params
        .insert("state".to_string(), callback.state);
    bad_corr
        .query_params
        .insert("code".to_string(), callback.code);
    match plugin.on_request_received(&mut bad_corr).await {
        PluginResult::Reject { status_code, .. } => assert_eq!(status_code, 400),
        other => panic!("expected correlation rejection, got {other:?}"),
    }

    // Negative nonce: keep Ferrum correlation cookie/state, but ask Hydra to
    // mint an ID token with a different nonce than Ferrum stored.
    let challenge_nonce = wait_for_browser_challenge(&plugin).await;
    let mismatched_auth = rewrite_authorization_nonce(
        &challenge_nonce.location,
        &format!("mismatched-{}", hydra.isolation),
    )
    .expect("rewrite nonce");
    let cb_nonce = hydra
        .complete_authorization_redirect(
            &mismatched_auth,
            &client.redirect_uri,
            &challenge_nonce.state,
        )
        .await
        .expect("code for nonce-mismatch");
    assert_eq!(cb_nonce.state, challenge_nonce.state);
    let mut nonce_ctx = html_ctx(REDIRECT_PATH);
    nonce_ctx.headers.insert(
        "cookie".to_string(),
        cookie_pair(&challenge_nonce.cookie).to_string(),
    );
    nonce_ctx
        .query_params
        .insert("state".to_string(), cb_nonce.state);
    nonce_ctx
        .query_params
        .insert("code".to_string(), cb_nonce.code);
    match plugin.on_request_received(&mut nonce_ctx).await {
        PluginResult::Reject { status_code, .. } => assert_eq!(
            status_code, 400,
            "nonce mismatch must be rejected by callback validation"
        ),
        other => panic!("expected nonce rejection, got {other:?}"),
    }

    let discovery = fetch_hydra_discovery(&hydra).await;

    // Negative issuer: explicit live Hydra endpoints + mismatched expected
    // issuer so the signed ID token `iss` check rejects at callback (not a
    // discovery-setup stall).
    let wrong_iss_plugin = oidc_plugin(explicit_oidc_config(
        &hydra,
        &client,
        &discovery,
        "http://127.0.0.1:9/",
        None,
    ));
    let ch = wait_for_browser_challenge(&wrong_iss_plugin).await;
    let cb = hydra
        .complete_authorization_redirect(&ch.location, &client.redirect_uri, &ch.state)
        .await
        .expect("code for wrong-issuer plugin");
    let mut cb_ctx = html_ctx(REDIRECT_PATH);
    cb_ctx
        .headers
        .insert("cookie".to_string(), cookie_pair(&ch.cookie).to_string());
    cb_ctx.query_params.insert("state".to_string(), cb.state);
    cb_ctx.query_params.insert("code".to_string(), cb.code);
    match wrong_iss_plugin.on_request_received(&mut cb_ctx).await {
        PluginResult::Reject { status_code, .. } => assert_eq!(
            status_code, 400,
            "issuer mismatch must be rejected by callback validation"
        ),
        other => panic!("expected issuer rejection, got {other:?}"),
    }

    // Negative audience: require an audience Hydra will not put on the ID token.
    let mut wrong_aud = base_oidc_config(&hydra, &client);
    wrong_aud["providers"][0]["audiences"] = json!(["api://not-granted"]);
    let wrong_aud_plugin = oidc_plugin(wrong_aud);
    let ch = wait_for_browser_challenge(&wrong_aud_plugin).await;
    let cb = hydra
        .complete_authorization_redirect(&ch.location, &client.redirect_uri, &ch.state)
        .await
        .expect("code for wrong-audience plugin");
    let mut cb_ctx = html_ctx(REDIRECT_PATH);
    cb_ctx
        .headers
        .insert("cookie".to_string(), cookie_pair(&ch.cookie).to_string());
    cb_ctx.query_params.insert("state".to_string(), cb.state);
    cb_ctx.query_params.insert("code".to_string(), cb.code);
    match wrong_aud_plugin.on_request_received(&mut cb_ctx).await {
        PluginResult::Reject { status_code, .. } => assert_eq!(
            status_code, 400,
            "audience mismatch must be rejected by callback validation"
        ),
        other => panic!("expected audience rejection, got {other:?}"),
    }

    // Negative signature: live Hydra token endpoint + unrelated JWKS.
    let jwks_mock = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/jwks"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "keys": [{
                "kty": "RSA",
                "kid": "wrong",
                "n": "sXch6-example-modulus-that-is-long-enough-for-shape-only-0000000001",
                "e": "AQAB",
                "alg": "RS256",
                "use": "sig"
            }]
        })))
        .mount(&jwks_mock)
        .await;
    let wrong_sig_plugin = oidc_plugin(explicit_oidc_config(
        &hydra,
        &client,
        &discovery,
        &hydra.issuer,
        Some(&format!("{}/jwks", jwks_mock.uri())),
    ));
    let ch = wait_for_browser_challenge(&wrong_sig_plugin).await;
    let cb = hydra
        .complete_authorization_redirect(&ch.location, &client.redirect_uri, &ch.state)
        .await
        .expect("code for wrong-jwks plugin");
    let mut cb_ctx = html_ctx(REDIRECT_PATH);
    cb_ctx
        .headers
        .insert("cookie".to_string(), cookie_pair(&ch.cookie).to_string());
    cb_ctx.query_params.insert("state".to_string(), cb.state);
    cb_ctx.query_params.insert("code".to_string(), cb.code);
    match wrong_sig_plugin.on_request_received(&mut cb_ctx).await {
        PluginResult::Reject { status_code, .. } => assert_eq!(
            status_code, 400,
            "signature mismatch must be rejected by callback validation"
        ),
        other => panic!("expected signature rejection, got {other:?}"),
    }

    // Subject is exercised positively via successful login (sub/email binding).
    let _ = FIXTURE_SUBJECT;
}

#[tokio::test]
#[serial]
async fn oidc_live_session_expiry_refresh_and_logout() {
    let Some(hydra) = hydra_ready("oidc_live_session_expiry_refresh_and_logout").await else {
        return;
    };
    let redirect_uri = format!("http://127.0.0.1{REDIRECT_PATH}");
    let client = hydra
        .create_client(
            "oidc-sess",
            &redirect_uri,
            TokenEndpointAuthMethod::ClientSecretBasic,
            &["authorization_code", "refresh_token"],
        )
        .await
        .expect("seed session client");

    let discovery = fetch_hydra_discovery(&hydra).await;
    // Token facade shortens expires_in so refresh_after reaches the plugin's
    // REFRESH_RETRY_BACKOFF floor (~30s) while session ttl stays valid.
    // refresh_skew must be <= ttl/2 (production constructor invariant).
    let (token_facade_url, token_stats) = hydra
        .start_token_facade(Some(8))
        .await
        .expect("token facade");

    let mut cfg = explicit_oidc_config(&hydra, &client, &discovery, &hydra.issuer, None);
    cfg["providers"][0]["token_endpoint"] = json!(token_facade_url);
    cfg["session"]["ttl_secs"] = json!(120);
    cfg["session"]["idle_ttl_secs"] = json!(120);
    cfg["behavior"]["refresh_skew_secs"] = json!(60); // <= 120/2
    let plugin = oidc_plugin(cfg);

    let challenge = wait_for_browser_challenge(&plugin).await;
    let session_cookie = complete_login(&hydra, &plugin, &client, &challenge).await;
    assert!(
        token_stats.authorization_code_ok.load(Ordering::SeqCst) >= 1,
        "login must complete an authorization_code grant through the facade"
    );
    let refresh_before = token_stats.refresh_token_ok.load(Ordering::SeqCst);

    // Wait until refresh is due (floor is ~30s), then authenticate once.
    // Poll without sliding earlier: only probe after the backoff window.
    let refresh_deadline = Instant::now() + Duration::from_secs(45);
    tokio::time::sleep(Duration::from_secs(31)).await;
    let mut renewed = session_cookie.clone();
    let mut saw_refresh = false;
    while Instant::now() < refresh_deadline {
        let mut ctx = session_ctx(&renewed, "/app");
        assert_continue(
            plugin
                .authenticate(&mut ctx, &ConsumerIndex::new(&[]))
                .await,
        );
        let mut rolled = HashMap::new();
        assert_continue(plugin.after_proxy(&mut ctx, 200, &mut rolled).await);
        if token_stats.refresh_token_ok.load(Ordering::SeqCst) > refresh_before {
            let set_cookie = rolled
                .get("set-cookie")
                .expect("successful refresh must re-issue the session cookie");
            let refreshed_cookie = set_cookie
                .lines()
                .find(|line| cookie_name(line) == "ferrum_oidc_si")
                .expect("refreshed Ferrum session cookie");
            assert_loopback_cookie_security(refreshed_cookie, "/");
            assert_ne!(
                cookie_pair(refreshed_cookie),
                cookie_pair(&renewed),
                "refreshed session must carry newly sealed state"
            );
            renewed = refreshed_cookie.to_string();
            saw_refresh = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    assert!(
        saw_refresh,
        "expected a successful refresh_token grant at Hydra via the token facade"
    );

    // Idle expiry: wait past idle_ttl without any authenticate/slide first.
    let mut idle_cfg = base_oidc_config(&hydra, &client);
    idle_cfg["session"]["ttl_secs"] = json!(30);
    idle_cfg["session"]["idle_ttl_secs"] = json!(2);
    idle_cfg["behavior"]["refresh_skew_secs"] = json!(0);
    let idle_plugin = oidc_plugin(idle_cfg);
    let ch = wait_for_browser_challenge(&idle_plugin).await;
    let idle_cookie = complete_login(&hydra, &idle_plugin, &client, &ch).await;
    sleep_past_ttl_secs(2).await;
    let mut idle_ctx = session_ctx(&idle_cookie, "/app");
    assert_rechallenge(
        idle_plugin
            .authenticate(&mut idle_ctx, &ConsumerIndex::new(&[]))
            .await,
        "idle expiry",
    );

    // Absolute expiry (also no pre-assertion slide).
    let mut abs_cfg = base_oidc_config(&hydra, &client);
    abs_cfg["session"]["ttl_secs"] = json!(2);
    abs_cfg["session"]["idle_ttl_secs"] = json!(30);
    abs_cfg["behavior"]["refresh_skew_secs"] = json!(0);
    let abs_plugin = oidc_plugin(abs_cfg);
    let ch = wait_for_browser_challenge(&abs_plugin).await;
    let abs_cookie = complete_login(&hydra, &abs_plugin, &client, &ch).await;
    sleep_past_ttl_secs(2).await;
    let mut abs_ctx = session_ctx(&abs_cookie, "/app");
    assert_rechallenge(
        abs_plugin
            .authenticate(&mut abs_ctx, &ConsumerIndex::new(&[]))
            .await,
        "absolute expiry",
    );

    // Logout against the refreshed session.
    let expected_end_session = discovery
        .get("end_session_endpoint")
        .and_then(Value::as_str)
        .expect("Hydra discovery must advertise end_session_endpoint");
    let mut logout_ctx = session_ctx(&renewed, LOGOUT_PATH);
    match plugin.on_request_received(&mut logout_ctx).await {
        PluginResult::Reject {
            status_code: 302,
            headers,
            ..
        } => {
            let location = headers.get("location").expect("logout Location");
            let actual = Url::parse(location).expect("logout Location URL");
            let expected = Url::parse(expected_end_session).expect("end-session URL");
            assert_eq!(actual.origin(), expected.origin());
            assert_eq!(actual.path(), expected.path());
            assert_eq!(
                actual.query_pairs().find_map(|(key, value)| {
                    (key == "post_logout_redirect_uri").then_some(value)
                }),
                Some("http://127.0.0.1/".into())
            );
            assert_eq!(
                actual
                    .query_pairs()
                    .find_map(|(key, value)| (key == "client_id").then_some(value)),
                Some(client.client_id.as_str().into())
            );
            assert_cookie_cleared(&headers, cookie_name(&renewed));
            let cleared = headers
                .get("set-cookie")
                .and_then(|cookies| {
                    cookies
                        .lines()
                        .find(|line| cookie_name(line) == cookie_name(&renewed))
                })
                .expect("cleared session cookie");
            assert_loopback_cookie_security(cleared, "/");
        }
        other => panic!("expected logout redirect, got {other:?}"),
    }

    // A cookie-backed session is stateless, so manually replaying the old
    // sealed value is not a valid server-side revocation test. Emulate the
    // browser applying the verified Max-Age=0 deletion and require a new login.
    let mut after = html_ctx("/app");
    match plugin
        .authenticate(&mut after, &ConsumerIndex::new(&[]))
        .await
    {
        PluginResult::Reject {
            status_code: 302, ..
        } => {}
        other => panic!("logged-out browser must challenge, got {other:?}"),
    }
}
