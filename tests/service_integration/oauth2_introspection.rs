//! Live OAuth2 token-introspection coverage against Ory Hydra.
//!
//! Independently runnable from the OIDC suite. Exercises active/inactive opaque
//! tokens, scope/role/issuer/audience checks, claim-header mapping,
//! `client_secret_basic` and `client_secret_post` request shaping (observed via
//! the non-secret facade), discovery vs direct endpoint configuration, cache
//! hit/expiry via an upstream-call counter, and failure policy (timeout /
//! malformed / oversized / auth / unavailable).
//!
//! Note: Hydra's admin introspection endpoint does not enforce client
//! authentication, so a wrong client secret against that URL is not a valid
//! auth-failure proof. Auth-failure fail-closed is covered by wiremock.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use ferrum_edge::ConsumerIndex;
use ferrum_edge::plugins::{Plugin, PluginResult, RequestContext, create_plugin};
use serde_json::{Value, json};
use serial_test::serial;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use crate::common::containers::fail_in_ci_else_skip;
use crate::common::hydra::{
    FIXTURE_EMAIL, FIXTURE_ROLE, HydraContainer, TokenEndpointAuthMethod, start_hydra_container,
};

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

fn introspection_plugin(config: Value) -> Arc<dyn Plugin> {
    let plugin = create_plugin("oauth2_introspection", &config)
        .expect("oauth2_introspection config should validate")
        .expect("oauth2_introspection should be registered");
    plugin
        .start_background_tasks()
        .expect("discovery workers start on tokio runtime");
    plugin
}

fn bearer_ctx(token: &str) -> RequestContext {
    let mut ctx = RequestContext::new("127.0.0.1".into(), "GET".into(), "/api".into());
    ctx.headers
        .insert("authorization".to_string(), format!("Bearer {token}"));
    ctx
}

fn reject_status(result: &PluginResult) -> Option<u16> {
    match result {
        PluginResult::Continue => None,
        PluginResult::Reject { status_code, .. } => Some(*status_code),
        PluginResult::RejectBinary { status_code, .. } => Some(*status_code),
    }
}

async fn wait_discovery_ready(plugin: &Arc<dyn Plugin>, token: &str) {
    let mut last = String::new();
    for _ in 0..60 {
        let mut ctx = bearer_ctx(token);
        match plugin
            .authenticate(&mut ctx, &ConsumerIndex::new(&[]))
            .await
        {
            PluginResult::Continue => return,
            PluginResult::Reject {
                status_code: 503, ..
            } => {
                last = "503".into();
            }
            PluginResult::Reject { status_code, .. } => {
                if status_code == 401 || status_code == 403 {
                    return;
                }
                last = format!("{status_code}");
            }
            other => last = format!("{other:?}"),
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    panic!("introspection discovery not ready: {last}");
}

#[tokio::test]
#[serial]
async fn oauth2_live_introspection_tokens_claims_cache_and_auth() {
    let Some(hydra) = hydra_ready("oauth2_live_introspection_tokens_claims_cache_and_auth").await
    else {
        return;
    };

    let redirect = "http://127.0.0.1/oauth/callback";
    let basic_client = hydra
        .create_client(
            "intro-basic",
            redirect,
            TokenEndpointAuthMethod::ClientSecretBasic,
            &["client_credentials", "authorization_code", "refresh_token"],
        )
        .await
        .expect("basic client");
    let post_client = hydra
        .create_client(
            "intro-post",
            redirect,
            TokenEndpointAuthMethod::ClientSecretPost,
            &["client_credentials"],
        )
        .await
        .expect("post client");
    assert_eq!(
        basic_client.token_endpoint_auth_method,
        TokenEndpointAuthMethod::ClientSecretBasic
    );
    assert_eq!(
        post_client.token_endpoint_auth_method,
        TokenEndpointAuthMethod::ClientSecretPost
    );

    let active = hydra
        .client_credentials_token(&basic_client, "profile", Some(&basic_client.audience))
        .await
        .expect("active opaque token");
    assert!(
        jsonwebtoken::decode_header(&active).is_err(),
        "Hydra access tokens must be opaque (not a compact JWT)"
    );

    let direct_cfg = json!({
        "providers": [{
            "introspection_endpoint": hydra.introspection_endpoint(),
            "issuer": hydra.issuer,
            "audiences": [basic_client.audience],
            "client_auth": {
                "method": "client_secret_basic",
                "client_id": basic_client.client_id,
                "client_secret": basic_client.client_secret
            },
            "required_scopes": ["profile"],
            "positive_cache_ttl_secs": 5,
            "negative_cache_ttl_secs": 2,
            "consumer_identity_claim": "sub",
            "claim_headers": {
                "client_id": "X-Token-Client"
            }
        }]
    });
    let plugin = introspection_plugin(direct_cfg);

    let mut ctx = bearer_ctx(&active);
    assert_eq!(
        reject_status(
            &plugin
                .authenticate(&mut ctx, &ConsumerIndex::new(&[]))
                .await
        ),
        None,
        "active opaque token must Continue"
    );
    let mut upstream = HashMap::new();
    assert!(matches!(
        plugin.before_proxy(&mut ctx, &mut upstream).await,
        PluginResult::Continue
    ));
    assert_eq!(
        upstream.get("x-token-client").map(String::as_str),
        Some(basic_client.client_id.as_str())
    );

    let inactive = format!("inactive-{}", hydra.isolation);
    let mut inactive_ctx = bearer_ctx(&inactive);
    assert_eq!(
        reject_status(
            &plugin
                .authenticate(&mut inactive_ctx, &ConsumerIndex::new(&[]))
                .await
        ),
        Some(401)
    );

    // Scope denial: token without the required profile scope.
    let no_scope = hydra
        .client_credentials_token(&basic_client, "", Some(&basic_client.audience))
        .await
        .expect("token without profile scope");
    let mut scope_ctx = bearer_ctx(&no_scope);
    let scope_status = reject_status(
        &plugin
            .authenticate(&mut scope_ctx, &ConsumerIndex::new(&[]))
            .await,
    );
    assert_eq!(scope_status, Some(403), "missing required scope must deny");

    let wrong_issuer = introspection_plugin(json!({
        "providers": [{
            "introspection_endpoint": hydra.introspection_endpoint(),
            "issuer": "http://127.0.0.1:9/",
            "audiences": [basic_client.audience],
            "client_auth": {
                "method": "client_secret_basic",
                "client_id": basic_client.client_id,
                "client_secret": basic_client.client_secret
            }
        }]
    }));
    let mut bad_iss = bearer_ctx(&active);
    assert_eq!(
        reject_status(
            &wrong_issuer
                .authenticate(&mut bad_iss, &ConsumerIndex::new(&[]))
                .await
        ),
        Some(401),
        "wrong issuer must deny independently of audience validation"
    );

    let wrong_audience = introspection_plugin(json!({
        "providers": [{
            "introspection_endpoint": hydra.introspection_endpoint(),
            "issuer": hydra.issuer,
            "audiences": ["api://wrong"],
            "client_auth": {
                "method": "client_secret_basic",
                "client_id": basic_client.client_id,
                "client_secret": basic_client.client_secret
            }
        }]
    }));
    let mut bad_aud = bearer_ctx(&active);
    assert_eq!(
        reject_status(
            &wrong_audience
                .authenticate(&mut bad_aud, &ConsumerIndex::new(&[]))
                .await
        ),
        Some(401),
        "wrong audience must deny independently of issuer validation"
    );

    let post_token = hydra
        .client_credentials_token(&post_client, "profile", Some(&post_client.audience))
        .await
        .expect("post-auth token");
    let post_plugin = introspection_plugin(json!({
        "providers": [{
            "introspection_endpoint": hydra.introspection_endpoint(),
            "client_auth": {
                "method": "client_secret_post",
                "client_id": post_client.client_id,
                "client_secret": post_client.client_secret
            }
        }]
    }));
    let mut post_ctx = bearer_ctx(&post_token);
    assert_eq!(
        reject_status(
            &post_plugin
                .authenticate(&mut post_ctx, &ConsumerIndex::new(&[]))
                .await
        ),
        None
    );

    // Discovery via same-origin facade → live admin introspect.
    let (discovery_url, facade_stats) = hydra
        .start_introspection_discovery_facade()
        .await
        .expect("discovery facade");
    let discovery_plugin = introspection_plugin(json!({
        "providers": [{
            "discovery_url": discovery_url,
            "issuer": hydra.issuer,
            "client_auth": {
                "method": "client_secret_basic",
                "client_id": basic_client.client_id,
                "client_secret": basic_client.client_secret
            },
            "positive_cache_ttl_secs": 3,
            "negative_cache_ttl_secs": 1
        }]
    }));
    // Warm discovery with an inactive token so the positive cache for `active`
    // stays cold for the hit/miss counter proof below.
    let warmup_inactive = format!("warmup-{}", hydra.isolation);
    wait_discovery_ready(&discovery_plugin, &warmup_inactive).await;

    let calls_before = facade_stats
        .upstream_introspect_calls
        .load(Ordering::SeqCst);
    let basic_before = facade_stats
        .basic_authorization_header
        .load(Ordering::SeqCst);
    let post_secret_before = facade_stats.post_client_secret_field.load(Ordering::SeqCst);

    let mut disc_ctx = bearer_ctx(&active);
    assert_eq!(
        reject_status(
            &discovery_plugin
                .authenticate(&mut disc_ctx, &ConsumerIndex::new(&[]))
                .await
        ),
        None,
        "discovery-resolved introspection must accept active token"
    );
    let after_first = facade_stats
        .upstream_introspect_calls
        .load(Ordering::SeqCst);
    assert!(
        after_first > calls_before,
        "first lookup must call upstream introspect"
    );
    assert!(
        facade_stats
            .basic_authorization_header
            .load(Ordering::SeqCst)
            > basic_before,
        "client_secret_basic must present Authorization to the facade"
    );
    assert_eq!(
        facade_stats.post_client_secret_field.load(Ordering::SeqCst),
        post_secret_before,
        "client_secret_basic must not send a client_secret form field"
    );

    // Cache hit: second lookup must not call upstream again.
    let mut disc_ctx2 = bearer_ctx(&active);
    assert_eq!(
        reject_status(
            &discovery_plugin
                .authenticate(&mut disc_ctx2, &ConsumerIndex::new(&[]))
                .await
        ),
        None,
        "cache hit must still Continue"
    );
    assert_eq!(
        facade_stats
            .upstream_introspect_calls
            .load(Ordering::SeqCst),
        after_first,
        "second lookup must be a positive-cache hit (no upstream call)"
    );

    // After TTL, another upstream call is required.
    tokio::time::sleep(Duration::from_secs(3) + Duration::from_millis(250)).await;
    let expiry_deadline = Instant::now() + Duration::from_secs(6);
    let mut refreshed_upstream = false;
    while Instant::now() < expiry_deadline {
        let before = facade_stats
            .upstream_introspect_calls
            .load(Ordering::SeqCst);
        let mut disc_ctx3 = bearer_ctx(&active);
        assert_eq!(
            reject_status(
                &discovery_plugin
                    .authenticate(&mut disc_ctx3, &ConsumerIndex::new(&[]))
                    .await
            ),
            None
        );
        if facade_stats
            .upstream_introspect_calls
            .load(Ordering::SeqCst)
            > before
        {
            refreshed_upstream = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(
        refreshed_upstream,
        "lookup after positive-cache TTL must call upstream again"
    );

    // client_secret_post shaping observed via a fresh facade (no secret values).
    let (discovery_url_post, post_stats) = hydra
        .start_introspection_discovery_facade()
        .await
        .expect("post discovery facade");
    let post_discovery_plugin = introspection_plugin(json!({
        "providers": [{
            "discovery_url": discovery_url_post,
            "client_auth": {
                "method": "client_secret_post",
                "client_id": post_client.client_id,
                "client_secret": post_client.client_secret
            }
        }]
    }));
    let post_field_before = post_stats.post_client_secret_field.load(Ordering::SeqCst);
    let basic_on_post = post_stats.basic_authorization_header.load(Ordering::SeqCst);
    wait_discovery_ready(&post_discovery_plugin, &post_token).await;
    assert!(
        post_stats.post_client_secret_field.load(Ordering::SeqCst) > post_field_before,
        "client_secret_post must include a client_secret form field"
    );
    assert_eq!(
        post_stats.basic_authorization_header.load(Ordering::SeqCst),
        basic_on_post,
        "client_secret_post must not send Authorization"
    );
    let mut post_facade_ctx = bearer_ctx(&post_token);
    assert_eq!(
        reject_status(
            &post_discovery_plugin
                .authenticate(&mut post_facade_ctx, &ConsumerIndex::new(&[]))
                .await
        ),
        None
    );

    // Claim-rich opaque token (Hydra puts consent session extras under `ext`).
    let claim_client = hydra
        .create_client(
            "intro-claims",
            redirect,
            TokenEndpointAuthMethod::ClientSecretBasic,
            &["authorization_code", "refresh_token"],
        )
        .await
        .expect("claims client");
    let (claim_token, _) = hydra
        .authorization_code_tokens(&claim_client, "openid offline_access profile email roles")
        .await
        .expect("claim-bearing opaque token");
    assert!(
        jsonwebtoken::decode_header(&claim_token).is_err(),
        "Hydra authorization-code access tokens must be opaque (not a compact JWT)"
    );
    let claim_plugin = introspection_plugin(json!({
        "role_claim": "ext.roles",
        "consumer_identity_claim": "ext.email",
        "providers": [{
            "introspection_endpoint": hydra.introspection_endpoint(),
            "client_auth": {
                "method": "client_secret_basic",
                "client_id": claim_client.client_id,
                "client_secret": claim_client.client_secret
            },
            "required_roles": [FIXTURE_ROLE],
            "claim_headers": {
                "ext.email": "X-Introspected-Email",
                "ext.roles": "X-Introspected-Roles"
            }
        }]
    }));
    let mut claim_ctx = bearer_ctx(&claim_token);
    claim_ctx
        .headers
        .insert("x-introspected-email".to_string(), "evil@attacker".into());
    assert_eq!(
        reject_status(
            &claim_plugin
                .authenticate(&mut claim_ctx, &ConsumerIndex::new(&[]))
                .await
        ),
        None
    );
    assert_eq!(
        claim_ctx.authenticated_identity.as_deref(),
        Some(FIXTURE_EMAIL)
    );
    let mut claim_upstream = claim_ctx.headers.clone();
    assert!(matches!(
        claim_plugin
            .before_proxy(&mut claim_ctx, &mut claim_upstream)
            .await,
        PluginResult::Continue
    ));
    assert_eq!(
        claim_upstream
            .get("x-introspected-email")
            .map(String::as_str),
        Some(FIXTURE_EMAIL)
    );
    assert!(
        claim_upstream
            .get("x-introspected-roles")
            .is_some_and(|roles| roles.contains(FIXTURE_ROLE)),
        "roles claim must reach the configured upstream header"
    );

    let wrong_role = introspection_plugin(json!({
        "role_claim": "ext.roles",
        "providers": [{
            "introspection_endpoint": hydra.introspection_endpoint(),
            "client_auth": {
                "method": "client_secret_basic",
                "client_id": claim_client.client_id,
                "client_secret": claim_client.client_secret
            },
            "required_roles": ["administrator"]
        }]
    }));
    let mut wrong_role_ctx = bearer_ctx(&claim_token);
    assert_eq!(
        reject_status(
            &wrong_role
                .authenticate(&mut wrong_role_ctx, &ConsumerIndex::new(&[]))
                .await
        ),
        Some(403),
        "a live token missing the configured role must be denied"
    );
}

#[tokio::test]
#[serial]
async fn oauth2_live_introspection_failure_policy() {
    let Some(hydra) = hydra_ready("oauth2_live_introspection_failure_policy").await else {
        return;
    };
    let redirect = "http://127.0.0.1/oauth/callback";
    let client = hydra
        .create_client(
            "intro-fail",
            redirect,
            TokenEndpointAuthMethod::ClientSecretBasic,
            &["client_credentials"],
        )
        .await
        .expect("failure-policy client");
    let good_token = hydra
        .client_credentials_token(&client, "profile", None)
        .await
        .expect("token for mixed tests");

    // Hydra admin introspect does not enforce client authentication, so a
    // wrong secret against that URL is not an auth-failure proof. Auth failure
    // fail-closed is covered by the wiremock 401 case below.

    let unavailable = introspection_plugin(json!({
        "providers": [{
            "introspection_endpoint": "http://127.0.0.1:9/oauth2/introspect",
            "client_auth": {
                "method": "client_secret_basic",
                "client_id": client.client_id,
                "client_secret": client.client_secret
            },
            "request_timeout_ms": 500
        }]
    }));
    let mut ctx = bearer_ctx(&good_token);
    assert_eq!(
        reject_status(
            &unavailable
                .authenticate(&mut ctx, &ConsumerIndex::new(&[]))
                .await
        ),
        Some(503)
    );

    // Adversarial responses the real IdP will not produce — still Ferrum paths.
    let timeout_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/introspect"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_delay(Duration::from_secs(3))
                .set_body_json(json!({"active": true})),
        )
        .mount(&timeout_server)
        .await;
    let timeout_plugin = introspection_plugin(json!({
        "providers": [{
            "introspection_endpoint": format!("{}/introspect", timeout_server.uri()),
            "client_auth": {"method": "none"},
            "request_timeout_ms": 200
        }]
    }));
    let mut ctx = bearer_ctx("timeout-token");
    assert_eq!(
        reject_status(
            &timeout_plugin
                .authenticate(&mut ctx, &ConsumerIndex::new(&[]))
                .await
        ),
        Some(503),
        "provider timeout → 503"
    );

    let malformed_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/introspect"))
        .respond_with(ResponseTemplate::new(200).set_body_string("not-json{"))
        .mount(&malformed_server)
        .await;
    let malformed_plugin = introspection_plugin(json!({
        "providers": [{
            "introspection_endpoint": format!("{}/introspect", malformed_server.uri()),
            "client_auth": {"method": "none"},
            "request_timeout_ms": 2000
        }]
    }));
    let mut ctx = bearer_ctx("malformed-token");
    assert_eq!(
        reject_status(
            &malformed_plugin
                .authenticate(&mut ctx, &ConsumerIndex::new(&[]))
                .await
        ),
        Some(503),
        "malformed introspection JSON → 503"
    );

    let oversized_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/introspect"))
        .respond_with(ResponseTemplate::new(200).set_body_string("x".repeat(70 * 1024)))
        .mount(&oversized_server)
        .await;
    let oversized_plugin = introspection_plugin(json!({
        "providers": [{
            "introspection_endpoint": format!("{}/introspect", oversized_server.uri()),
            "client_auth": {"method": "none"},
            "request_timeout_ms": 2000
        }]
    }));
    let mut ctx = bearer_ctx("oversized-token");
    assert_eq!(
        reject_status(
            &oversized_plugin
                .authenticate(&mut ctx, &ConsumerIndex::new(&[]))
                .await
        ),
        Some(503),
        "oversized introspection body → 503"
    );

    // Auth failure against wiremock that rejects Basic credentials.
    let auth_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/introspect"))
        .respond_with(ResponseTemplate::new(401).set_body_json(json!({"error": "invalid_client"})))
        .mount(&auth_server)
        .await;
    let auth_fail = introspection_plugin(json!({
        "providers": [{
            "introspection_endpoint": format!("{}/introspect", auth_server.uri()),
            "client_auth": {
                "method": "client_secret_basic",
                "client_id": "mock-client",
                "client_secret": "mock-secret"
            },
            "request_timeout_ms": 2000
        }]
    }));
    let mut ctx = bearer_ctx("auth-fail-token");
    assert_eq!(
        reject_status(
            &auth_fail
                .authenticate(&mut ctx, &ConsumerIndex::new(&[]))
                .await
        ),
        Some(503),
        "introspection auth failure → 503"
    );

    // Live Hydra still works after adversarial cases (no cross-contamination).
    let live = introspection_plugin(json!({
        "providers": [{
            "introspection_endpoint": hydra.introspection_endpoint(),
            "client_auth": {
                "method": "client_secret_basic",
                "client_id": client.client_id,
                "client_secret": client.client_secret
            }
        }]
    }));
    let mut ctx = bearer_ctx(&good_token);
    assert_eq!(
        reject_status(&live.authenticate(&mut ctx, &ConsumerIndex::new(&[])).await),
        None
    );
}
