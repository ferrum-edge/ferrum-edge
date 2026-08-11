use async_trait::async_trait;
use base64::Engine as _;
use ferrum_edge::ConsumerIndex;
use ferrum_edge::config::types::AuthMode;
use ferrum_edge::plugins::{
    Plugin, PluginHttpClient, PluginResult, RequestContext, key_auth::KeyAuth,
    oauth2_introspection::Oauth2Introspection, priority,
};
use ferrum_edge::proxy::run_authentication_phase;
use futures_util::future::join_all;
use serde_json::json;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use super::plugin_utils::{assert_continue, create_test_consumer};

struct InvalidSecondaryAuth;

#[test]
fn oauth2_custom_header_locations_are_registered_as_credentials() {
    let plugin = Oauth2Introspection::new(
        &json!({
            "providers": [{
                "introspection_endpoint": "http://127.0.0.1:8181/introspect",
                "client_auth": {"method": "none"},
                "from_headers": [{"name": "X-Opaque-Token"}]
            }]
        }),
        PluginHttpClient::default(),
    )
    .unwrap();

    assert_eq!(plugin.request_headers_to_redact(), &["x-opaque-token"]);
}

#[test]
fn oauth2_marks_forwarded_custom_query_locations_for_opa_redaction() {
    let plugin = Oauth2Introspection::new(
        &json!({
            "providers": [{
                "introspection_endpoint": "http://127.0.0.1:8181/introspect",
                "client_auth": {"method": "none"},
                "from_params": ["opaque_sso_token"],
                "forward_original_token": true
            }]
        }),
        PluginHttpClient::default(),
    )
    .unwrap();
    let mut ctx = RequestContext::new("127.0.0.1".into(), "GET".into(), "/test".into());
    ctx.query_params.insert(
        "opaque_sso_token".to_string(),
        "forwarded-opaque-token".to_string(),
    );

    plugin.mark_query_credentials_for_redaction(&mut ctx);

    assert_eq!(
        ctx.metadata
            .get("auth.query_credential_param.opaque_sso_token")
            .map(String::as_str),
        Some("true")
    );
    assert_eq!(
        ctx.query_params.get("opaque_sso_token").map(String::as_str),
        Some("forwarded-opaque-token"),
        "OPA redaction markers must not change backend forwarding semantics"
    );
}

#[async_trait]
impl Plugin for InvalidSecondaryAuth {
    fn name(&self) -> &str {
        "invalid_secondary_auth"
    }

    fn is_auth_plugin(&self) -> bool {
        true
    }

    async fn authenticate(
        &self,
        _ctx: &mut RequestContext,
        _consumer_index: &ConsumerIndex,
    ) -> PluginResult {
        PluginResult::Reject {
            status_code: 401,
            body: r#"{"error":"Invalid secondary credential"}"#.to_string(),
            headers: HashMap::new(),
        }
    }
}

fn make_ctx(token: &str) -> RequestContext {
    let mut ctx = RequestContext::new("127.0.0.1".into(), "GET".into(), "/test".into());
    ctx.headers
        .insert("authorization".to_string(), format!("Bearer {token}"));
    ctx
}

fn config(endpoint: &str) -> serde_json::Value {
    json!({
        "providers": [{
            "introspection_endpoint": endpoint,
            "client_auth": {"method": "none"}
        }]
    })
}

fn config_with_client_auth(endpoint: &str, method: &str) -> serde_json::Value {
    json!({
        "providers": [{
            "introspection_endpoint": endpoint,
            "client_auth": {
                "method": method,
                "client_id": "cid",
                "client_secret": "shhh",
                "private_key_pem": "not-a-real-pem"
            }
        }]
    })
}

fn discovery_config_with_client_auth(discovery_url: &str, method: &str) -> serde_json::Value {
    json!({
        "providers": [{
            "discovery_url": discovery_url,
            "client_auth": {
                "method": method,
                "client_id": "cid",
                "client_secret": "shhh"
            }
        }]
    })
}

fn assert_bearer_reject(result: PluginResult, status: u16, error: &str) {
    match result {
        PluginResult::Reject {
            status_code,
            headers,
            ..
        } => {
            assert_eq!(status_code, status);
            let challenge = headers
                .iter()
                .find_map(|(name, value)| {
                    name.eq_ignore_ascii_case("www-authenticate")
                        .then_some(value.as_str())
                })
                .expect("Bearer rejection must include a challenge");
            assert_eq!(challenge, format!(r#"Bearer error="{error}""#));
        }
        other => panic!("expected rejection, got {other:?}"),
    }
}

fn assert_plain_reject(result: PluginResult, status: u16) {
    match result {
        PluginResult::Reject {
            status_code,
            headers,
            ..
        } => {
            assert_eq!(status_code, status);
            assert!(
                headers
                    .keys()
                    .all(|name| !name.eq_ignore_ascii_case("www-authenticate"))
            );
        }
        other => panic!("expected rejection, got {other:?}"),
    }
}

#[test]
fn new_rejects_empty_providers() {
    assert!(
        Oauth2Introspection::new(&json!({"providers": []}), PluginHttpClient::default()).is_err()
    );
}

#[test]
fn new_rejects_unbounded_and_impossible_cache_budgets() {
    let endpoint = "http://127.0.0.1:8181/introspect";
    let million_entries = Oauth2Introspection::new(
        &json!({
            "providers": [{
                "introspection_endpoint": endpoint,
                "client_auth": {"method": "none"},
                "max_cache_entries": 1_000_000
            }]
        }),
        PluginHttpClient::default(),
    )
    .err()
    .expect("one million cache entries must exceed the hard maximum");
    assert!(million_entries.contains("max_cache_entries"));
    assert!(million_entries.contains("between 100 and 100000"));

    let impossible_total = Oauth2Introspection::new(
        &json!({
            "providers": [{
                "introspection_endpoint": endpoint,
                "client_auth": {"method": "none"},
                "max_cache_entries": 100_000,
                "max_cache_entry_bytes": 65_536,
                "max_cache_total_bytes": 1_048_576
            }]
        }),
        PluginHttpClient::default(),
    )
    .err()
    .expect("a total budget below the cache's minimum footprint must fail");
    assert!(impossible_total.contains("max_cache_total_bytes"));
    assert!(impossible_total.contains("must be at least"));
}

#[test]
fn new_rejects_credentialed_client_auth_for_remote_http_endpoint() {
    // The invalid private-key PEM is intentional: private_key_jwt must fail on
    // the plaintext remote endpoint before any secret material is parsed.
    for method in [
        "client_secret_basic",
        "client_secret_post",
        "private_key_jwt",
    ] {
        let err = Oauth2Introspection::new(
            &config_with_client_auth("http://idp.internal/introspect", method),
            PluginHttpClient::default(),
        )
        .err()
        .expect("remote http endpoint should reject credentialed auth");
        assert!(
            err.contains("requires an https"),
            "method {method} produced unexpected error: {err}"
        );
    }
}

#[test]
fn new_accepts_credentialed_client_auth_for_remote_https_endpoint() {
    for method in ["client_secret_basic", "client_secret_post"] {
        assert!(
            Oauth2Introspection::new(
                &config_with_client_auth("https://idp.internal/introspect", method),
                PluginHttpClient::default(),
            )
            .is_ok(),
            "method {method} should accept remote https endpoint"
        );
    }
}

#[test]
fn new_accepts_credentialed_client_auth_for_loopback_http_endpoint() {
    for endpoint in [
        "http://localhost:9000/introspect",
        "http://127.0.0.1:9000/introspect",
        "http://[::1]:9000/introspect",
    ] {
        assert!(
            Oauth2Introspection::new(
                &config_with_client_auth(endpoint, "client_secret_basic"),
                PluginHttpClient::default(),
            )
            .is_ok(),
            "loopback http endpoint {endpoint} should be accepted"
        );
    }
}

#[test]
fn new_accepts_credentialed_client_auth_with_discovery_url_outside_tokio() {
    assert!(
        Oauth2Introspection::new(
            &discovery_config_with_client_auth(
                "https://issuer.example.com/.well-known/openid-configuration",
                "client_secret_basic",
            ),
            PluginHttpClient::default(),
        )
        .is_ok()
    );
}

#[test]
fn new_rejects_none_client_auth_for_remote_endpoint() {
    let err = match Oauth2Introspection::new(
        &json!({
            "providers": [{
                "introspection_endpoint": "https://auth.example.com/introspect",
                "client_auth": {"method": "none"}
            }]
        }),
        PluginHttpClient::default(),
    ) {
        Ok(_) => panic!("remote none auth should reject"),
        Err(err) => err,
    };
    assert!(err.contains("only allowed"));
}

#[test]
fn new_accepts_none_client_auth_for_localhost_endpoint() {
    assert!(
        Oauth2Introspection::new(
            &json!({
                "providers": [{
                    "introspection_endpoint": "http://localhost:8080/introspect",
                    "client_auth": {"method": "none"}
                }]
            }),
            PluginHttpClient::default(),
        )
        .is_ok()
    );
}

#[test]
fn new_rejects_none_client_auth_for_local_mdns_endpoint() {
    assert!(
        Oauth2Introspection::new(
            &json!({
                "providers": [{
                    "introspection_endpoint": "http://idp.local/introspect",
                    "client_auth": {"method": "none"}
                }]
            }),
            PluginHttpClient::default(),
        )
        .is_err()
    );
}

#[tokio::test]
async fn active_token_sets_authenticated_identity_when_no_consumer_match() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/introspect"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "active": true,
            "username": "external-user",
            "scope": "read:data"
        })))
        .mount(&server)
        .await;

    let endpoint = format!("{}/introspect", server.uri());
    let plugin = Oauth2Introspection::new(&config(&endpoint), PluginHttpClient::default()).unwrap();
    assert_eq!(plugin.priority(), priority::OAUTH2_INTROSPECTION);
    // Keep token values distinct so each assertion exercises its intended path.
    let mut ctx = make_ctx("active-opaque-token");
    let result = plugin
        .authenticate(&mut ctx, &ConsumerIndex::new(&[]))
        .await;
    assert_continue(result);
    assert_eq!(ctx.authenticated_identity.as_deref(), Some("external-user"));
    assert_eq!(ctx.auth_method, Some("oauth2_introspection"));
}

#[tokio::test]
async fn active_token_with_blank_identity_does_not_authenticate_principal() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/introspect"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "active": true,
            "username": "   \t"
        })))
        .mount(&server)
        .await;

    let endpoint = format!("{}/introspect", server.uri());
    let plugin = Oauth2Introspection::new(&config(&endpoint), PluginHttpClient::default()).unwrap();
    let mut ctx = make_ctx("blank-identity-token");
    let result = plugin
        .authenticate(&mut ctx, &ConsumerIndex::new(&[]))
        .await;

    assert_continue(result);
    assert!(ctx.authenticated_identity.is_none());
    assert!(ctx.effective_identity().is_none());
    assert!(ctx.auth_method.is_none());
}

#[tokio::test]
async fn oauth_multi_auth_does_not_commit_blank_principal_side_effects() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/introspect"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "active": true,
            "username": "   ",
            "email": "untrusted@example.test"
        })))
        .mount(&server)
        .await;

    let oauth = Arc::new(
        Oauth2Introspection::new(
            &json!({
                "providers": [{
                    "introspection_endpoint": format!("{}/introspect", server.uri()),
                    "client_auth": {"method": "none"},
                    "forward_original_token": false,
                    "claim_headers": {"email": "X-Untrusted-Email"}
                }]
            }),
            PluginHttpClient::default(),
        )
        .unwrap(),
    );
    let key_auth: Arc<dyn Plugin> =
        Arc::new(KeyAuth::new(&json!({"key_location": "header:X-API-Key"})).unwrap());
    let consumers = [create_test_consumer()];
    let consumer_index = ConsumerIndex::new(&consumers);
    let mut ctx = make_ctx("blank-principal-token");
    ctx.headers
        .insert("x-api-key".to_string(), "test-api-key".to_string());
    let oauth_plugin: Arc<dyn Plugin> = oauth.clone();

    let rejection = run_authentication_phase(
        AuthMode::Multi,
        &[oauth_plugin, key_auth],
        &mut ctx,
        &consumer_index,
    )
    .await;
    assert!(rejection.is_none(), "later key_auth must authenticate");
    assert_eq!(ctx.auth_method, Some("key_auth"));

    let mut headers = ctx.headers.clone();
    assert_continue(oauth.before_proxy(&mut ctx, &mut headers).await);
    assert_eq!(
        headers.get("authorization").map(String::as_str),
        Some("Bearer blank-principal-token")
    );
    assert!(!headers.contains_key("x-untrusted-email"));
}

#[tokio::test]
async fn inactive_token_rejects_with_401() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/introspect"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"active": false})))
        .mount(&server)
        .await;

    let endpoint = format!("{}/introspect", server.uri());
    let plugin = Oauth2Introspection::new(&config(&endpoint), PluginHttpClient::default()).unwrap();
    let mut ctx = make_ctx("inactive-opaque-token");
    let result = plugin
        .authenticate(&mut ctx, &ConsumerIndex::new(&[]))
        .await;
    assert_bearer_reject(result, 401, "invalid_token");
    assert_bearer_reject(
        plugin
            .authenticate(
                &mut make_ctx("inactive-opaque-token"),
                &ConsumerIndex::new(&[]),
            )
            .await,
        401,
        "invalid_token",
    );
    assert_eq!(server.received_requests().await.unwrap().len(), 1);
}

#[tokio::test]
async fn separate_plugin_instances_do_not_share_policy_decisions() {
    // Each live policy owns its cache. A token accepted by a permissive instance
    // must be introspected again by a stricter instance sharing the endpoint.
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/introspect"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "active": true,
            "username": "external-user",
            "iss": "https://issuer-a.example",
            "aud": "audience-a"
        })))
        .mount(&server)
        .await;
    let endpoint = format!("{}/introspect", server.uri());

    // Permissive provider: no issuer/audience constraints -> accepts and caches.
    let permissive = Oauth2Introspection::new(
        &json!({
            "providers": [{
                "introspection_endpoint": endpoint,
                "client_auth": {"method": "none"}
            }]
        }),
        PluginHttpClient::default(),
    )
    .unwrap();

    // Stricter provider: same endpoint + client auth, but enforces a different
    // issuer/audience than the introspection response carries.
    let strict = Oauth2Introspection::new(
        &json!({
            "providers": [{
                "introspection_endpoint": endpoint,
                "client_auth": {"method": "none"},
                "issuer": "https://issuer-b.example",
                "audiences": ["audience-b"]
            }]
        }),
        PluginHttpClient::default(),
    )
    .unwrap();

    let consumers = ConsumerIndex::new(&[]);

    // Permissive provider accepts and populates its positive cache.
    let mut ctx = make_ctx("shared-token");
    assert_continue(permissive.authenticate(&mut ctx, &consumers).await);

    // Stricter provider must re-validate issuer/audience instead of reusing the
    // permissive provider's cached claims, so it rejects with 401.
    let mut ctx = make_ctx("shared-token");
    assert_bearer_reject(
        strict.authenticate(&mut ctx, &consumers).await,
        401,
        "invalid_token",
    );
}

#[tokio::test]
async fn claims_to_headers_and_forward_original_false_strip_authorization() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/introspect"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "active": true,
            "username": "external-user",
            "email": "user@example.com"
        })))
        .mount(&server)
        .await;

    let endpoint = format!("{}/introspect", server.uri());
    let plugin = Oauth2Introspection::new(
        &json!({
            "providers": [{
                "introspection_endpoint": endpoint,
                "client_auth": {"method": "none"},
                "forward_original_token": false,
                "claim_headers": {"email": "X-User-Email"}
            }]
        }),
        PluginHttpClient::default(),
    )
    .unwrap();
    let mut ctx = make_ctx("claims-opaque-token");
    let result = plugin
        .authenticate(&mut ctx, &ConsumerIndex::new(&[]))
        .await;
    assert_continue(result);

    let mut headers = HashMap::from([(
        "authorization".to_string(),
        "Bearer claims-opaque-token".to_string(),
    )]);
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);
    assert!(!headers.contains_key("authorization"));
    assert_eq!(
        headers.get("x-user-email").map(String::as_str),
        Some("user@example.com")
    );
    assert_eq!(
        ctx.authenticated_identity_header.as_deref(),
        Some("external-user")
    );
}

#[tokio::test]
async fn principal_less_introspection_attempt_does_not_mutate_later_key_auth_request() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/introspect"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "active": true,
            "principal": "   ",
            "display_name": "Header Without Principal",
            "email": "unaccepted@example.com"
        })))
        .mount(&server)
        .await;

    let introspection = Arc::new(
        Oauth2Introspection::new(
            &json!({"providers": [{
                "introspection_endpoint": format!("{}/introspect", server.uri()),
                "client_auth": {"method": "none"},
                "from_params": ["access_token"],
                "forward_original_token": false,
                "consumer_identity_claim": "principal",
                "consumer_header_claim": "display_name",
                "claim_headers": {"email": "X-User-Email"}
            }]}),
            PluginHttpClient::default(),
        )
        .expect("valid introspection config"),
    );
    let key_auth = Arc::new(KeyAuth::new(&json!({})).expect("valid key auth config"));
    let auth_plugins: Vec<Arc<dyn Plugin>> = vec![introspection.clone(), key_auth];
    let consumer_index = ConsumerIndex::new(&[create_test_consumer()]);
    let mut ctx = RequestContext::new("127.0.0.1".into(), "GET".into(), "/test".into());
    ctx.query_params
        .insert("access_token".to_string(), "opaque-token".to_string());
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
    assert_eq!(
        ctx.query_params.get("access_token").map(String::as_str),
        Some("opaque-token")
    );
    assert!(
        !ctx.metadata
            .contains_key("auth.strip_query_param.access_token")
    );
    assert!(
        !ctx.metadata
            .values()
            .any(|value| value == "unaccepted@example.com")
    );

    let mut headers = ctx.headers.clone();
    assert_continue(introspection.before_proxy(&mut ctx, &mut headers).await);
    assert!(!headers.contains_key("x-user-email"));
}

#[tokio::test]
async fn multi_provider_falls_through_to_provider_that_accepts_token() {
    // Two providers share the default Authorization-bearer token location (the
    // common multi-IdP setup). The first provider does not recognize the token
    // (active:false); the second does. Routing must try the second provider
    // instead of rejecting on the first provider's verdict.
    let provider_a = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/introspect"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"active": false})))
        .mount(&provider_a)
        .await;
    let provider_b = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/introspect"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "active": true,
            "username": "user-from-b"
        })))
        .mount(&provider_b)
        .await;

    let plugin = Oauth2Introspection::new(
        &json!({
            "allow_provider_fanout": true,
            "providers": [
                {
                    "introspection_endpoint": format!("{}/introspect", provider_a.uri()),
                    "client_auth": {"method": "none"}
                },
                {
                    "introspection_endpoint": format!("{}/introspect", provider_b.uri()),
                    "client_auth": {"method": "none"}
                }
            ]
        }),
        PluginHttpClient::default(),
    )
    .unwrap();

    let mut ctx = make_ctx("token-owned-by-provider-b");
    let result = plugin
        .authenticate(&mut ctx, &ConsumerIndex::new(&[]))
        .await;
    assert_continue(result);
    assert_eq!(ctx.authenticated_identity.as_deref(), Some("user-from-b"));
    assert_eq!(ctx.auth_method, Some("oauth2_introspection"));
}

#[tokio::test]
async fn query_param_token_marks_shared_strip_prefix_for_proxy() {
    // forward_original_token=false on a query-param token must mark the param for
    // stripping with the shared `auth.strip_query_param.` prefix the proxy honors.
    // oauth2 previously used a private prefix the proxy ignored, leaking the token
    // to the backend.
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/introspect"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"active": true, "username": "u"})),
        )
        .mount(&server)
        .await;
    let plugin = Oauth2Introspection::new(
        &json!({
            "providers": [{
                "introspection_endpoint": format!("{}/introspect", server.uri()),
                "client_auth": {"method": "none"},
                "from_params": ["access_token"],
                "forward_original_token": false
            }]
        }),
        PluginHttpClient::default(),
    )
    .unwrap();
    let mut ctx = RequestContext::new("127.0.0.1".into(), "GET".into(), "/test".into());
    ctx.query_params
        .insert("access_token".to_string(), "qp-opaque-token".to_string());
    assert_continue(
        plugin
            .authenticate(&mut ctx, &ConsumerIndex::new(&[]))
            .await,
    );
    assert!(
        ctx.metadata
            .contains_key("auth.strip_query_param.access_token")
    );
    assert!(!ctx.query_params.contains_key("access_token"));
}

#[test]
fn new_rejects_unknown_fields_at_every_config_layer() {
    let configs = [
        json!({
            "providers": [{
                "introspection_endpoint": "http://localhost/introspect",
                "client_auth": {"method": "none"}
            }],
            "required_scope": ["read"]
        }),
        json!({
            "providers": [{
                "introspection_endpoint": "http://localhost/introspect",
                "client_auth": {"method": "none"},
                "audience": "api"
            }]
        }),
        json!({
            "providers": [{
                "introspection_endpoint": "http://localhost/introspect",
                "client_auth": {"method": "none", "client_secert": "typo"}
            }]
        }),
        json!({
            "providers": [{
                "introspection_endpoint": "http://localhost/introspect",
                "client_auth": {"method": "none"},
                "from_headers": [{"name": "x-token", "prefx": "Token "}]
            }]
        }),
    ];

    for config in configs {
        let error = Oauth2Introspection::new(&config, PluginHttpClient::default())
            .err()
            .expect("unknown config key must fail closed");
        assert!(error.contains("unknown field"), "unexpected error: {error}");
    }
}

#[test]
fn new_bounds_provider_count_and_requires_explicit_shared_trust_for_fanout() {
    let provider = json!({
        "introspection_endpoint": "http://localhost/introspect",
        "client_auth": {"method": "none"}
    });
    assert!(
        Oauth2Introspection::new(
            &json!({"providers": vec![provider.clone(); 17]}),
            PluginHttpClient::default(),
        )
        .is_err()
    );
    let error = Oauth2Introspection::new(
        &json!({"providers": [provider.clone(), provider]}),
        PluginHttpClient::default(),
    )
    .err()
    .expect("ambiguous Authorization fanout must require explicit trust");
    assert!(error.contains("allow_provider_fanout"));

    let duplicate_location = json!({
        "introspection_endpoint": "http://localhost/introspect",
        "client_auth": {"method": "none"},
        "from_headers": [{"name": "x-tenant-token"}]
    });
    assert!(
        Oauth2Introspection::new(
            &json!({"providers": [duplicate_location.clone(), duplicate_location]}),
            PluginHttpClient::default(),
        )
        .is_err()
    );

    let implicit_authorization = json!({
        "introspection_endpoint": "http://localhost/introspect",
        "client_auth": {"method": "none"}
    });
    for from_headers in [
        json!([{"name": "Authorization", "prefix": "bEaReR "}]),
        json!([{"name": "Authorization"}]),
    ] {
        let explicit_authorization = json!({
            "introspection_endpoint": "http://localhost/introspect",
            "client_auth": {"method": "none"},
            "from_headers": from_headers
        });
        let error = Oauth2Introspection::new(
            &json!({"providers": [implicit_authorization.clone(), explicit_authorization]}),
            PluginHttpClient::default(),
        )
        .err()
        .expect("explicit and implicit Authorization bearer sources must conflict");
        assert!(error.contains("allow_provider_fanout"));
    }
}

#[tokio::test]
async fn authorization_scheme_is_case_insensitive_and_non_bearer_is_skipped() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/introspect"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"active": true, "username": "u"})),
        )
        .mount(&server)
        .await;
    let endpoint = format!("{}/introspect", server.uri());
    let plugin = Oauth2Introspection::new(&config(&endpoint), PluginHttpClient::default()).unwrap();

    for (scheme, token) in [("BEARER", "uppercase-token"), ("bEaReR", "mixed-token")] {
        let mut ctx = RequestContext::new("127.0.0.1".into(), "GET".into(), "/test".into());
        ctx.headers
            .insert("authorization".to_string(), format!("{scheme} {token}"));
        assert_continue(
            plugin
                .authenticate(&mut ctx, &ConsumerIndex::new(&[]))
                .await,
        );
    }

    let mut ctx = RequestContext::new("127.0.0.1".into(), "GET".into(), "/test".into());
    ctx.headers.insert(
        "authorization".to_string(),
        "Basic not-a-bearer-token".to_string(),
    );
    assert_continue(
        plugin
            .authenticate(&mut ctx, &ConsumerIndex::new(&[]))
            .await,
    );
    assert_eq!(server.received_requests().await.unwrap().len(), 2);
}

#[tokio::test]
async fn prefixless_authorization_location_skips_foreign_scheme() {
    let server = MockServer::start().await;
    let plugin = Oauth2Introspection::new(
        &json!({
            "providers": [{
                "introspection_endpoint": format!("{}/introspect", server.uri()),
                "client_auth": {"method": "none"},
                "from_headers": [{"name": "Authorization"}]
            }]
        }),
        PluginHttpClient::default(),
    )
    .unwrap();
    let mut ctx = RequestContext::new("127.0.0.1".into(), "GET".into(), "/test".into());
    ctx.headers.insert(
        "authorization".to_string(),
        "Basic dXNlcjpwYXNz".to_string(),
    );

    assert_continue(
        plugin
            .authenticate(&mut ctx, &ConsumerIndex::new(&[]))
            .await,
    );
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn explicit_authorization_location_routes_case_insensitive_bearer_scheme() {
    let authorization_provider = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/introspect"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"active": true, "username": "u"})),
        )
        .mount(&authorization_provider)
        .await;
    let other_provider = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"active": false})))
        .mount(&other_provider)
        .await;
    let plugin = Oauth2Introspection::new(
        &json!({
            "providers": [
                {
                    "introspection_endpoint": format!(
                        "{}/introspect",
                        authorization_provider.uri()
                    ),
                    "client_auth": {"method": "none"},
                    "from_headers": [{"name": "Authorization", "prefix": "Bearer "}]
                },
                {
                    "introspection_endpoint": format!("{}/introspect", other_provider.uri()),
                    "client_auth": {"method": "none"},
                    "from_headers": [{"name": "x-other-provider-token"}]
                }
            ]
        }),
        PluginHttpClient::default(),
    )
    .unwrap();
    let mut ctx = RequestContext::new("127.0.0.1".into(), "GET".into(), "/test".into());
    ctx.headers.insert(
        "authorization".to_string(),
        "bEaReR explicit-provider-token".to_string(),
    );
    assert_continue(
        plugin
            .authenticate(&mut ctx, &ConsumerIndex::new(&[]))
            .await,
    );
    assert_eq!(
        authorization_provider
            .received_requests()
            .await
            .unwrap()
            .len(),
        1
    );
    assert!(other_provider.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn malformed_active_values_are_503_and_never_negative_cached() {
    let server = MockServer::start().await;
    let responses = Arc::new([
        json!({}),
        json!({"active": null}),
        json!({"active": "true"}),
        json!({"active": 1}),
        json!({"active": true, "username": "recovered"}),
    ]);
    let calls = Arc::new(AtomicUsize::new(0));
    Mock::given(method("POST"))
        .and(path("/introspect"))
        .respond_with({
            let responses = Arc::clone(&responses);
            let calls = Arc::clone(&calls);
            move |_: &wiremock::Request| {
                let index = calls
                    .fetch_add(1, Ordering::SeqCst)
                    .min(responses.len() - 1);
                ResponseTemplate::new(200).set_body_json(responses[index].clone())
            }
        })
        .mount(&server)
        .await;
    let endpoint = format!("{}/introspect", server.uri());
    let plugin = Oauth2Introspection::new(&config(&endpoint), PluginHttpClient::default()).unwrap();

    for token in ["missing", "null", "string", "number"] {
        assert_plain_reject(
            plugin
                .authenticate(&mut make_ctx(token), &ConsumerIndex::new(&[]))
                .await,
            503,
        );
    }
    assert_continue(
        plugin
            .authenticate(&mut make_ctx("missing"), &ConsumerIndex::new(&[]))
            .await,
    );
    assert_eq!(calls.load(Ordering::SeqCst), 5);
}

#[tokio::test]
async fn provider_failures_are_503_without_bearer_challenges() {
    let cases = [
        ResponseTemplate::new(500),
        ResponseTemplate::new(200).set_body_raw("not-json", "application/json"),
        ResponseTemplate::new(200)
            .set_delay(Duration::from_millis(300))
            .set_body_json(json!({"active": true})),
    ];
    for (index, response) in cases.into_iter().enumerate() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/introspect"))
            .respond_with(response)
            .mount(&server)
            .await;
        let plugin = Oauth2Introspection::new(
            &json!({
                "providers": [{
                    "introspection_endpoint": format!("{}/introspect", server.uri()),
                    "client_auth": {"method": "none"},
                    "request_timeout_ms": 100
                }]
            }),
            PluginHttpClient::default(),
        )
        .unwrap();
        assert_plain_reject(
            plugin
                .authenticate(
                    &mut make_ctx(&format!("provider-failure-{index}")),
                    &ConsumerIndex::new(&[]),
                )
                .await,
            503,
        );
    }

    let plugin = Oauth2Introspection::new(
        &config("http://127.0.0.1:1/introspect"),
        PluginHttpClient::default(),
    )
    .unwrap();
    assert_plain_reject(
        plugin
            .authenticate(&mut make_ctx("transport-failure"), &ConsumerIndex::new(&[]))
            .await,
        503,
    );
}

#[tokio::test]
async fn unavailable_provider_takes_precedence_over_inactive_fanout_result() {
    let inactive = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/introspect"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"active": false})))
        .mount(&inactive)
        .await;
    let unavailable = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/introspect"))
        .respond_with(ResponseTemplate::new(503))
        .mount(&unavailable)
        .await;
    let plugin = Oauth2Introspection::new(
        &json!({
            "allow_provider_fanout": true,
            "providers": [
                {
                    "introspection_endpoint": format!("{}/introspect", inactive.uri()),
                    "client_auth": {"method": "none"}
                },
                {
                    "introspection_endpoint": format!("{}/introspect", unavailable.uri()),
                    "client_auth": {"method": "none"}
                }
            ]
        }),
        PluginHttpClient::default(),
    )
    .unwrap();
    assert_plain_reject(
        plugin
            .authenticate(
                &mut make_ctx("mixed-verdict-token"),
                &ConsumerIndex::new(&[]),
            )
            .await,
        503,
    );
}

#[tokio::test]
async fn provider_unavailable_survives_later_multi_auth_401() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/introspect"))
        .respond_with(ResponseTemplate::new(503))
        .mount(&server)
        .await;
    let oauth = Arc::new(
        Oauth2Introspection::new(
            &json!({
                "providers": [{
                    "introspection_endpoint": format!("{}/introspect", server.uri()),
                    "client_auth": {"method": "none"},
                    "forward_original_token": false,
                    "claim_headers": {"email": "X-Untrusted-Email"}
                }]
            }),
            PluginHttpClient::default(),
        )
        .unwrap(),
    );
    let oauth_plugin: Arc<dyn Plugin> = oauth.clone();
    let invalid_secondary: Arc<dyn Plugin> = Arc::new(InvalidSecondaryAuth);
    let mut ctx = make_ctx("provider-outage-token");
    let rejection = run_authentication_phase(
        AuthMode::Multi,
        &[oauth_plugin, invalid_secondary],
        &mut ctx,
        &ConsumerIndex::new(&[]),
    )
    .await
    .expect("provider outage must fail closed");
    assert_eq!(rejection.0, 503);
    assert!(
        rejection
            .2
            .keys()
            .all(|name| !name.eq_ignore_ascii_case("www-authenticate"))
    );
    let mut headers = ctx.headers.clone();
    assert_continue(oauth.before_proxy(&mut ctx, &mut headers).await);
    assert_eq!(
        headers.get("authorization").map(String::as_str),
        Some("Bearer provider-outage-token")
    );
    assert!(!headers.contains_key("x-untrusted-email"));
}

#[tokio::test]
async fn missing_credentials_advertise_bearer_in_single_and_multi_auth_modes() {
    for auth_mode in [AuthMode::Single, AuthMode::Multi] {
        let plugin: Arc<dyn Plugin> = Arc::new(
            Oauth2Introspection::new(
                &config("http://localhost/introspect"),
                PluginHttpClient::default(),
            )
            .unwrap(),
        );
        let mut ctx = RequestContext::new("127.0.0.1".into(), "GET".into(), "/test".into());
        let rejection =
            run_authentication_phase(auth_mode, &[plugin], &mut ctx, &ConsumerIndex::new(&[]))
                .await
                .expect("missing authentication must reject");
        assert_eq!(rejection.0, 401);
        assert_eq!(
            rejection.2.iter().find_map(|(name, value)| {
                name.eq_ignore_ascii_case("www-authenticate")
                    .then_some(value.as_str())
            }),
            Some("Bearer")
        );
    }
}

#[tokio::test]
async fn client_secret_basic_uses_oauth_form_encoding_on_the_wire() {
    let cases = [
        ("cid", "shhh", "cid:shhh"),
        ("client:id", "s%cret", "client%3Aid:s%25cret"),
        ("space id", "snow ☃", "space+id:snow+%E2%98%83"),
        ("cli/ent", "a+b&c", "cli%2Fent:a%2Bb%26c"),
    ];
    for (index, (client_id, client_secret, encoded_credential)) in cases.into_iter().enumerate() {
        let server = MockServer::start().await;
        let expected = format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode(encoded_credential)
        );
        Mock::given(method("POST"))
            .and(path("/introspect"))
            .and(header("authorization", expected.as_str()))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(json!({"active": true, "username": "u"})),
            )
            .expect(1)
            .mount(&server)
            .await;
        let plugin = Oauth2Introspection::new(
            &json!({
                "providers": [{
                    "introspection_endpoint": format!("{}/introspect", server.uri()),
                    "client_auth": {
                        "method": "client_secret_basic",
                        "client_id": client_id,
                        "client_secret": client_secret
                    }
                }]
            }),
            PluginHttpClient::default(),
        )
        .unwrap();
        assert_continue(
            plugin
                .authenticate(
                    &mut make_ctx(&format!("basic-encoding-{index}")),
                    &ConsumerIndex::new(&[]),
                )
                .await,
        );
    }
}

#[tokio::test]
async fn sender_constrained_and_unsupported_token_types_fail_closed() {
    let server = MockServer::start().await;
    let responses = Arc::new([
        json!({"active": true, "cnf": {"jkt": "thumbprint"}}),
        json!({"active": true, "token_type": "DPoP"}),
        json!({"active": true, "token_type": 7}),
    ]);
    let calls = Arc::new(AtomicUsize::new(0));
    Mock::given(method("POST"))
        .and(path("/introspect"))
        .respond_with({
            let responses = Arc::clone(&responses);
            let calls = Arc::clone(&calls);
            move |_: &wiremock::Request| {
                let index = calls
                    .fetch_add(1, Ordering::SeqCst)
                    .min(responses.len() - 1);
                ResponseTemplate::new(200).set_body_json(responses[index].clone())
            }
        })
        .mount(&server)
        .await;
    let endpoint = format!("{}/introspect", server.uri());
    let plugin = Oauth2Introspection::new(&config(&endpoint), PluginHttpClient::default()).unwrap();

    for token in ["cnf-token", "dpop-token"] {
        assert_bearer_reject(
            plugin
                .authenticate(&mut make_ctx(token), &ConsumerIndex::new(&[]))
                .await,
            401,
            "invalid_token",
        );
    }
    assert_plain_reject(
        plugin
            .authenticate(
                &mut make_ctx("malformed-token-type"),
                &ConsumerIndex::new(&[]),
            )
            .await,
        503,
    );
}

#[tokio::test]
async fn authorization_fallback_strips_the_actual_source_for_query_only_provider() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/introspect"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"active": true, "username": "u"})),
        )
        .mount(&server)
        .await;
    let plugin = Oauth2Introspection::new(
        &json!({
            "providers": [{
                "introspection_endpoint": format!("{}/introspect", server.uri()),
                "client_auth": {"method": "none"},
                "from_params": ["access_token"],
                "forward_original_token": false
            }]
        }),
        PluginHttpClient::default(),
    )
    .unwrap();
    let mut ctx = make_ctx("authorization-fallback-token");
    assert_continue(
        plugin
            .authenticate(&mut ctx, &ConsumerIndex::new(&[]))
            .await,
    );
    let mut headers = ctx.headers.clone();
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
    assert!(
        headers
            .keys()
            .all(|name| !name.eq_ignore_ascii_case("authorization"))
    );
}

#[tokio::test]
async fn accepted_token_is_stripped_from_every_duplicate_location() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/introspect"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"active": true, "username": "u"})),
        )
        .mount(&server)
        .await;
    let plugin = Oauth2Introspection::new(
        &json!({
            "providers": [{
                "introspection_endpoint": format!("{}/introspect", server.uri()),
                "client_auth": {"method": "none"},
                "from_headers": [
                    {"name": "x-access-token"},
                    {"name": "x-unrelated-token"}
                ],
                "from_params": ["access_token"],
                "forward_original_token": false
            }]
        }),
        PluginHttpClient::default(),
    )
    .unwrap();
    let mut ctx = make_ctx("duplicate-token");
    ctx.headers
        .insert("x-access-token".to_string(), "duplicate-token".to_string());
    ctx.headers.insert(
        "x-unrelated-token".to_string(),
        "different-token".to_string(),
    );
    ctx.query_params
        .insert("access_token".to_string(), "duplicate-token".to_string());
    assert_continue(
        plugin
            .authenticate(&mut ctx, &ConsumerIndex::new(&[]))
            .await,
    );

    let mut headers = ctx.headers.clone();
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
    assert!(
        headers
            .keys()
            .all(|name| !name.eq_ignore_ascii_case("authorization"))
    );
    assert!(!headers.contains_key("x-access-token"));
    assert_eq!(
        headers.get("x-unrelated-token").map(String::as_str),
        Some("different-token")
    );
    assert!(!ctx.query_params.contains_key("access_token"));
    assert!(
        ctx.metadata
            .contains_key("auth.strip_query_param.access_token")
    );
}

#[tokio::test]
async fn duplicate_authorization_token_stripping_uses_shared_bearer_syntax() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/introspect"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"active": true, "username": "u"})),
        )
        .mount(&server)
        .await;
    let plugin = Oauth2Introspection::new(
        &json!({
            "providers": [{
                "introspection_endpoint": format!("{}/introspect", server.uri()),
                "client_auth": {"method": "none"},
                "from_params": ["access_token"],
                "forward_original_token": false
            }]
        }),
        PluginHttpClient::default(),
    )
    .unwrap();

    for authorization in ["Bearer\tduplicate-token", "Bearer  duplicate-token"] {
        let mut ctx = RequestContext::new("127.0.0.1".into(), "GET".into(), "/test".into());
        ctx.headers
            .insert("authorization".to_string(), authorization.to_string());
        ctx.query_params
            .insert("access_token".to_string(), "duplicate-token".to_string());
        assert_continue(
            plugin
                .authenticate(&mut ctx, &ConsumerIndex::new(&[]))
                .await,
        );

        let mut headers = ctx.headers.clone();
        assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
        assert!(
            headers
                .keys()
                .all(|name| !name.eq_ignore_ascii_case("authorization"))
        );
    }
}

#[tokio::test]
async fn provider_specific_location_routes_without_disclosing_to_siblings() {
    let provider_a = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"active": true})))
        .mount(&provider_a)
        .await;
    let provider_b = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/introspect"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"active": true, "username": "b"})),
        )
        .mount(&provider_b)
        .await;
    let plugin = Oauth2Introspection::new(
        &json!({
            "providers": [
                {
                    "introspection_endpoint": format!("{}/introspect", provider_a.uri()),
                    "client_auth": {"method": "none"},
                    "from_headers": [{"name": "x-provider-a-token"}]
                },
                {
                    "introspection_endpoint": format!("{}/introspect", provider_b.uri()),
                    "client_auth": {"method": "none"},
                    "from_headers": [{"name": "x-provider-b-token"}]
                }
            ]
        }),
        PluginHttpClient::default(),
    )
    .unwrap();
    let mut ctx = RequestContext::new("127.0.0.1".into(), "GET".into(), "/test".into());
    ctx.headers.insert(
        "x-provider-b-token".to_string(),
        "provider-b-only".to_string(),
    );
    assert_continue(
        plugin
            .authenticate(&mut ctx, &ConsumerIndex::new(&[]))
            .await,
    );
    assert!(provider_a.received_requests().await.unwrap().is_empty());
    assert_eq!(provider_b.received_requests().await.unwrap().len(), 1);
}

#[tokio::test]
async fn duplicate_provider_hints_do_not_fan_out_without_shared_trust() {
    let provider_a = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/introspect"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"active": false})))
        .mount(&provider_a)
        .await;
    let provider_b = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/introspect"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"active": true, "username": "b"})),
        )
        .mount(&provider_b)
        .await;
    let plugin = Oauth2Introspection::new(
        &json!({
            "providers": [
                {
                    "introspection_endpoint": format!("{}/introspect", provider_a.uri()),
                    "client_auth": {"method": "none"},
                    "from_headers": [{"name": "x-provider-a-token"}]
                },
                {
                    "introspection_endpoint": format!("{}/introspect", provider_b.uri()),
                    "client_auth": {"method": "none"},
                    "from_headers": [{"name": "x-provider-b-token"}]
                }
            ]
        }),
        PluginHttpClient::default(),
    )
    .unwrap();
    let mut ctx = RequestContext::new("127.0.0.1".into(), "GET".into(), "/test".into());
    ctx.headers
        .insert("x-provider-a-token".to_string(), "shared-token".to_string());
    ctx.headers
        .insert("x-provider-b-token".to_string(), "shared-token".to_string());
    assert_bearer_reject(
        plugin
            .authenticate(&mut ctx, &ConsumerIndex::new(&[]))
            .await,
        401,
        "invalid_token",
    );
    assert_eq!(provider_a.received_requests().await.unwrap().len(), 1);
    assert!(provider_b.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn cache_policy_is_owned_by_each_live_plugin_instance() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/introspect"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"active": true, "username": "u"})),
        )
        .mount(&server)
        .await;
    let endpoint = format!("{}/introspect", server.uri());
    let cached = Oauth2Introspection::new(
        &json!({
            "providers": [{
                "introspection_endpoint": endpoint,
                "client_auth": {"method": "none"},
                "positive_cache_ttl_secs": 3600
            }]
        }),
        PluginHttpClient::default(),
    )
    .unwrap();
    let uncached = Oauth2Introspection::new(
        &json!({
            "providers": [{
                "introspection_endpoint": endpoint,
                "client_auth": {"method": "none"},
                "positive_cache_ttl_secs": 0
            }]
        }),
        PluginHttpClient::default(),
    )
    .unwrap();
    assert_continue(
        cached
            .authenticate(
                &mut make_ctx("cache-policy-token"),
                &ConsumerIndex::new(&[]),
            )
            .await,
    );
    assert_continue(
        uncached
            .authenticate(
                &mut make_ctx("cache-policy-token"),
                &ConsumerIndex::new(&[]),
            )
            .await,
    );
    assert_eq!(server.received_requests().await.unwrap().len(), 2);
}

#[tokio::test]
async fn cache_retains_only_normalized_authorization_material() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/introspect"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "active": true,
            "username": "normalized-user",
            "unrelated_provider_payload": "x".repeat(60 * 1024)
        })))
        .mount(&server)
        .await;
    let endpoint = format!("{}/introspect", server.uri());
    let plugin = Oauth2Introspection::new(
        &json!({
            "providers": [{
                "introspection_endpoint": endpoint,
                "client_auth": {"method": "none"},
                "max_cache_entry_bytes": 256
            }]
        }),
        PluginHttpClient::default(),
    )
    .unwrap();

    for _ in 0..2 {
        let mut ctx = make_ctx("normalized-cache-token");
        assert_continue(
            plugin
                .authenticate(&mut ctx, &ConsumerIndex::new(&[]))
                .await,
        );
        assert_eq!(
            ctx.authenticated_identity.as_deref(),
            Some("normalized-user")
        );
    }
    assert_eq!(
        server.received_requests().await.unwrap().len(),
        1,
        "unrelated response JSON must not consume the normalized entry budget"
    );
}

#[tokio::test]
async fn oversized_normalized_result_is_authorized_but_not_cached() {
    let server = MockServer::start().await;
    let asserted_header = "h".repeat(512);
    Mock::given(method("POST"))
        .and(path("/introspect"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "active": true,
            "username": "uncached-user",
            "asserted": asserted_header.clone()
        })))
        .mount(&server)
        .await;
    let endpoint = format!("{}/introspect", server.uri());
    let plugin = Oauth2Introspection::new(
        &json!({
            "providers": [{
                "introspection_endpoint": endpoint,
                "client_auth": {"method": "none"},
                "max_cache_entry_bytes": 256,
                "claim_headers": {"asserted": "x-introspected-assertion"}
            }]
        }),
        PluginHttpClient::default(),
    )
    .unwrap();

    for _ in 0..2 {
        let mut ctx = make_ctx("oversized-normalized-token");
        assert_continue(
            plugin
                .authenticate(&mut ctx, &ConsumerIndex::new(&[]))
                .await,
        );
        let mut headers = ctx.headers.clone();
        assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
        assert_eq!(
            headers.get("x-introspected-assertion").map(String::as_str),
            Some(asserted_header.as_str())
        );
    }
    assert_eq!(
        server.received_requests().await.unwrap().len(),
        2,
        "a valid oversized normalized result must work but must not be retained"
    );
}

#[tokio::test]
async fn oversized_tokens_and_provider_responses_fail_closed() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/introspect"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(
            format!(r#"{{"active":true,"padding":"{}"}}"#, "x".repeat(70 * 1024)),
            "application/json",
        ))
        .mount(&server)
        .await;
    let endpoint = format!("{}/introspect", server.uri());
    let plugin = Oauth2Introspection::new(&config(&endpoint), PluginHttpClient::default()).unwrap();
    assert_bearer_reject(
        plugin
            .authenticate(
                &mut make_ctx(&"t".repeat(8 * 1024 + 1)),
                &ConsumerIndex::new(&[]),
            )
            .await,
        401,
        "invalid_request",
    );
    assert!(server.received_requests().await.unwrap().is_empty());
    assert_plain_reject(
        plugin
            .authenticate(
                &mut make_ctx("oversized-response"),
                &ConsumerIndex::new(&[]),
            )
            .await,
        503,
    );
}

#[tokio::test]
async fn identical_in_flight_tokens_are_coalesced_by_hash() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/introspect"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_delay(Duration::from_millis(100))
                .set_body_json(json!({"active": true, "username": "u"})),
        )
        .mount(&server)
        .await;
    let endpoint = format!("{}/introspect", server.uri());
    let plugin = Arc::new(
        Oauth2Introspection::new(&config(&endpoint), PluginHttpClient::default()).unwrap(),
    );
    let results = join_all((0..12).map(|_| {
        let plugin = Arc::clone(&plugin);
        async move {
            plugin
                .authenticate(
                    &mut make_ctx("one-shared-in-flight-token"),
                    &ConsumerIndex::new(&[]),
                )
                .await
        }
    }))
    .await;
    for result in results {
        assert_continue(result);
    }
    assert_eq!(server.received_requests().await.unwrap().len(), 1);
}

#[tokio::test]
async fn unique_token_flood_is_bounded_with_503_backpressure() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/introspect"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_delay(Duration::from_millis(200))
                .set_body_json(json!({"active": true, "username": "u"})),
        )
        .mount(&server)
        .await;
    let endpoint = format!("{}/introspect", server.uri());
    let plugin = Arc::new(
        Oauth2Introspection::new(&config(&endpoint), PluginHttpClient::default()).unwrap(),
    );
    let results = join_all((0..48).map(|index| {
        let plugin = Arc::clone(&plugin);
        async move {
            plugin
                .authenticate(
                    &mut make_ctx(&format!("unique-flood-token-{index}")),
                    &ConsumerIndex::new(&[]),
                )
                .await
        }
    }))
    .await;
    let mut unavailable = 0usize;
    for result in results {
        match result {
            PluginResult::Continue => {}
            PluginResult::Reject {
                status_code: 503, ..
            } => unavailable += 1,
            other => panic!("unexpected flood result: {other:?}"),
        }
    }
    assert!(unavailable > 0);
    assert!(server.received_requests().await.unwrap().len() <= 32);
}

#[tokio::test]
async fn oversized_discovery_document_never_installs_its_endpoint() {
    let server = MockServer::start().await;
    let discovery_body = format!(
        r#"{{"introspection_endpoint":"{}/introspect","padding":"{}"}}"#,
        server.uri(),
        "x".repeat(140 * 1024)
    );
    Mock::given(method("GET"))
        .and(path("/.well-known/openid-configuration"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(discovery_body, "application/json"))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/introspect"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"active": true, "username": "u"})),
        )
        .mount(&server)
        .await;
    let plugin = Oauth2Introspection::new(
        &json!({
            "providers": [{
                "discovery_url": format!("{}/.well-known/openid-configuration", server.uri()),
                "client_auth": {"method": "none"}
            }]
        }),
        PluginHttpClient::default(),
    )
    .unwrap();
    plugin.start_background_tasks().unwrap();
    wait_for_discovery_request(&server).await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_plain_reject(
        plugin
            .authenticate(
                &mut make_ctx("oversized-discovery"),
                &ConsumerIndex::new(&[]),
            )
            .await,
        503,
    );
    let requests = server.received_requests().await.unwrap();
    assert_eq!(
        requests
            .iter()
            .filter(|request| request.method.as_str() == "POST")
            .count(),
        0
    );
}

async fn wait_for_discovery_request(server: &MockServer) {
    for _ in 0..40 {
        if !server.received_requests().await.unwrap().is_empty() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("discovery worker did not issue its initial request");
}

#[tokio::test]
async fn retired_discovery_generation_is_cancelled_and_live_start_is_idempotent() {
    let retired_server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(503))
        .mount(&retired_server)
        .await;
    let retired = Oauth2Introspection::new(
        &json!({
            "providers": [{
                "discovery_url": format!("{}/.well-known/openid-configuration", retired_server.uri()),
                "client_auth": {"method": "none"}
            }]
        }),
        PluginHttpClient::default(),
    )
    .unwrap();
    retired.start_background_tasks().unwrap();
    wait_for_discovery_request(&retired_server).await;
    drop(retired);

    let live_server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(503))
        .mount(&live_server)
        .await;
    let live = Oauth2Introspection::new(
        &json!({
            "providers": [{
                "discovery_url": format!("{}/.well-known/openid-configuration", live_server.uri()),
                "client_auth": {"method": "none"}
            }]
        }),
        PluginHttpClient::default(),
    )
    .unwrap();
    live.start_background_tasks().unwrap();
    live.start_background_tasks().unwrap();
    wait_for_discovery_request(&live_server).await;
    tokio::time::sleep(Duration::from_millis(2200)).await;

    assert_eq!(retired_server.received_requests().await.unwrap().len(), 1);
    assert_eq!(live_server.received_requests().await.unwrap().len(), 2);
}
