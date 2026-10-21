//! `WWW-Authenticate` challenges on every gateway-generated `401`
//! (RFC 9110 §15.5.2, issue #6774).
//!
//! Covers the shared authentication flow, the built-in mechanisms that use it
//! (`key_auth`, `jwt_auth`, `basic_auth`), the authentication-phase
//! aggregation that keeps one mechanism's challenge from erasing another's,
//! and the rejection-finalizer safety net for `401`s raised outside the
//! authentication phase. `hmac_auth`, `mtls_auth`, `jwks_auth`, and
//! `soap_ws_security` keep their per-mechanism matrices beside their own
//! fixtures.

use async_trait::async_trait;
use base64::Engine;
use ferrum_edge::_test_support::finalize_plugin_rejection_without_committed_hooks_for_test;
use ferrum_edge::ConsumerIndex;
use ferrum_edge::config::types::AuthMode;
use ferrum_edge::plugins::utils::auth_flow::{
    self, AuthMechanism, CredentialRejection, ExtractedCredential, VerifyOutcome, run_auth,
};
use ferrum_edge::plugins::{
    Plugin, PluginResult, RequestContext, access_control::AccessControl, basic_auth::BasicAuth,
    jwt_auth::JwtAuth, key_auth::KeyAuth,
};
use ferrum_edge::proxy::run_authentication_phase;
use serde_json::json;
use std::collections::HashMap;
use std::sync::Arc;

use super::plugin_utils::{
    assert_continue, assert_phase_unauthorized_with_challenge, assert_unauthorized_with_challenge,
    challenge_header, context_with_materialized_raw_header_bytes, create_test_consumer,
};

/// Secret `create_test_consumer`'s Basic password hash was derived with.
const BASIC_HASH_SECRET: &str = "test-hmac-secret-for-basic-auth-unit-tests";
/// Secret `create_test_consumer`'s JWT credential carries.
const JWT_SECRET: &str = "test-jwt-secret";

const SCRIPTED_CHALLENGE: &str = r#"Scripted realm="ferrum-edge""#;
const SCRIPTED_INVALID_FORMAT: &str = r#"Scripted error="invalid_request""#;
const SCRIPTED_INVALID_CREDENTIAL: &str = r#"Scripted error="invalid_credential""#;

fn ctx() -> RequestContext {
    RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/protected".to_string(),
    )
}

fn ctx_with_header(name: &str, value: &str) -> RequestContext {
    let mut ctx = ctx();
    ctx.headers.insert(name.to_string(), value.to_string());
    ctx
}

fn consumers() -> ConsumerIndex {
    ConsumerIndex::new(&[create_test_consumer()])
}

fn basic_auth() -> BasicAuth {
    ferrum_edge::_test_support::basic_auth_with_secret_for_test(&json!({}), BASIC_HASH_SECRET)
        .expect("basic_auth builds with the explicit test secret")
}

fn basic_header(user: &str, pass: &str) -> String {
    let encoded = base64::engine::general_purpose::STANDARD.encode(format!("{user}:{pass}"));
    format!("Basic {encoded}")
}

fn jwt(claims: serde_json::Value, secret: &str) -> String {
    use jsonwebtoken::{EncodingKey, Header, encode};
    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
    .expect("test JWT encodes")
}

fn bearer(token: &str) -> String {
    format!("Bearer {token}")
}

// ---------------------------------------------------------------------------
// Shared authentication flow
// ---------------------------------------------------------------------------

/// A mechanism that extracts and verifies to scripted outcomes and overrides
/// the per-rejection challenge.
#[derive(Clone)]
struct ScriptedMechanism {
    extracted: ExtractedCredential,
    outcome: VerifyOutcome,
}

#[async_trait]
impl AuthMechanism for ScriptedMechanism {
    fn mechanism_name(&self) -> &'static str {
        "scripted_auth"
    }

    fn authentication_challenge(&self) -> &'static str {
        SCRIPTED_CHALLENGE
    }

    fn rejection_challenge(&self, rejection: CredentialRejection) -> &'static str {
        match rejection {
            CredentialRejection::InvalidFormat => SCRIPTED_INVALID_FORMAT,
            CredentialRejection::InvalidCredential => SCRIPTED_INVALID_CREDENTIAL,
        }
    }

    fn extract(&self, _ctx: &RequestContext) -> ExtractedCredential {
        self.extracted.clone()
    }

    async fn verify(
        &self,
        _credential: ExtractedCredential,
        _consumer_index: &ConsumerIndex,
    ) -> VerifyOutcome {
        self.outcome.clone()
    }
}

/// A mechanism that relies on the default `rejection_challenge`.
struct AdvertisedOnlyMechanism {
    outcome: VerifyOutcome,
}

#[async_trait]
impl AuthMechanism for AdvertisedOnlyMechanism {
    fn mechanism_name(&self) -> &'static str {
        "advertised_only_auth"
    }

    fn authentication_challenge(&self) -> &'static str {
        SCRIPTED_CHALLENGE
    }

    fn extract(&self, _ctx: &RequestContext) -> ExtractedCredential {
        ExtractedCredential::ApiKey("presented".to_string())
    }

    async fn verify(
        &self,
        _credential: ExtractedCredential,
        _consumer_index: &ConsumerIndex,
    ) -> VerifyOutcome {
        self.outcome.clone()
    }
}

fn body(text: &str) -> String {
    format!(r#"{{"error":"{text}"}}"#)
}

#[tokio::test]
async fn shared_flow_attaches_a_challenge_to_every_401_outcome() {
    let presented = || ExtractedCredential::ApiKey("presented".to_string());
    let cases = [
        (
            "invalid format at extraction",
            ExtractedCredential::InvalidFormat(body("malformed")),
            VerifyOutcome::NotApplicable,
            SCRIPTED_INVALID_FORMAT,
        ),
        (
            "invalid format at verification",
            presented(),
            VerifyOutcome::InvalidFormat(body("malformed")),
            SCRIPTED_INVALID_FORMAT,
        ),
        (
            "invalid secret or signature",
            presented(),
            VerifyOutcome::Invalid(body("invalid")),
            SCRIPTED_INVALID_CREDENTIAL,
        ),
        (
            "unknown consumer",
            presented(),
            VerifyOutcome::ConsumerNotFound(body("unknown")),
            SCRIPTED_INVALID_CREDENTIAL,
        ),
        (
            "verification failure",
            presented(),
            VerifyOutcome::VerificationFailed(body("failed")),
            SCRIPTED_INVALID_CREDENTIAL,
        ),
    ];
    for (case, extracted, outcome, expected) in cases {
        let mechanism = ScriptedMechanism { extracted, outcome };
        let mut ctx = ctx();
        let result = run_auth(&mechanism, &mut ctx, &ConsumerIndex::new(&[])).await;
        match &result {
            PluginResult::Reject { status_code, .. } => {
                assert_eq!(*status_code, 401, "{case}");
            }
            other => panic!("{case}: expected a rejection, got {other:?}"),
        }
        assert_unauthorized_with_challenge(result, expected);
    }
}

#[tokio::test]
async fn shared_flow_rejection_challenge_defaults_to_the_advertised_challenge() {
    for outcome in [
        VerifyOutcome::InvalidFormat(body("malformed")),
        VerifyOutcome::Invalid(body("invalid")),
        VerifyOutcome::ConsumerNotFound(body("unknown")),
        VerifyOutcome::VerificationFailed(body("failed")),
    ] {
        let mechanism = AdvertisedOnlyMechanism { outcome };
        let mut ctx = ctx();
        let result = run_auth(&mechanism, &mut ctx, &ConsumerIndex::new(&[])).await;
        assert_unauthorized_with_challenge(result, SCRIPTED_CHALLENGE);
    }
}

#[tokio::test]
async fn shared_flow_non_401_outcomes_carry_no_challenge() {
    for (outcome, expected_status) in [
        (VerifyOutcome::Forbidden(body("forbidden")), 403),
        (VerifyOutcome::Internal(body("internal")), 500),
    ] {
        let mechanism = ScriptedMechanism {
            extracted: ExtractedCredential::ApiKey("presented".to_string()),
            outcome,
        };
        let mut ctx = ctx();
        match run_auth(&mechanism, &mut ctx, &ConsumerIndex::new(&[])).await {
            PluginResult::Reject {
                status_code,
                headers,
                ..
            } => {
                assert_eq!(status_code, expected_status);
                assert_eq!(challenge_header(&headers), None);
            }
            other => panic!("expected a rejection, got {other:?}"),
        }
    }
}

#[tokio::test]
async fn shared_flow_missing_and_successful_credentials_continue() {
    let missing = ScriptedMechanism {
        extracted: ExtractedCredential::Missing,
        outcome: VerifyOutcome::NotApplicable,
    };
    let mut ctx_missing = ctx();
    assert_continue(run_auth(&missing, &mut ctx_missing, &ConsumerIndex::new(&[])).await);

    let success = ScriptedMechanism {
        extracted: ExtractedCredential::ApiKey("presented".to_string()),
        outcome: VerifyOutcome::consumer(Arc::new(create_test_consumer())),
    };
    let mut ctx_success = ctx();
    assert_continue(run_auth(&success, &mut ctx_success, &ConsumerIndex::new(&[])).await);
    assert!(ctx_success.identified_consumer.is_some());
}

#[test]
fn builtin_challenges_are_header_valid_and_name_the_applicable_scheme() {
    for (challenge, scheme) in [
        (auth_flow::GENERIC_AUTHENTICATION_CHALLENGE, "ferrum-edge"),
        (auth_flow::BASIC_AUTHENTICATION_CHALLENGE, "Basic"),
        (auth_flow::BEARER_AUTHENTICATION_CHALLENGE, "Bearer"),
        (auth_flow::BEARER_INVALID_REQUEST_CHALLENGE, "Bearer"),
        (auth_flow::BEARER_INVALID_TOKEN_CHALLENGE, "Bearer"),
        (auth_flow::DPOP_AUTHENTICATION_CHALLENGE, "DPoP"),
        (auth_flow::DPOP_INVALID_PROOF_CHALLENGE, "DPoP"),
        (auth_flow::API_KEY_AUTHENTICATION_CHALLENGE, "ApiKey"),
        (auth_flow::HMAC_AUTHENTICATION_CHALLENGE, "hmac"),
        (
            auth_flow::CLIENT_CERTIFICATE_AUTHENTICATION_CHALLENGE,
            "ClientCertificate",
        ),
        (
            auth_flow::WS_SECURITY_AUTHENTICATION_CHALLENGE,
            "WS-Security",
        ),
    ] {
        assert!(
            auth_flow::is_valid_authentication_challenge(challenge),
            "{challenge}"
        );
        assert_eq!(
            auth_flow::authentication_challenge_scheme(challenge),
            scheme
        );
    }
}

#[test]
fn challenge_lists_keep_one_challenge_per_scheme_and_drop_invalid_values() {
    let mut challenges = Vec::new();
    auth_flow::push_authentication_challenge(
        &mut challenges,
        auth_flow::BEARER_INVALID_TOKEN_CHALLENGE,
    );
    // Same scheme, compared case-insensitively: the first, more specific one wins.
    auth_flow::push_authentication_challenge(&mut challenges, "bearer");
    // Header-invalid or empty values are never emitted.
    auth_flow::push_authentication_challenge(&mut challenges, "Basic\r\nX-Injected: 1");
    auth_flow::push_authentication_challenge(&mut challenges, "   ");
    auth_flow::push_authentication_challenge(&mut challenges, "realm=\"no-scheme\"");
    auth_flow::push_authentication_challenge(
        &mut challenges,
        auth_flow::API_KEY_AUTHENTICATION_CHALLENGE,
    );
    assert_eq!(
        auth_flow::render_authentication_challenges(&challenges),
        r#"Bearer error="invalid_token", ApiKey realm="ferrum-edge""#
    );
    assert_eq!(
        auth_flow::render_authentication_challenges(&[]),
        auth_flow::GENERIC_AUTHENTICATION_CHALLENGE
    );
}

// ---------------------------------------------------------------------------
// key_auth — `ApiKey`
// ---------------------------------------------------------------------------

#[tokio::test]
async fn key_auth_challenges_every_401_with_api_key() {
    let plugin = KeyAuth::new(&json!({})).unwrap();
    let index = consumers();

    // Missing credentials: the plugin defers, and the phase answers.
    let mut missing = ctx();
    assert_continue(plugin.authenticate(&mut missing, &index).await);
    let auth_plugins: Vec<Arc<dyn Plugin>> = vec![Arc::new(KeyAuth::new(&json!({})).unwrap())];
    for mode in [AuthMode::Single, AuthMode::Multi] {
        let mut ctx = ctx();
        assert_phase_unauthorized_with_challenge(
            run_authentication_phase(mode, &auth_plugins, &mut ctx, &index).await,
            auth_flow::API_KEY_AUTHENTICATION_CHALLENGE,
        );
    }

    // Malformed (non-UTF-8) key.
    let mut malformed = context_with_materialized_raw_header_bytes("x-api-key", b"\xFF\xFE");
    assert_unauthorized_with_challenge(
        plugin.authenticate(&mut malformed, &index).await,
        auth_flow::API_KEY_AUTHENTICATION_CHALLENGE,
    );

    // Blank key (invalid) and unknown key (no consumer).
    for key in ["   ", "not-a-known-key"] {
        let mut ctx = ctx_with_header("x-api-key", key);
        assert_unauthorized_with_challenge(
            plugin.authenticate(&mut ctx, &index).await,
            auth_flow::API_KEY_AUTHENTICATION_CHALLENGE,
        );
    }

    // Success carries no rejection at all.
    let mut valid = ctx_with_header("x-api-key", "test-api-key");
    assert_continue(plugin.authenticate(&mut valid, &index).await);
    assert!(valid.identified_consumer.is_some());
}

// ---------------------------------------------------------------------------
// jwt_auth — RFC 6750 `Bearer`
// ---------------------------------------------------------------------------

#[tokio::test]
async fn jwt_auth_challenges_every_401_with_bearer() {
    let plugin = JwtAuth::new(&json!({})).unwrap();
    let index = consumers();

    // Missing credentials: advertised `Bearer`, no error code (RFC 6750 §3.1).
    let auth_plugins: Vec<Arc<dyn Plugin>> = vec![Arc::new(JwtAuth::new(&json!({})).unwrap())];
    for mode in [AuthMode::Single, AuthMode::Multi] {
        let mut ctx = ctx();
        assert_phase_unauthorized_with_challenge(
            run_authentication_phase(mode, &auth_plugins, &mut ctx, &index).await,
            auth_flow::BEARER_AUTHENTICATION_CHALLENGE,
        );
    }

    // Malformed presentation: an empty bearer credential.
    let mut empty = ctx_with_header("authorization", "Bearer ");
    assert_unauthorized_with_challenge(
        plugin.authenticate(&mut empty, &index).await,
        auth_flow::BEARER_INVALID_REQUEST_CHALLENGE,
    );

    let cases = [
        // Not a JWT at all.
        bearer("not-a-jwt"),
        // Well formed, but names no consumer.
        bearer(&jwt(
            json!({"sub": "nobody", "exp": 9_999_999_999u64}),
            JWT_SECRET,
        )),
        // Known consumer, wrong signing secret.
        bearer(&jwt(
            json!({"sub": "testuser", "exp": 9_999_999_999u64}),
            "the-wrong-secret",
        )),
        // Known consumer, valid signature, expired.
        bearer(&jwt(json!({"sub": "testuser", "exp": 1u64}), JWT_SECRET)),
    ];
    for authorization in cases {
        let mut ctx = ctx_with_header("authorization", &authorization);
        assert_unauthorized_with_challenge(
            plugin.authenticate(&mut ctx, &index).await,
            auth_flow::BEARER_INVALID_TOKEN_CHALLENGE,
        );
    }

    let mut valid = ctx_with_header(
        "authorization",
        &bearer(&jwt(
            json!({"sub": "testuser", "exp": 9_999_999_999u64}),
            JWT_SECRET,
        )),
    );
    assert_continue(plugin.authenticate(&mut valid, &index).await);
    assert!(valid.identified_consumer.is_some());
}

// ---------------------------------------------------------------------------
// basic_auth — RFC 7617 `Basic`
// ---------------------------------------------------------------------------

#[tokio::test]
async fn basic_auth_challenges_every_401_with_basic() {
    let plugin = basic_auth();
    let index = consumers();

    let auth_plugins: Vec<Arc<dyn Plugin>> = vec![Arc::new(basic_auth())];
    let mut missing = ctx();
    assert_phase_unauthorized_with_challenge(
        run_authentication_phase(AuthMode::Single, &auth_plugins, &mut missing, &index).await,
        auth_flow::BASIC_AUTHENTICATION_CHALLENGE,
    );

    for authorization in [
        // Malformed base64.
        "Basic !!!not-base64!!!".to_string(),
        // Unknown user.
        basic_header("nobody", "password"),
        // Known user, wrong password.
        basic_header("testuser", "wrong-password"),
    ] {
        let mut ctx = ctx_with_header("authorization", &authorization);
        assert_unauthorized_with_challenge(
            plugin.authenticate(&mut ctx, &index).await,
            auth_flow::BASIC_AUTHENTICATION_CHALLENGE,
        );
    }

    let mut valid = ctx_with_header("authorization", &basic_header("testuser", "password"));
    assert_continue(plugin.authenticate(&mut valid, &index).await);
    assert!(valid.identified_consumer.is_some());
}

// ---------------------------------------------------------------------------
// Multiple mechanisms do not erase one another's challenges
// ---------------------------------------------------------------------------

#[tokio::test]
async fn missing_credentials_advertise_every_applicable_mechanism() {
    let auth_plugins: Vec<Arc<dyn Plugin>> = vec![
        Arc::new(KeyAuth::new(&json!({})).unwrap()),
        Arc::new(JwtAuth::new(&json!({})).unwrap()),
        Arc::new(basic_auth()),
        // A second instance of an already-listed scheme adds nothing.
        Arc::new(KeyAuth::new(&json!({"key_location": "query:api_key"})).unwrap()),
    ];
    for mode in [AuthMode::Single, AuthMode::Multi] {
        let mut ctx = ctx();
        assert_phase_unauthorized_with_challenge(
            run_authentication_phase(mode, &auth_plugins, &mut ctx, &consumers()).await,
            r#"ApiKey realm="ferrum-edge", Bearer, Basic realm="ferrum-edge", charset="UTF-8""#,
        );
    }
}

#[tokio::test]
async fn multi_auth_keeps_every_rejecting_mechanism_challenge() {
    let auth_plugins: Vec<Arc<dyn Plugin>> = vec![
        Arc::new(KeyAuth::new(&json!({})).unwrap()),
        Arc::new(JwtAuth::new(&json!({})).unwrap()),
        Arc::new(basic_auth()),
    ];
    let mut ctx = ctx();
    ctx.headers
        .insert("x-api-key".to_string(), "not-a-known-key".to_string());
    ctx.headers
        .insert("authorization".to_string(), bearer("not-a-jwt"));

    let rejection =
        run_authentication_phase(AuthMode::Multi, &auth_plugins, &mut ctx, &consumers()).await;

    // The last rejection still selects the body, but the earlier `key_auth`
    // rejection's challenge survives, and the credential-less Basic mechanism
    // is still advertised.
    let (_, body, _) = rejection.clone().expect("both credentials are invalid");
    assert_eq!(&body[..], br#"{"error":"Invalid JWT token"}"#);
    assert_phase_unauthorized_with_challenge(
        rejection,
        r#"ApiKey realm="ferrum-edge", Bearer error="invalid_token", Basic realm="ferrum-edge", charset="UTF-8""#,
    );
}

#[tokio::test]
async fn single_auth_rejection_also_advertises_the_other_mechanisms() {
    let auth_plugins: Vec<Arc<dyn Plugin>> = vec![
        Arc::new(JwtAuth::new(&json!({})).unwrap()),
        Arc::new(basic_auth()),
    ];
    let mut ctx = ctx_with_header("authorization", &bearer("not-a-jwt"));
    assert_phase_unauthorized_with_challenge(
        run_authentication_phase(AuthMode::Single, &auth_plugins, &mut ctx, &consumers()).await,
        r#"Bearer error="invalid_token", Basic realm="ferrum-edge", charset="UTF-8""#,
    );
}

#[tokio::test]
async fn successful_authentication_after_a_rejection_carries_no_challenge() {
    let auth_plugins: Vec<Arc<dyn Plugin>> = vec![
        Arc::new(KeyAuth::new(&json!({})).unwrap()),
        Arc::new(JwtAuth::new(&json!({})).unwrap()),
    ];
    let mut ctx = ctx();
    ctx.headers
        .insert("x-api-key".to_string(), "not-a-known-key".to_string());
    ctx.headers.insert(
        "authorization".to_string(),
        bearer(&jwt(
            json!({"sub": "testuser", "exp": 9_999_999_999u64}),
            JWT_SECRET,
        )),
    );
    assert!(
        run_authentication_phase(AuthMode::Multi, &auth_plugins, &mut ctx, &consumers())
            .await
            .is_none()
    );
}

/// A custom authentication plugin that rejects with a `401` and advertises no
/// challenge of its own.
struct ChallengelessAuth {
    rejection_headers: HashMap<String, String>,
}

#[async_trait]
impl Plugin for ChallengelessAuth {
    fn name(&self) -> &str {
        "challengeless_auth"
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
            body: r#"{"error":"custom rejection"}"#.to_string(),
            headers: self.rejection_headers.clone(),
        }
    }
}

/// A custom authentication plugin that refuses an authenticated principal.
struct ForbiddingAuth;

#[async_trait]
impl Plugin for ForbiddingAuth {
    fn name(&self) -> &str {
        "forbidding_auth"
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
            status_code: 403,
            body: r#"{"error":"forbidden"}"#.to_string(),
            headers: HashMap::new(),
        }
    }
}

#[tokio::test]
async fn a_custom_401_without_a_challenge_gets_an_applicable_or_generic_one() {
    for mode in [AuthMode::Single, AuthMode::Multi] {
        let alone: Vec<Arc<dyn Plugin>> = vec![Arc::new(ChallengelessAuth {
            rejection_headers: HashMap::new(),
        })];
        let mut ctx_alone = ctx();
        assert_phase_unauthorized_with_challenge(
            run_authentication_phase(mode.clone(), &alone, &mut ctx_alone, &consumers()).await,
            auth_flow::GENERIC_AUTHENTICATION_CHALLENGE,
        );

        let with_key_auth: Vec<Arc<dyn Plugin>> = vec![
            Arc::new(ChallengelessAuth {
                rejection_headers: HashMap::new(),
            }),
            Arc::new(KeyAuth::new(&json!({})).unwrap()),
        ];
        let mut ctx_with_key_auth = ctx();
        assert_phase_unauthorized_with_challenge(
            run_authentication_phase(mode, &with_key_auth, &mut ctx_with_key_auth, &consumers())
                .await,
            auth_flow::API_KEY_AUTHENTICATION_CHALLENGE,
        );
    }
}

#[tokio::test]
async fn a_header_invalid_challenge_is_replaced_rather_than_sent() {
    let auth_plugins: Vec<Arc<dyn Plugin>> = vec![Arc::new(ChallengelessAuth {
        rejection_headers: HashMap::from([(
            "www-authenticate".to_string(),
            "Bearer\r\nX-Injected: 1".to_string(),
        )]),
    })];
    let mut ctx = ctx();
    let rejection =
        run_authentication_phase(AuthMode::Single, &auth_plugins, &mut ctx, &consumers()).await;
    let (_, _, headers) = rejection.clone().expect("custom plugin rejects");
    assert_eq!(
        headers
            .keys()
            .filter(|name| name.eq_ignore_ascii_case("www-authenticate"))
            .count(),
        1,
        "exactly one challenge field: {headers:?}"
    );
    assert_phase_unauthorized_with_challenge(
        rejection,
        auth_flow::GENERIC_AUTHENTICATION_CHALLENGE,
    );
}

#[tokio::test]
async fn a_non_401_authentication_rejection_gets_no_challenge() {
    let auth_plugins: Vec<Arc<dyn Plugin>> = vec![
        Arc::new(KeyAuth::new(&json!({})).unwrap()),
        Arc::new(ForbiddingAuth),
    ];
    for mode in [AuthMode::Single, AuthMode::Multi] {
        let mut ctx = ctx();
        let (status, _, headers) =
            run_authentication_phase(mode, &auth_plugins, &mut ctx, &consumers())
                .await
                .expect("forbidden");
        assert_eq!(status, 403);
        assert_eq!(challenge_header(&headers), None);
    }
}

// ---------------------------------------------------------------------------
// Rejection-finalizer safety net: 401s outside the authentication phase
// ---------------------------------------------------------------------------

async fn finalize_401(
    plugins: &[Arc<dyn Plugin>],
    status_code: u16,
    headers: HashMap<String, String>,
) -> (u16, HashMap<String, String>) {
    let mut ctx = ctx();
    match finalize_plugin_rejection_without_committed_hooks_for_test(
        plugins,
        &mut ctx,
        PluginResult::Reject {
            status_code,
            body: r#"{"error":"rejected"}"#.to_string(),
            headers,
        },
    )
    .await
    {
        PluginResult::RejectBinary {
            status_code,
            headers,
            ..
        } => (status_code, headers),
        other => panic!("expected a finalized rejection, got {other:?}"),
    }
}

#[tokio::test]
async fn access_control_401_advertises_the_route_authentication_challenges() {
    let access_control = AccessControl::new(&json!({"allowed_consumers": ["testuser"]})).unwrap();
    let mut unauthenticated = ctx();
    let rejection = access_control.authorize(&mut unauthenticated).await;
    let PluginResult::Reject {
        status_code,
        headers,
        ..
    } = rejection
    else {
        panic!("access_control must reject an unidentified caller");
    };
    assert_eq!(status_code, 401);

    let plugins: Vec<Arc<dyn Plugin>> = vec![
        Arc::new(KeyAuth::new(&json!({})).unwrap()),
        Arc::new(JwtAuth::new(&json!({})).unwrap()),
        Arc::new(access_control),
    ];
    let (status, finalized) = finalize_401(&plugins, status_code, headers).await;
    assert_eq!(status, 401);
    assert_eq!(
        challenge_header(&finalized),
        Some(r#"ApiKey realm="ferrum-edge", Bearer"#)
    );
}

#[tokio::test]
async fn a_plugin_401_on_a_route_without_authentication_gets_the_generic_challenge() {
    let (status, headers) = finalize_401(&[], 401, HashMap::new()).await;
    assert_eq!(status, 401);
    assert_eq!(
        challenge_header(&headers),
        Some(auth_flow::GENERIC_AUTHENTICATION_CHALLENGE)
    );
}

#[tokio::test]
async fn a_plugin_401_keeps_its_own_valid_challenge() {
    let plugins: Vec<Arc<dyn Plugin>> = vec![Arc::new(KeyAuth::new(&json!({})).unwrap())];
    let (status, headers) = finalize_401(
        &plugins,
        401,
        HashMap::from([(
            "www-authenticate".to_string(),
            r#"Bearer realm="api""#.to_string(),
        )]),
    )
    .await;
    assert_eq!(status, 401);
    assert_eq!(challenge_header(&headers), Some(r#"Bearer realm="api""#));
}

#[tokio::test]
async fn a_plugin_401_with_an_invalid_challenge_is_repaired() {
    let plugins: Vec<Arc<dyn Plugin>> = vec![Arc::new(KeyAuth::new(&json!({})).unwrap())];
    let (status, headers) = finalize_401(
        &plugins,
        401,
        HashMap::from([(
            "WWW-Authenticate".to_string(),
            "Bearer\r\nX-Injected: 1".to_string(),
        )]),
    )
    .await;
    assert_eq!(status, 401);
    assert_eq!(
        challenge_header(&headers),
        Some(auth_flow::API_KEY_AUTHENTICATION_CHALLENGE)
    );
}

#[tokio::test]
async fn a_non_401_plugin_rejection_gets_no_challenge() {
    let plugins: Vec<Arc<dyn Plugin>> = vec![Arc::new(KeyAuth::new(&json!({})).unwrap())];
    for status_code in [400, 403, 429, 503] {
        let (status, headers) = finalize_401(&plugins, status_code, HashMap::new()).await;
        assert_eq!(status, status_code);
        assert_eq!(challenge_header(&headers), None, "status {status_code}");
    }
}
