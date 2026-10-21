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
        (auth_flow::DPOP_INVALID_TOKEN_CHALLENGE, "DPoP"),
        (auth_flow::OIDC_AUTHENTICATION_CHALLENGE, "Bearer"),
        (auth_flow::OIDC_INVALID_SESSION_CHALLENGE, "Bearer"),
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
        assert!(
            http::HeaderValue::from_str(challenge).is_ok(),
            "{challenge}"
        );
        assert_eq!(
            auth_flow::authentication_challenge_scheme(challenge),
            scheme
        );
    }
}

#[test]
fn challenge_lists_drop_only_equivalent_challenges() {
    let mut challenges = Vec::new();
    for value in [
        auth_flow::BEARER_INVALID_TOKEN_CHALLENGE,
        // Equivalent: same scheme (case-insensitive) and the same parameters.
        r#"bearer error="invalid_token""#,
        // A different parameter set is a distinct alternative.
        auth_flow::BEARER_AUTHENTICATION_CHALLENGE,
        auth_flow::OIDC_AUTHENTICATION_CHALLENGE,
        r#"Basic realm="tenant-a""#,
        // Parameter order and name case do not matter.
        r#"Basic charset="UTF-8", REALM="ferrum-edge""#,
        auth_flow::BASIC_AUTHENTICATION_CHALLENGE,
        // Realm values compare case-sensitively.
        r#"Basic realm="Tenant-A""#,
    ] {
        assert!(
            auth_flow::push_authentication_challenge(&mut challenges, value),
            "{value}"
        );
    }
    assert_eq!(
        auth_flow::render_authentication_challenges(&challenges),
        r#"Bearer error="invalid_token", Bearer, Bearer realm="oidc", Basic realm="tenant-a", Basic charset="UTF-8", REALM="ferrum-edge", Basic realm="Tenant-A""#
    );
    assert_eq!(
        auth_flow::render_authentication_challenges(&[]),
        auth_flow::GENERIC_AUTHENTICATION_CHALLENGE
    );
}

/// RFC 7616 §3.7: one realm may offer several `Digest` algorithms; each is a
/// distinct alternative a client may need.
#[test]
fn digest_algorithm_alternatives_in_one_realm_are_all_kept() {
    let mut challenges = Vec::new();
    assert!(auth_flow::push_authentication_challenge(
        &mut challenges,
        r#"Digest realm="api", qop="auth", algorithm=SHA-256, nonce="n1", Digest realm="api", qop="auth", algorithm=MD5, nonce="n1""#,
    ));
    assert_eq!(challenges.len(), 2, "{challenges:?}");
    // A token68 challenge is equivalent only to the same token68.
    assert!(auth_flow::push_authentication_challenge(
        &mut challenges,
        "Negotiate abc==, Negotiate abc==, Negotiate def=="
    ));
    assert_eq!(challenges.len(), 4, "{challenges:?}");
}

/// RFC 9110 §11.2: `token68` may end in `=` padding, so `Basic realm=` is a
/// well-formed token68 challenge, not a parameter without a value.
#[test]
fn token68_with_padding_is_well_formed() {
    for value in ["Basic realm=", "Negotiate abc==", "Bearer mF_9.B5f-4.1JqM"] {
        assert!(
            auth_flow::is_valid_authentication_challenge(value),
            "{value}"
        );
    }
    // A parameter followed by stray text without a list comma is not.
    assert!(!auth_flow::is_valid_authentication_challenge(
        "Basic realm=\"\" x"
    ));
}

#[test]
fn every_challenge_in_a_supplied_list_is_kept() {
    let mut challenges = Vec::new();
    assert!(auth_flow::push_authentication_challenge(
        &mut challenges,
        r#"Newauth realm="apps", type=1, title="Login to \"apps\"", Basic realm="simple""#,
    ));
    assert!(auth_flow::push_authentication_challenge(
        &mut challenges,
        " , Negotiate abc+/def==, , ",
    ));
    assert_eq!(
        challenges,
        vec![
            r#"Newauth realm="apps", type=1, title="Login to \"apps\"""#.to_string(),
            r#"Basic realm="simple""#.to_string(),
            "Negotiate abc+/def==".to_string(),
        ]
    );
    for challenge in &challenges {
        assert!(
            http::HeaderValue::from_str(challenge).is_ok(),
            "{challenge}"
        );
    }
}

#[test]
fn malformed_challenges_are_refused_whole() {
    for malformed in [
        "",
        "   ",
        " , , ",
        "Bearer\r\n",
        "Bearer\r\nX-Injected: 1",
        "Basic\nrealm=\"x\"",
        "Bearer\0",
        "realm=\"no-scheme\"",
        "Basic realm=\"unterminated",
        "Basic realm=\"bad\\\u{1}escape\"",
        "Basic realm=\"a\", realm=\"b\"",
        // Any repeated auth-param name is ambiguous, compared case-insensitively.
        "Bearer error=\"invalid_token\", error=\"invalid_request\"",
        "Basic realm=\"a\", REALM=\"b\"",
        "Digest algorithm=MD5, Algorithm=SHA-256",
        "Basic realm=\"x\" charset=\"UTF-8\"",
        "Basic=",
        "Basic realm=\"caf\u{e9}\"",
        "B@sic realm=\"x\"",
        // One malformed challenge spoils the whole list.
        "Basic realm=\"ok\", Bearer\u{7}",
    ] {
        assert!(
            !auth_flow::is_valid_authentication_challenge(malformed),
            "{malformed:?} must be refused"
        );
        let mut challenges = Vec::new();
        assert!(
            !auth_flow::push_authentication_challenge(&mut challenges, malformed),
            "{malformed:?} must add nothing"
        );
        assert!(challenges.is_empty(), "{malformed:?}: {challenges:?}");
    }
}

#[test]
fn reauthentication_challenge_names_the_committing_mechanism() {
    for (auth_method, expected) in [
        (
            Some("basic_auth"),
            auth_flow::BASIC_AUTHENTICATION_CHALLENGE,
        ),
        (Some("ldap_auth"), auth_flow::BASIC_AUTHENTICATION_CHALLENGE),
        (Some("jwt_auth"), auth_flow::BEARER_INVALID_TOKEN_CHALLENGE),
        (Some("jwks_auth"), auth_flow::BEARER_INVALID_TOKEN_CHALLENGE),
        (
            Some("oauth2_introspection"),
            auth_flow::BEARER_INVALID_TOKEN_CHALLENGE,
        ),
        (
            Some("oidc_relying_party"),
            auth_flow::OIDC_INVALID_SESSION_CHALLENGE,
        ),
        (
            Some("key_auth"),
            auth_flow::API_KEY_AUTHENTICATION_CHALLENGE,
        ),
        (Some("hmac_auth"), auth_flow::HMAC_AUTHENTICATION_CHALLENGE),
        (
            Some("mtls_auth"),
            auth_flow::CLIENT_CERTIFICATE_AUTHENTICATION_CHALLENGE,
        ),
        (
            Some("soap_ws_security"),
            auth_flow::WS_SECURITY_AUTHENTICATION_CHALLENGE,
        ),
        (
            Some("custom_auth"),
            auth_flow::GENERIC_AUTHENTICATION_CHALLENGE,
        ),
        (None, auth_flow::GENERIC_AUTHENTICATION_CHALLENGE),
    ] {
        let mut ctx = ctx();
        ctx.auth_method = auth_method;
        assert_eq!(
            auth_flow::reauthentication_challenge(&ctx),
            expected,
            "{auth_method:?}"
        );
    }
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

async fn finalize_with(
    plugins: &[Arc<dyn Plugin>],
    ctx: &mut RequestContext,
    status_code: u16,
    headers: HashMap<String, String>,
) -> (u16, HashMap<String, String>) {
    match finalize_plugin_rejection_without_committed_hooks_for_test(
        plugins,
        ctx,
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

async fn finalize_401(
    plugins: &[Arc<dyn Plugin>],
    status_code: u16,
    headers: HashMap<String, String>,
) -> (u16, HashMap<String, String>) {
    let mut ctx = ctx();
    finalize_with(plugins, &mut ctx, status_code, headers).await
}

fn challenge_field_count(headers: &HashMap<String, String>) -> usize {
    headers
        .keys()
        .filter(|name| name.eq_ignore_ascii_case("www-authenticate"))
        .count()
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
async fn a_plugin_401_with_a_malformed_challenge_is_repaired() {
    let plugins: Vec<Arc<dyn Plugin>> = vec![Arc::new(KeyAuth::new(&json!({})).unwrap())];
    for malformed in [
        "Bearer\r\nX-Injected: 1",
        // Validated after trimming but emitted as-is, the wire builder would
        // drop this value and send a challenge-less 401.
        "Bearer\r\n",
        "Basic realm=\"unterminated",
        "Bearer error=\"invalid_token\", error=\"invalid_request\"",
        "Basic realm=\"ok\", Bearer\u{7}",
    ] {
        let (status, headers) = finalize_401(
            &plugins,
            401,
            HashMap::from([("WWW-Authenticate".to_string(), malformed.to_string())]),
        )
        .await;
        assert_eq!(status, 401);
        assert_eq!(challenge_field_count(&headers), 1, "{malformed:?}");
        let emitted = challenge_header(&headers).expect("a challenge is emitted");
        assert_eq!(
            emitted,
            auth_flow::API_KEY_AUTHENTICATION_CHALLENGE,
            "{malformed:?}"
        );
        assert!(http::HeaderValue::from_str(emitted).is_ok());
    }
}

#[tokio::test]
async fn a_plugin_401_keeps_every_valid_challenge_across_field_spellings() {
    let (status, headers) = finalize_401(
        &[],
        401,
        HashMap::from([
            (
                "WWW-Authenticate".to_string(),
                r#"Basic realm="a""#.to_string(),
            ),
            (
                "www-authenticate".to_string(),
                r#"Basic realm="b", Bearer"#.to_string(),
            ),
            ("Www-Authenticate".to_string(), "Bearer\r\n".to_string()),
        ]),
    )
    .await;
    assert_eq!(status, 401);
    assert_eq!(challenge_field_count(&headers), 1, "{headers:?}");
    // Spellings are read in a fixed order, so the result is deterministic.
    assert_eq!(
        challenge_header(&headers),
        Some(r#"Basic realm="a", Basic realm="b", Bearer"#)
    );
}

/// A header policy that would delete the field cannot leave a gateway `401`
/// without a challenge: the guarantee is re-asserted over the final map.
#[tokio::test]
async fn operator_header_policies_cannot_strip_a_gateway_challenge() {
    let policies: Vec<Arc<dyn Plugin>> = vec![
        Arc::new(
            ferrum_edge::plugins::security_headers::SecurityHeaders::new(
                &json!({"remove": ["WWW-Authenticate"]}),
            )
            .unwrap(),
        ),
        Arc::new(
            ferrum_edge::plugins::response_transformer::ResponseTransformer::new(&json!({
                "rules": [
                    {"operation": "remove", "target": "header", "key": "WWW-Authenticate"}
                ]
            }))
            .unwrap(),
        ),
    ];
    for policy in policies {
        let plugins: Vec<Arc<dyn Plugin>> =
            vec![Arc::new(KeyAuth::new(&json!({})).unwrap()), policy];
        let (status, headers) = finalize_401(&plugins, 401, HashMap::new()).await;
        assert_eq!(status, 401);
        assert_eq!(
            challenge_header(&headers),
            Some(auth_flow::API_KEY_AUTHENTICATION_CHALLENGE)
        );
    }

    // The same `security_headers` policy still governs every other status.
    let plugins: Vec<Arc<dyn Plugin>> = vec![Arc::new(
        ferrum_edge::plugins::security_headers::SecurityHeaders::new(
            &json!({"remove": ["WWW-Authenticate"]}),
        )
        .unwrap(),
    )];
    let (status, headers) = finalize_401(
        &plugins,
        403,
        HashMap::from([("WWW-Authenticate".to_string(), "Bearer".to_string())]),
    )
    .await;
    assert_eq!(status, 403);
    assert_eq!(challenge_header(&headers), None);
}

/// Adding the challenge leaves the CORS decoration of the rejection intact.
#[tokio::test]
async fn the_challenge_preserves_cors_decoration() {
    let cors_config = json!({"allowed_origins": ["https://app.example"]});
    let mut access_control_headers = Vec::new();
    for status_code in [403, 401] {
        let plugins: Vec<Arc<dyn Plugin>> = vec![
            Arc::new(KeyAuth::new(&json!({})).unwrap()),
            Arc::new(ferrum_edge::plugins::cors::CorsPlugin::new(&cors_config).unwrap()),
        ];
        let mut ctx = ctx_with_header("origin", "https://app.example");
        for plugin in &plugins {
            assert_continue(plugin.on_request_received(&mut ctx).await);
        }
        let (status, headers) =
            finalize_with(&plugins, &mut ctx, status_code, HashMap::new()).await;
        assert_eq!(status, status_code);
        if status_code == 401 {
            assert_eq!(
                challenge_header(&headers),
                Some(auth_flow::API_KEY_AUTHENTICATION_CHALLENGE)
            );
        }
        let mut cors: Vec<(String, String)> = headers
            .iter()
            .filter(|(name, _)| {
                let name = name.to_ascii_lowercase();
                name.starts_with("access-control-") || name == "vary"
            })
            .map(|(name, value)| (name.to_ascii_lowercase(), value.clone()))
            .collect();
        cors.sort();
        access_control_headers.push(cors);
    }
    assert_eq!(access_control_headers[0], access_control_headers[1]);
}

/// A plugin that relays an origin-authored response (a cached, federated, or
/// function response) as its short-circuit.
struct OriginRelay;

#[async_trait]
impl Plugin for OriginRelay {
    fn name(&self) -> &str {
        "origin_relay"
    }

    fn rejects_with_origin_response(&self) -> bool {
        true
    }
}

/// An origin `401` carried by a plugin short-circuit is passed through as the
/// origin authored it: the gateway did not author it, so it adds no challenge.
#[tokio::test]
async fn an_origin_authored_401_is_never_given_a_gateway_challenge() {
    let plugins: Vec<Arc<dyn Plugin>> = vec![Arc::new(KeyAuth::new(&json!({})).unwrap())];

    let mut serverless = ctx();
    ferrum_edge::_test_support::set_serverless_terminate_response_for_test(&mut serverless, true);
    let (status, headers) = finalize_with(&plugins, &mut serverless, 401, HashMap::new()).await;
    assert_eq!(status, 401);
    assert_eq!(challenge_header(&headers), None, "{headers:?}");

    let mut relayed = ctx();
    ferrum_edge::_test_support::note_rejecting_plugin_for_test(&relayed, &OriginRelay);
    let (status, headers) = finalize_with(&plugins, &mut relayed, 401, HashMap::new()).await;
    assert_eq!(status, 401);
    assert_eq!(challenge_header(&headers), None, "{headers:?}");

    // A gateway rejection on the same route still gets one.
    let (status, headers) = finalize_401(&plugins, 401, HashMap::new()).await;
    assert_eq!(status, 401);
    assert_eq!(
        challenge_header(&headers),
        Some(auth_flow::API_KEY_AUTHENTICATION_CHALLENGE)
    );
}

#[tokio::test]
async fn distinct_realms_from_several_mechanisms_are_all_advertised() {
    let auth_plugins: Vec<Arc<dyn Plugin>> = vec![
        Arc::new(ChallengelessAuth {
            rejection_headers: HashMap::from([(
                "www-authenticate".to_string(),
                r#"Basic realm="tenant-a""#.to_string(),
            )]),
        }),
        Arc::new(basic_auth()),
    ];
    let mut ctx = ctx();
    assert_phase_unauthorized_with_challenge(
        run_authentication_phase(AuthMode::Single, &auth_plugins, &mut ctx, &consumers()).await,
        r#"Basic realm="tenant-a", Basic realm="ferrum-edge", charset="UTF-8""#,
    );
}

/// The fixed pre-commitment authorization-expiry terminal (issue #3815) names
/// the committing mechanism's scheme.
#[tokio::test]
async fn the_authorization_expiry_terminal_carries_a_challenge() {
    use ferrum_edge::proxy::auth_lifetime::StreamAuthTermination;

    for (auth_method, expected) in [
        (Some("jwt_auth"), auth_flow::BEARER_INVALID_TOKEN_CHALLENGE),
        (
            Some("mtls_auth"),
            auth_flow::CLIENT_CERTIFICATE_AUTHENTICATION_CHALLENGE,
        ),
        (None, auth_flow::GENERIC_AUTHENTICATION_CHALLENGE),
    ] {
        let mut ctx = ctx();
        ctx.identified_consumer = Some(Arc::new(create_test_consumer()));
        ctx.auth_method = auth_method;
        for termination in [
            StreamAuthTermination::CredentialExpired,
            StreamAuthTermination::AuthenticatedStreamMaxLifetime,
        ] {
            let (status, headers, _) =
                ferrum_edge::_test_support::authorization_expired_pre_commitment_response_for_test(
                    &ctx,
                    termination,
                    false,
                );
            assert_eq!(status, 401);
            assert_eq!(
                challenge_header(&headers),
                Some(expected),
                "{auth_method:?}"
            );
        }
        // Native gRPC keeps its trailers-only UNAUTHENTICATED framing.
        let (status, headers, _) =
            ferrum_edge::_test_support::authorization_expired_pre_commitment_response_for_test(
                &ctx,
                StreamAuthTermination::CredentialExpired,
                true,
            );
        assert_eq!(status, 200);
        assert_eq!(challenge_header(&headers), None);
    }
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

/// A response-phase plugin that replaces a backend response with a `401`
/// carrying no challenge (a WAF response refusal configured for `401`, say).
struct ResponseRefusal401;

#[async_trait]
impl Plugin for ResponseRefusal401 {
    fn name(&self) -> &str {
        "response_refusal_401"
    }

    async fn after_proxy(
        &self,
        _ctx: &mut RequestContext,
        _response_status: u16,
        _response_headers: &mut HashMap<String, String>,
    ) -> PluginResult {
        PluginResult::Reject {
            status_code: 401,
            body: r#"{"error":"response refused"}"#.to_string(),
            headers: HashMap::new(),
        }
    }
}

#[tokio::test]
async fn a_response_phase_401_rejection_carries_a_challenge() {
    let plugins: Vec<Arc<dyn Plugin>> = vec![
        Arc::new(KeyAuth::new(&json!({})).unwrap()),
        Arc::new(ResponseRefusal401),
    ];
    let mut ctx = ctx();
    let mut backend_headers =
        HashMap::from([("content-type".to_string(), "application/json".to_string())]);
    let (status, _, headers) = ferrum_edge::_test_support::run_after_proxy_hooks_reject_for_test(
        &plugins,
        &mut ctx,
        200,
        &mut backend_headers,
    )
    .await
    .expect("the response-phase plugin refuses the backend response");
    assert_eq!(status, 401);
    assert_eq!(
        challenge_header(&headers),
        Some(auth_flow::API_KEY_AUTHENTICATION_CHALLENGE)
    );
}

#[tokio::test]
async fn an_accepted_backend_401_is_left_as_the_backend_sent_it() {
    let plugins: Vec<Arc<dyn Plugin>> = vec![Arc::new(KeyAuth::new(&json!({})).unwrap())];
    let mut ctx = ctx();
    let mut backend_headers =
        HashMap::from([("content-type".to_string(), "application/json".to_string())]);
    assert!(
        ferrum_edge::_test_support::run_after_proxy_hooks_reject_for_test(
            &plugins,
            &mut ctx,
            401,
            &mut backend_headers,
        )
        .await
        .is_none()
    );
    assert_eq!(challenge_header(&backend_headers), None);
}

/// A body policy that refuses a buffered synthetic response with a `401`.
struct SyntheticBodyRefusal401;

#[async_trait]
impl Plugin for SyntheticBodyRefusal401 {
    fn name(&self) -> &str {
        "synthetic_body_refusal_401"
    }

    fn requires_response_body_buffering(&self) -> bool {
        true
    }

    async fn on_final_response_body(
        &self,
        _ctx: &mut RequestContext,
        _response_status: u16,
        _response_headers: &HashMap<String, String>,
        _body: &[u8],
    ) -> PluginResult {
        PluginResult::Reject {
            status_code: 401,
            body: r#"{"error":"body refused"}"#.to_string(),
            headers: HashMap::new(),
        }
    }
}

/// An origin short-circuit that gateway policy replaced is gateway-authored:
/// the replacement `401` gets its challenge (issue #6774).
#[tokio::test]
async fn a_gateway_replacement_of_an_origin_response_carries_a_challenge() {
    let plugins: Vec<Arc<dyn Plugin>> = vec![
        Arc::new(KeyAuth::new(&json!({})).unwrap()),
        Arc::new(SyntheticBodyRefusal401),
    ];
    let mut serverless = ctx();
    ferrum_edge::_test_support::set_serverless_terminate_response_for_test(&mut serverless, true);
    let (status, headers) = finalize_with(
        &plugins,
        &mut serverless,
        200,
        HashMap::from([("content-type".to_string(), "application/json".to_string())]),
    )
    .await;
    assert_eq!(status, 401);
    assert_eq!(
        challenge_header(&headers),
        Some(auth_flow::API_KEY_AUTHENTICATION_CHALLENGE),
        "{headers:?}"
    );
}

/// Several `Digest` alternatives one custom mechanism offers for one realm
/// survive authentication-phase aggregation (RFC 7616 §3.7).
#[tokio::test]
async fn digest_alternatives_survive_authentication_phase_aggregation() {
    let digest = r#"Digest realm="api", algorithm=SHA-256, nonce="n1", Digest realm="api", algorithm=MD5, nonce="n1""#;
    let auth_plugins: Vec<Arc<dyn Plugin>> = vec![Arc::new(ChallengelessAuth {
        rejection_headers: HashMap::from([("WWW-Authenticate".to_string(), digest.to_string())]),
    })];
    for mode in [AuthMode::Single, AuthMode::Multi] {
        let mut ctx = ctx();
        assert_phase_unauthorized_with_challenge(
            run_authentication_phase(mode, &auth_plugins, &mut ctx, &consumers()).await,
            digest,
        );
    }
}

/// A final client-visible response-header policy that refuses a `200` with a
/// `401` (a `waf` response-header rule with `reject_status_code: 401`, say).
struct FinalHeaderPolicyRefusal401;

#[async_trait]
impl Plugin for FinalHeaderPolicyRefusal401 {
    fn name(&self) -> &str {
        "final_header_policy_refusal_401"
    }

    fn enforces_final_client_visible_response_headers(&self, _ctx: &RequestContext) -> bool {
        true
    }

    async fn finalize_client_visible_response_headers(
        &self,
        _ctx: &mut RequestContext,
        response_status: u16,
        _response_headers: &HashMap<String, String>,
    ) -> PluginResult {
        if response_status == 401 {
            return PluginResult::Continue;
        }
        PluginResult::Reject {
            status_code: 401,
            body: r#"{"error":"response header refused"}"#.to_string(),
            headers: HashMap::new(),
        }
    }
}

/// A reject-path hook opted in to replacing the response, answering with a
/// `401` of the same status as the response it replaces.
struct SameStatusReplacer401;

#[async_trait]
impl Plugin for SameStatusReplacer401 {
    fn name(&self) -> &str {
        "same_status_replacer_401"
    }

    fn applies_after_proxy_on_reject(&self) -> bool {
        true
    }

    fn may_replace_rejection_response(&self) -> bool {
        true
    }

    async fn after_proxy(
        &self,
        _ctx: &mut RequestContext,
        _response_status: u16,
        _response_headers: &mut HashMap<String, String>,
    ) -> PluginResult {
        PluginResult::Reject {
            status_code: 401,
            body: r#"{"error":"replaced"}"#.to_string(),
            headers: HashMap::new(),
        }
    }
}

/// An origin short-circuit replaced by the final header policy is
/// gateway-authored, so the replacement `401` gets its challenge.
#[tokio::test]
async fn a_final_header_policy_replacement_of_an_origin_response_carries_a_challenge() {
    let plugins: Vec<Arc<dyn Plugin>> = vec![
        Arc::new(KeyAuth::new(&json!({})).unwrap()),
        Arc::new(FinalHeaderPolicyRefusal401),
    ];
    let mut serverless = ctx();
    ferrum_edge::_test_support::set_serverless_terminate_response_for_test(&mut serverless, true);
    let (status, headers) = finalize_with(
        &plugins,
        &mut serverless,
        200,
        HashMap::from([("content-type".to_string(), "application/json".to_string())]),
    )
    .await;
    assert_eq!(status, 401);
    assert_eq!(
        challenge_header(&headers),
        Some(auth_flow::API_KEY_AUTHENTICATION_CHALLENGE),
        "{headers:?}"
    );
}

/// A same-status replacement by an opted-in reject hook is still a gateway
/// replacement of the origin `401`.
#[tokio::test]
async fn a_same_status_reject_hook_replacement_of_an_origin_401_carries_a_challenge() {
    let plugins: Vec<Arc<dyn Plugin>> = vec![
        Arc::new(KeyAuth::new(&json!({})).unwrap()),
        Arc::new(SameStatusReplacer401),
    ];
    let mut serverless = ctx();
    ferrum_edge::_test_support::set_serverless_terminate_response_for_test(&mut serverless, true);
    let (status, headers) = finalize_with(&plugins, &mut serverless, 401, HashMap::new()).await;
    assert_eq!(status, 401);
    assert_eq!(
        challenge_header(&headers),
        Some(auth_flow::API_KEY_AUTHENTICATION_CHALLENGE),
        "{headers:?}"
    );
}
