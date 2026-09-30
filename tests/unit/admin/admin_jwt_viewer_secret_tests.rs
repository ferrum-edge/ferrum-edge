//! Role-ceiling admin JWT verification: `FERRUM_ADMIN_JWT_VIEWER_SECRET`
//! (issue #5904).
//!
//! A token whose signature verifies under the viewer secret is authorized as
//! `viewer` whatever its `role` claim says. The ceiling comes from the key that
//! verified the signature, both keys are pinned to HS256, and identical
//! secrets are refused.
//!
//! `FERRUM_ADMIN_JWT_VIEWER_NAMESPACES` (issue #5929) adds a namespace ceiling
//! for the same key; its parser, token/actor wiring, and env wiring are pinned
//! at the bottom of this file.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{Duration, Utc};
use ferrum_edge::admin::audit::{AuditActor, NamespaceCeilingDecision};
use ferrum_edge::admin::jwt_auth::{
    ADMIN_JWT_VIEWER_SECRET_EQUALS_PRIMARY_ERROR, AdminKeyTier, AdminRole, JwtConfig, JwtError,
    JwtManager, MAX_VIEWER_KEY_SUBJECT_BYTES, ViewerNamespaceCeiling, create_jwt_manager_from_env,
    random_read_only_jwt_manager,
};
use ferrum_edge::fips::approved::HmacSha256;
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use serde_json::{Value, json};

use crate::unit::env_lock::EnvGuard;

const PRIMARY_SECRET: &str = "primary-admin-secret-0123456789abcdef";
const VIEWER_SECRET: &str = "viewer-ceiling-secret-0123456789abcdef";
const ISSUER: &str = "viewer-ceiling-test";

fn jwt_config(secret: &str, issuer: &str) -> JwtConfig {
    JwtConfig {
        secret: secret.to_string(),
        issuer: issuer.to_string(),
        audience: None,
        max_ttl_seconds: 3600,
        algorithm: Algorithm::HS256,
    }
}

fn manager_with_viewer_secret() -> JwtManager {
    JwtManager::new(jwt_config(PRIMARY_SECRET, ISSUER))
        .with_viewer_secret(VIEWER_SECRET.to_string())
        .expect("a distinct 32+ character viewer secret is accepted")
}

fn claims_window(role: Option<&str>, iat_offset: i64, exp_offset: i64) -> Value {
    let now = Utc::now();
    let mut claims = json!({
        "iss": ISSUER,
        "sub": "drift-monitor",
        "iat": (now + Duration::seconds(iat_offset)).timestamp(),
        "nbf": (now + Duration::seconds(iat_offset)).timestamp(),
        "exp": (now + Duration::seconds(exp_offset)).timestamp(),
        "jti": uuid::Uuid::new_v4().to_string(),
    });
    if let Some(role) = role {
        claims["role"] = json!(role);
    }
    claims
}

fn claims(role: &str) -> Value {
    claims_window(Some(role), 0, 600)
}

fn sign(claims: &Value, secret: &str, algorithm: Algorithm) -> String {
    encode(
        &Header::new(algorithm),
        claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
    .unwrap()
}

/// A token with an arbitrary header, HMAC-SHA-256-signed with `secret` — the
/// shape of an algorithm-confusion attempt.
fn forge_with_header(header: &Value, claims: &Value, secret: Option<&str>) -> String {
    let header = URL_SAFE_NO_PAD.encode(serde_json::to_vec(header).unwrap());
    let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims).unwrap());
    let signing_input = format!("{header}.{payload}");
    let signature = match secret {
        Some(secret) => {
            let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).unwrap();
            mac.update(signing_input.as_bytes());
            URL_SAFE_NO_PAD.encode(mac.finalize().as_ref())
        }
        None => String::new(),
    };
    format!("{signing_input}.{signature}")
}

#[test]
fn viewer_secret_token_is_capped_at_viewer_whatever_its_role_claim() {
    let manager = manager_with_viewer_secret();

    for claimed in [AdminRole::Viewer, AdminRole::Operator, AdminRole::Admin] {
        let token = sign(&claims(claimed.as_str()), VIEWER_SECRET, Algorithm::HS256);
        let verified = manager
            .verify_token(&token)
            .expect("viewer-secret token verifies");

        assert_eq!(verified.key_tier, AdminKeyTier::Viewer);
        assert_eq!(verified.role_ceiling(), AdminRole::Viewer);
        // The claim is untouched; the ceiling is applied at authorization.
        assert_eq!(verified.claims.admin_role().unwrap(), claimed);
        assert_eq!(verified.effective_role().unwrap(), AdminRole::Viewer);

        let actor = AuditActor::from_verified(&verified).expect("actor builds");
        assert_eq!(
            actor.role,
            AdminRole::Viewer,
            "a viewer-secret token claiming `{}` must authorize as viewer",
            claimed.as_str()
        );
        assert!(!actor.role.allows(AdminRole::Operator));
        assert!(!actor.role.allows(AdminRole::Admin));
    }
}

#[test]
fn viewer_secret_token_scopes_grant_nothing() {
    let manager = manager_with_viewer_secret();
    let mut scoped = claims("viewer");
    scoped["scope"] = json!("diagnostics:read");

    let capped = manager
        .verify_token(&sign(&scoped, VIEWER_SECRET, Algorithm::HS256))
        .expect("viewer-secret token verifies");
    assert!(capped.claims.grants_scope("diagnostics:read"));
    assert!(
        !capped.grants_scope("diagnostics:read"),
        "a viewer-key token must not obtain a scope from its own claim"
    );
    let actor = AuditActor::from_verified(&capped).unwrap();
    assert_eq!(actor.key_tier, AdminKeyTier::Viewer);
    assert!(!actor.key_tier.honours_scopes());
    assert_eq!(actor.audit_subject(), "viewer-key:drift-monitor");

    // Control: the same claims under the primary key keep the scope.
    let primary = manager
        .verify_token(&sign(&scoped, PRIMARY_SECRET, Algorithm::HS256))
        .expect("primary token verifies");
    assert!(primary.grants_scope("diagnostics:read"));
    let actor = AuditActor::from_verified(&primary).unwrap();
    assert_eq!(actor.audit_subject(), "drift-monitor");
}

#[test]
fn primary_secret_token_keeps_its_claimed_role() {
    let manager = manager_with_viewer_secret();

    for claimed in [AdminRole::Viewer, AdminRole::Operator, AdminRole::Admin] {
        let token = sign(&claims(claimed.as_str()), PRIMARY_SECRET, Algorithm::HS256);
        let verified = manager
            .verify_token(&token)
            .expect("primary-secret token verifies");
        assert_eq!(verified.key_tier, AdminKeyTier::Primary);
        assert_eq!(verified.role_ceiling(), AdminRole::Admin);
        let actor = AuditActor::from_verified(&verified).expect("actor builds");
        assert_eq!(actor.role, claimed);
    }
}

#[test]
fn viewer_secret_token_without_a_valid_role_claim_still_fails_closed() {
    let manager = manager_with_viewer_secret();

    let unknown_role = sign(&claims("superuser"), VIEWER_SECRET, Algorithm::HS256);
    let verified = manager.verify_token(&unknown_role).unwrap();
    assert!(verified.effective_role().is_err());
    assert!(AuditActor::from_verified(&verified).is_err());

    let missing_role = sign(
        &claims_window(None, 0, 600),
        VIEWER_SECRET,
        Algorithm::HS256,
    );
    let verified = manager.verify_token(&missing_role).unwrap();
    assert!(
        AuditActor::from_verified(&verified).is_err(),
        "the ceiling must never turn a role-less token into a viewer"
    );
}

#[test]
fn algorithm_confusion_is_rejected_for_both_keys() {
    let manager = manager_with_viewer_secret();
    let admin_claims = claims("admin");

    // Other HMAC algorithms, signed with either real secret.
    for secret in [PRIMARY_SECRET, VIEWER_SECRET] {
        for algorithm in [Algorithm::HS384, Algorithm::HS512] {
            let token = sign(&admin_claims, secret, algorithm);
            assert!(
                manager.verify_token(&token).is_err(),
                "{algorithm:?} must be refused; both keys are pinned to HS256"
            );
        }
    }

    // `alg: none` with an empty signature.
    let unsigned = forge_with_header(&json!({"alg": "none", "typ": "JWT"}), &admin_claims, None);
    assert!(manager.verify_token(&unsigned).is_err());

    // An asymmetric `alg` whose signature is really an HMAC under the viewer
    // secret (the classic public-key-as-HMAC-secret confusion).
    for alg in ["RS256", "ES256", "EdDSA", "PS256"] {
        let forged = forge_with_header(
            &json!({"alg": alg, "typ": "JWT"}),
            &admin_claims,
            Some(VIEWER_SECRET),
        );
        assert!(
            manager.verify_token(&forged).is_err(),
            "`alg: {alg}` must be refused"
        );
    }

    // Control: the same hand-built shape with `HS256` is accepted, capped,
    // so the refusals above are about the algorithm and not the forging.
    let control = forge_with_header(
        &json!({"alg": "HS256", "typ": "JWT"}),
        &admin_claims,
        Some(VIEWER_SECRET),
    );
    let verified = manager
        .verify_token(&control)
        .expect("HS256 control verifies");
    assert_eq!(verified.effective_role().unwrap(), AdminRole::Viewer);
}

#[test]
fn viewer_secret_tokens_get_the_full_claim_validation() {
    let manager = manager_with_viewer_secret();

    // Expired (validate_exp).
    let expired = sign(
        &claims_window(Some("viewer"), -900, -300),
        VIEWER_SECRET,
        Algorithm::HS256,
    );
    assert!(manager.verify_token(&expired).is_err());

    // Wrong issuer.
    let mut wrong_issuer = claims("viewer");
    wrong_issuer["iss"] = json!("someone-else");
    let wrong_issuer = sign(&wrong_issuer, VIEWER_SECRET, Algorithm::HS256);
    assert!(manager.verify_token(&wrong_issuer).is_err());

    // Lifetime beyond FERRUM_ADMIN_JWT_MAX_TTL.
    let too_long = sign(
        &claims_window(Some("viewer"), 0, 7200),
        VIEWER_SECRET,
        Algorithm::HS256,
    );
    assert!(manager.verify_token(&too_long).is_err());

    // Signed with neither secret.
    let foreign = sign(
        &claims("viewer"),
        "unrelated-secret-0123456789abcdef-xyz",
        Algorithm::HS256,
    );
    assert!(manager.verify_token(&foreign).is_err());
}

#[test]
fn viewer_key_subjects_with_control_characters_or_excess_length_are_rejected() {
    let manager = manager_with_viewer_secret();
    let long = "a".repeat(MAX_VIEWER_KEY_SUBJECT_BYTES + 1);
    let at_limit = "a".repeat(MAX_VIEWER_KEY_SUBJECT_BYTES);
    for sub in [
        "forged\nkey_tier=primary",
        "tab\there",
        "bell\u{7}",
        long.as_str(),
    ] {
        let mut hostile = claims("viewer");
        hostile["sub"] = json!(sub);
        let token = sign(&hostile, VIEWER_SECRET, Algorithm::HS256);
        assert!(
            manager.verify_token(&token).is_err(),
            "viewer-key subject {sub:?} must be refused"
        );
    }

    let mut ok = claims("viewer");
    ok["sub"] = json!(at_limit);
    let token = sign(&ok, VIEWER_SECRET, Algorithm::HS256);
    assert!(manager.verify_token(&token).is_ok());

    // Primary-key subjects keep their existing behaviour.
    let mut primary = claims("viewer");
    primary["sub"] = json!("line\nbreak");
    let token = sign(&primary, PRIMARY_SECRET, Algorithm::HS256);
    assert!(manager.verify_token(&token).is_ok());
}

#[test]
fn viewer_signed_token_is_rejected_without_a_configured_viewer_secret() {
    let manager = JwtManager::new(jwt_config(PRIMARY_SECRET, ISSUER));
    assert!(!manager.has_viewer_secret());
    let token = sign(&claims("viewer"), VIEWER_SECRET, Algorithm::HS256);
    assert!(manager.verify_token(&token).is_err());
}

#[test]
fn identical_and_short_viewer_secrets_are_refused_without_echoing_them() {
    let identical = JwtManager::new(jwt_config(PRIMARY_SECRET, ISSUER))
        .with_viewer_secret(PRIMARY_SECRET.to_string());
    let Err(JwtError::VerificationFailed(message)) = identical else {
        panic!("identical viewer and primary secrets must be refused");
    };
    assert_eq!(message, ADMIN_JWT_VIEWER_SECRET_EQUALS_PRIMARY_ERROR);
    assert!(!message.contains(PRIMARY_SECRET));

    let short = "short-viewer-secret";
    let refused =
        JwtManager::new(jwt_config(PRIMARY_SECRET, ISSUER)).with_viewer_secret(short.to_string());
    let Err(JwtError::VerificationFailed(message)) = refused else {
        panic!("a viewer secret under 32 characters must be refused");
    };
    assert!(message.contains("FERRUM_ADMIN_JWT_VIEWER_SECRET"));
    assert!(message.contains("at least"));
    assert!(!message.contains(short));
}

#[test]
fn create_jwt_manager_from_env_reads_and_validates_the_viewer_secret() {
    let env = EnvGuard::new(&[]);
    env.unset("FERRUM_ADMIN_JWT_ISSUER");
    env.unset("FERRUM_ADMIN_JWT_AUDIENCE");
    env.unset("FERRUM_ADMIN_JWT_MAX_TTL");
    env.set("FERRUM_ADMIN_JWT_SECRET", PRIMARY_SECRET);

    env.unset("FERRUM_ADMIN_JWT_VIEWER_SECRET");
    let manager = create_jwt_manager_from_env().expect("primary secret alone is valid");
    assert!(!manager.has_viewer_secret());

    env.set("FERRUM_ADMIN_JWT_VIEWER_SECRET", PRIMARY_SECRET);
    let Err(identical) = create_jwt_manager_from_env() else {
        panic!("identical secrets must be refused at startup");
    };
    assert!(identical.to_string().contains("must differ"));
    assert!(!identical.to_string().contains(PRIMARY_SECRET));

    env.set("FERRUM_ADMIN_JWT_VIEWER_SECRET", "too-short");
    assert!(create_jwt_manager_from_env().is_err());

    env.set("FERRUM_ADMIN_JWT_VIEWER_SECRET", VIEWER_SECRET);
    let manager = create_jwt_manager_from_env().expect("distinct viewer secret is accepted");
    assert!(manager.has_viewer_secret());
    let mut admin_claims = claims("admin");
    admin_claims["iss"] = json!("ferrum-edge");
    let token = sign(&admin_claims, VIEWER_SECRET, Algorithm::HS256);
    let verified = manager
        .verify_token(&token)
        .expect("viewer-secret token verifies with the default issuer");
    assert_eq!(verified.effective_role().unwrap(), AdminRole::Viewer);
}

#[test]
fn random_read_only_fallback_keeps_the_viewer_secret() {
    let env = EnvGuard::new(&[]);
    env.unset("FERRUM_ADMIN_JWT_SECRET");
    env.unset("FERRUM_ADMIN_JWT_ISSUER");
    env.unset("FERRUM_ADMIN_JWT_AUDIENCE");
    env.unset("FERRUM_ADMIN_JWT_MAX_TTL");
    env.set("FERRUM_ADMIN_JWT_VIEWER_SECRET", VIEWER_SECRET);

    assert!(matches!(
        create_jwt_manager_from_env(),
        Err(JwtError::NotConfigured)
    ));
    let manager = random_read_only_jwt_manager().expect("fallback builds");
    assert!(manager.has_viewer_secret());

    let mut admin_claims = claims("admin");
    admin_claims["iss"] = json!("ferrum-edge");
    let token = sign(&admin_claims, VIEWER_SECRET, Algorithm::HS256);
    let verified = manager
        .verify_token(&token)
        .expect("viewer-secret token verifies under the random-primary fallback");
    assert_eq!(verified.effective_role().unwrap(), AdminRole::Viewer);

    env.set("FERRUM_ADMIN_JWT_VIEWER_SECRET", "too-short");
    assert!(
        random_read_only_jwt_manager().is_err(),
        "an invalid viewer secret must fail startup, not be dropped"
    );
}

// ── FERRUM_ADMIN_JWT_VIEWER_NAMESPACES (issue #5929) ────────────────────

fn ceiling(raw: &str) -> ViewerNamespaceCeiling {
    ViewerNamespaceCeiling::parse(raw).expect("valid ceiling")
}

fn manager_with_namespace_ceiling(raw: &str) -> JwtManager {
    manager_with_viewer_secret().with_viewer_namespace_ceiling(ceiling(raw))
}

fn claims_with_ns(ns: Option<Value>) -> Value {
    let mut claims = claims("viewer");
    if let Some(ns) = ns {
        claims["ns"] = ns;
    }
    claims
}

fn actor_for(manager: &JwtManager, secret: &str, ns: Option<Value>) -> AuditActor {
    let token = sign(&claims_with_ns(ns), secret, Algorithm::HS256);
    let verified = manager.verify_token(&token).expect("token verifies");
    AuditActor::from_verified(&verified).expect("actor builds")
}

#[test]
fn viewer_namespace_ceiling_parser_trims_and_collapses_duplicates() {
    let parsed = ceiling(" staging ,analytics,staging");
    assert_eq!(parsed.len(), 2);
    assert!(!parsed.is_empty());
    assert!(parsed.allows("staging"));
    assert!(parsed.allows("analytics"));
    assert!(!parsed.allows("prod"));
    assert!(!parsed.allows(" staging "));
    assert!(ceiling("a.b_c-1").allows("a.b_c-1"));
}

#[test]
fn viewer_namespace_ceiling_parser_fails_closed_on_malformed_lists() {
    for (raw, expected) in [
        ("", "lists no namespace"),
        (" \t ", "lists no namespace"),
        ("staging,,prod", "entry 2 is empty"),
        ("staging,", "entry 2 is empty"),
        (",staging", "entry 1 is empty"),
        ("*", "wildcards are not supported"),
        ("staging,*", "entry 2 is `*`"),
        ("-leading-hyphen", "entry 1"),
        ("has space", "entry 1"),
        ("slash/name", "entry 1"),
    ] {
        let error = ViewerNamespaceCeiling::parse(raw).expect_err("malformed list is refused");
        assert!(
            error.contains("FERRUM_ADMIN_JWT_VIEWER_NAMESPACES"),
            "{raw:?}: {error}"
        );
        assert!(error.contains(expected), "{raw:?}: {error}");
    }
    let too_long = "a".repeat(255);
    let error = ViewerNamespaceCeiling::parse(&too_long).expect_err("255 characters is too long");
    assert!(error.contains("1-254 characters"), "{error}");
    assert!(ViewerNamespaceCeiling::parse(&"a".repeat(254)).is_ok());
}

#[test]
fn viewer_namespace_ceiling_error_names_only_the_offending_entry() {
    let error = ViewerNamespaceCeiling::parse("staging,Bad Name!,prod").expect_err("refused");
    assert!(error.contains("entry 2"), "{error}");
    assert!(error.contains("\"Bad Name!\""), "{error}");
    assert!(!error.contains("staging"), "{error}");
    assert!(!error.contains("prod"), "{error}");
}

#[test]
fn viewer_key_tokens_carry_the_namespace_ceiling_and_primary_tokens_do_not() {
    let manager = manager_with_namespace_ceiling("staging");
    assert!(manager.viewer_namespace_ceiling().is_some());

    let viewer = sign(&claims("admin"), VIEWER_SECRET, Algorithm::HS256);
    let verified = manager
        .verify_token(&viewer)
        .expect("viewer-key token verifies");
    assert_eq!(verified.key_tier, AdminKeyTier::Viewer);
    assert_eq!(verified.namespace_ceiling, Some(ceiling("staging")));

    let primary = sign(&claims("admin"), PRIMARY_SECRET, Algorithm::HS256);
    let verified = manager
        .verify_token(&primary)
        .expect("primary token verifies");
    assert_eq!(verified.key_tier, AdminKeyTier::Primary);
    assert_eq!(verified.namespace_ceiling, None);

    // Without a configured ceiling no viewer-key token carries one.
    let unbounded = manager_with_viewer_secret();
    let verified = unbounded.verify_token(&viewer).expect("verifies");
    assert_eq!(verified.namespace_ceiling, None);
}

#[test]
fn claim_less_viewer_key_actor_is_bounded_by_the_ceiling() {
    let manager = manager_with_namespace_ceiling("staging,analytics");
    let actor = actor_for(&manager, VIEWER_SECRET, None);

    // Claim presence records what the token carried.
    assert!(!actor.allowed_namespaces.is_present());
    assert_eq!(
        actor.namespace_ceiling_decision("staging"),
        NamespaceCeilingDecision::Within
    );
    assert_eq!(
        actor.namespace_ceiling_decision("analytics"),
        NamespaceCeilingDecision::Within
    );
    assert_eq!(
        actor.namespace_ceiling_decision("prod"),
        NamespaceCeilingDecision::Outside
    );
    assert_eq!(
        actor.namespace_ceiling_decision("ferrum"),
        NamespaceCeilingDecision::Outside
    );
}

#[test]
fn viewer_key_ns_claim_is_narrowed_to_the_ceiling() {
    let manager = manager_with_namespace_ceiling("staging");

    let wide = actor_for(&manager, VIEWER_SECRET, Some(json!(["staging", "prod"])));
    assert!(wide.allowed_namespaces.is_present());
    assert!(wide.allowed_namespaces.allows("staging"));
    assert!(
        !wide.allowed_namespaces.allows("prod"),
        "a viewer-key `ns` claim must not reach past the ceiling"
    );

    // A claim naming only namespaces outside the ceiling authorizes nothing.
    let outside = actor_for(&manager, VIEWER_SECRET, Some(json!("prod")));
    assert!(outside.allowed_namespaces.is_present());
    assert!(!outside.allowed_namespaces.allows("prod"));
    assert!(!outside.allowed_namespaces.allows("staging"));
    assert_eq!(
        outside.namespace_ceiling_decision("prod"),
        NamespaceCeilingDecision::Outside
    );

    // A malformed claim still fails closed.
    let token = sign(
        &claims_with_ns(Some(json!(""))),
        VIEWER_SECRET,
        Algorithm::HS256,
    );
    let verified = manager.verify_token(&token).expect("signature verifies");
    assert!(AuditActor::from_verified(&verified).is_err());
}

#[test]
fn primary_key_actor_is_unaffected_by_the_ceiling() {
    let manager = manager_with_namespace_ceiling("staging");

    let unscoped = actor_for(&manager, PRIMARY_SECRET, None);
    assert!(unscoped.namespace_ceiling.is_none());
    assert_eq!(
        unscoped.namespace_ceiling_decision("prod"),
        NamespaceCeilingDecision::NotApplicable
    );

    let scoped = actor_for(&manager, PRIMARY_SECRET, Some(json!(["prod"])));
    assert!(scoped.allowed_namespaces.allows("prod"));
    assert_eq!(
        scoped.namespace_ceiling_decision("prod"),
        NamespaceCeilingDecision::NotApplicable
    );
}

#[test]
fn ceiling_decision_is_recorded_on_security_audit_diffs_only_when_it_applies() {
    use ferrum_edge::admin::audit::with_namespace_ceiling_decision;

    let manager = manager_with_namespace_ceiling("staging");
    let base = json!({"failure_category": "namespace_denied", "resources": "all"});

    let viewer = actor_for(&manager, VIEWER_SECRET, None);
    let outside = with_namespace_ceiling_decision(base.clone(), &viewer, "prod");
    assert_eq!(outside["namespace_ceiling"], "outside");
    assert_eq!(outside["failure_category"], "namespace_denied");
    let within = with_namespace_ceiling_decision(base.clone(), &viewer, "staging");
    assert_eq!(within["namespace_ceiling"], "within");

    let primary = actor_for(&manager, PRIMARY_SECRET, None);
    let unchanged = with_namespace_ceiling_decision(base.clone(), &primary, "prod");
    assert_eq!(unchanged, base, "primary-key records keep their shape");
    assert_eq!(
        NamespaceCeilingDecision::NotApplicable.as_str(),
        "not_applicable"
    );
}

#[test]
fn create_jwt_manager_from_env_reads_and_validates_the_viewer_namespace_ceiling() {
    let env = EnvGuard::new(&[]);
    env.unset("FERRUM_ADMIN_JWT_ISSUER");
    env.unset("FERRUM_ADMIN_JWT_AUDIENCE");
    env.unset("FERRUM_ADMIN_JWT_MAX_TTL");
    env.set("FERRUM_ADMIN_JWT_SECRET", PRIMARY_SECRET);
    env.set("FERRUM_ADMIN_JWT_VIEWER_SECRET", VIEWER_SECRET);

    env.unset("FERRUM_ADMIN_JWT_VIEWER_NAMESPACES");
    let manager = create_jwt_manager_from_env().expect("no ceiling is valid");
    assert!(manager.viewer_namespace_ceiling().is_none());

    for invalid in ["", "staging,", "*", "Bad Name!"] {
        env.set("FERRUM_ADMIN_JWT_VIEWER_NAMESPACES", invalid);
        let Err(JwtError::VerificationFailed(message)) = create_jwt_manager_from_env() else {
            panic!("{invalid:?} must fail startup, not be dropped");
        };
        assert!(
            message.contains("FERRUM_ADMIN_JWT_VIEWER_NAMESPACES"),
            "{invalid:?}: {message}"
        );
    }

    env.set("FERRUM_ADMIN_JWT_VIEWER_NAMESPACES", "staging, analytics");
    let manager = create_jwt_manager_from_env().expect("a valid ceiling is accepted");
    assert_eq!(
        manager.viewer_namespace_ceiling(),
        Some(&ceiling("analytics,staging"))
    );
    let mut viewer_claims = claims("viewer");
    viewer_claims["iss"] = json!("ferrum-edge");
    let token = sign(&viewer_claims, VIEWER_SECRET, Algorithm::HS256);
    let verified = manager
        .verify_token(&token)
        .expect("viewer-key token verifies");
    let actor = AuditActor::from_verified(&verified).unwrap();
    assert_eq!(
        actor.namespace_ceiling_decision("prod"),
        NamespaceCeilingDecision::Outside
    );
}

#[test]
fn random_read_only_fallback_keeps_the_viewer_namespace_ceiling() {
    let env = EnvGuard::new(&[]);
    env.unset("FERRUM_ADMIN_JWT_SECRET");
    env.unset("FERRUM_ADMIN_JWT_ISSUER");
    env.unset("FERRUM_ADMIN_JWT_AUDIENCE");
    env.unset("FERRUM_ADMIN_JWT_MAX_TTL");
    env.set("FERRUM_ADMIN_JWT_VIEWER_SECRET", VIEWER_SECRET);
    env.set("FERRUM_ADMIN_JWT_VIEWER_NAMESPACES", "staging");

    let manager = random_read_only_jwt_manager().expect("fallback builds");
    assert_eq!(
        manager.viewer_namespace_ceiling(),
        Some(&ceiling("staging"))
    );

    env.set("FERRUM_ADMIN_JWT_VIEWER_NAMESPACES", "staging,,prod");
    assert!(
        random_read_only_jwt_manager().is_err(),
        "an invalid ceiling must fail startup, not be dropped"
    );
}
