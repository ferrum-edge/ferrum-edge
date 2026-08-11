//! Authenticated-principal size boundary (GHSA-m28c-f3v5-26qg).
//!
//! An oversized verified external identity must be rejected where it would
//! become the authoritative principal, never silently shortened. Truncation
//! would let two distinct principals sharing a prefix collapse into one
//! downstream billing identity.

use ferrum_edge::plugins::RequestContext;
use ferrum_edge::plugins::utils::auth_attempt::AuthenticationAttempt;
use ferrum_edge::plugins::utils::auth_flow::{
    MAX_AUTHENTICATED_IDENTITY_BYTES, VerifyOutcome, authentication_attempt_can_commit,
    commit_authentication_attempt,
};

use super::plugin_utils::create_test_consumer;

fn context() -> RequestContext {
    RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/test".to_string(),
    )
}

fn external_success(identity: &str) -> VerifyOutcome {
    VerifyOutcome::success(None, Some(identity.to_string()), None)
}

#[test]
fn identity_at_the_limit_is_committed_verbatim() {
    let identity = "a".repeat(MAX_AUTHENTICATED_IDENTITY_BYTES);
    let mut ctx = context();
    let committed = commit_authentication_attempt(
        &mut ctx,
        AuthenticationAttempt::new(),
        external_success(&identity),
        "jwks_auth",
        true,
    )
    .expect("exactly-at-limit identity is accepted");
    assert!(committed);
    assert_eq!(
        ctx.authenticated_identity.as_deref(),
        Some(identity.as_str())
    );
}

#[test]
fn identity_one_byte_over_the_limit_is_rejected_not_truncated() {
    let identity = "a".repeat(MAX_AUTHENTICATED_IDENTITY_BYTES + 1);
    let mut ctx = context();
    let outcome = commit_authentication_attempt(
        &mut ctx,
        AuthenticationAttempt::new(),
        external_success(&identity),
        "jwks_auth",
        true,
    );
    match outcome {
        Err(VerifyOutcome::Forbidden(body)) => {
            assert!(body.contains("exceeds"), "unexpected body: {body}");
            // The rejection must not echo the credential-derived identity.
            assert!(!body.contains(&identity), "identity leaked into the error");
        }
        other => panic!("expected Forbidden rejection, got {other:?}"),
    }
    assert_eq!(
        ctx.authenticated_identity, None,
        "a rejected attempt must leave no principal"
    );
    assert!(ctx.identified_consumer.is_none());
    assert!(ctx.auth_method.is_none());
}

/// Two distinct principals sharing a long prefix must both be rejected rather
/// than reduced to one identical accepted principal.
#[test]
fn shared_prefix_oversized_identities_do_not_become_one_principal() {
    let prefix = "p".repeat(MAX_AUTHENTICATED_IDENTITY_BYTES);
    for suffix in ["alice", "bob"] {
        let identity = format!("{prefix}{suffix}");
        let mut ctx = context();
        let outcome = commit_authentication_attempt(
            &mut ctx,
            AuthenticationAttempt::new(),
            external_success(&identity),
            "jwks_auth",
            true,
        );
        assert!(
            matches!(outcome, Err(VerifyOutcome::Forbidden(_))),
            "shared-prefix identity must be rejected"
        );
        assert_eq!(ctx.authenticated_identity, None);
    }
}

/// A multibyte identity that is under the byte limit is accepted untouched, and
/// one over the limit is rejected — the bound is on bytes, never on a
/// char-boundary-shortened value.
#[test]
fn multibyte_identity_bound_is_byte_exact() {
    // 'é' is two UTF-8 bytes.
    let under = "é".repeat(MAX_AUTHENTICATED_IDENTITY_BYTES / 2);
    assert_eq!(under.len(), MAX_AUTHENTICATED_IDENTITY_BYTES);
    let mut ctx = context();
    assert!(
        commit_authentication_attempt(
            &mut ctx,
            AuthenticationAttempt::new(),
            external_success(&under),
            "jwks_auth",
            true,
        )
        .is_ok()
    );
    assert_eq!(ctx.authenticated_identity.as_deref(), Some(under.as_str()));

    let over = format!("{under}é");
    let mut ctx = context();
    assert!(matches!(
        commit_authentication_attempt(
            &mut ctx,
            AuthenticationAttempt::new(),
            external_success(&over),
            "jwks_auth",
            true,
        ),
        Err(VerifyOutcome::Forbidden(_))
    ));
    assert_eq!(ctx.authenticated_identity, None);
}

/// The oversize check must also cover the display/header identity, which is
/// forwarded to backends as `X-Consumer-Username`.
#[test]
fn oversized_display_identity_is_rejected() {
    let header = "h".repeat(MAX_AUTHENTICATED_IDENTITY_BYTES + 1);
    let mut ctx = context();
    let outcome = commit_authentication_attempt(
        &mut ctx,
        AuthenticationAttempt::new(),
        VerifyOutcome::success(None, Some("alice".to_string()), Some(header)),
        "jwks_auth",
        true,
    );
    assert!(matches!(outcome, Err(VerifyOutcome::Forbidden(_))));
    assert_eq!(ctx.authenticated_identity, None);
    assert_eq!(ctx.authenticated_identity_header, None);
}

/// The non-mutating preflight must agree with the commit boundary, so a caller
/// with irreversible side effects does not perform them for an attempt that the
/// boundary is going to reject.
#[test]
fn preflight_agrees_with_the_commit_boundary() {
    let ctx = context();
    let oversized = external_success(&"a".repeat(MAX_AUTHENTICATED_IDENTITY_BYTES + 1));
    assert!(!authentication_attempt_can_commit(&ctx, &oversized, true));

    let allowed = external_success(&"a".repeat(MAX_AUTHENTICATED_IDENTITY_BYTES));
    assert!(authentication_attempt_can_commit(&ctx, &allowed, true));
}

/// A valid primary external identity plus an oversized display/header claim
/// must fail both preflight and final commit — otherwise OIDC session auth can
/// rotate a refresh token after a true preflight and still be rejected.
#[test]
fn preflight_and_commit_agree_on_oversized_display_header() {
    let header = "h".repeat(MAX_AUTHENTICATED_IDENTITY_BYTES + 1);
    let outcome = VerifyOutcome::success(None, Some("alice".to_string()), Some(header));
    let ctx = context();
    assert!(
        !authentication_attempt_can_commit(&ctx, &outcome, true),
        "preflight must reject an oversized display/header claim"
    );

    let mut ctx = context();
    let commit = commit_authentication_attempt(
        &mut ctx,
        AuthenticationAttempt::new(),
        outcome,
        "oidc_relying_party",
        true,
    );
    assert!(
        matches!(commit, Err(VerifyOutcome::Forbidden(_))),
        "commit must reject the same oversized display/header claim"
    );
    assert_eq!(ctx.authenticated_identity, None);
    assert_eq!(ctx.authenticated_identity_header, None);
    assert!(ctx.auth_method.is_none());
}

/// An oversized header without a usable/permitted external principal must not
/// block a mapped Consumer-only attempt: the display claim is meaningless then
/// and is discarded at the commit boundary.
#[test]
fn oversized_header_without_external_identity_does_not_block_consumer() {
    let consumer = std::sync::Arc::new(create_test_consumer());
    let header = "h".repeat(MAX_AUTHENTICATED_IDENTITY_BYTES + 1);

    // No external identity at all.
    let outcome = VerifyOutcome::success(
        Some(std::sync::Arc::clone(&consumer)),
        None,
        Some(header.clone()),
    );
    let ctx = context();
    assert!(
        authentication_attempt_can_commit(&ctx, &outcome, true),
        "preflight must not treat an orphaned oversized header as a principal bound"
    );
    let mut ctx = context();
    assert!(
        commit_authentication_attempt(
            &mut ctx,
            AuthenticationAttempt::new(),
            outcome,
            "key_auth",
            true,
        )
        .expect("consumer-only commit is accepted")
    );
    assert_eq!(
        ctx.identified_consumer
            .as_ref()
            .map(|c| c.username.as_str()),
        Some("testuser")
    );
    assert_eq!(ctx.authenticated_identity, None);
    assert_eq!(ctx.authenticated_identity_header, None);

    // Blank/whitespace-only external identity is also not a usable principal,
    // so the oversized header remains discarded.
    let outcome = VerifyOutcome::Success {
        consumer: Some(std::sync::Arc::clone(&consumer)),
        external_identity: Some("   \t".to_string()),
        external_identity_header: Some(header.clone()),
        credential_deadline: None,
    };
    let ctx = context();
    assert!(authentication_attempt_can_commit(&ctx, &outcome, true));
    let mut ctx = context();
    assert!(
        commit_authentication_attempt(
            &mut ctx,
            AuthenticationAttempt::new(),
            outcome,
            "key_auth",
            true,
        )
        .expect("blank external identity discards the header")
    );
    assert_eq!(ctx.authenticated_identity, None);
    assert_eq!(ctx.authenticated_identity_header, None);

    // External identities disabled: oversized header must not block the Consumer.
    let outcome = VerifyOutcome::success(Some(consumer), Some("alice".to_string()), Some(header));
    let ctx = context();
    assert!(authentication_attempt_can_commit(&ctx, &outcome, false));
    let mut ctx = context();
    assert!(
        commit_authentication_attempt(
            &mut ctx,
            AuthenticationAttempt::new(),
            outcome,
            "key_auth",
            false,
        )
        .expect("external identities disabled still commits the Consumer")
    );
    assert_eq!(ctx.authenticated_identity, None);
    assert_eq!(ctx.authenticated_identity_header, None);
}

/// Blank display/header normalization must stay aligned between preflight and
/// commit: whitespace-only headers are discarded, not size-checked.
#[test]
fn blank_display_header_normalization_aligned_with_preflight() {
    let blank_headers = ["", "   ", "\t\n", " \n\t "];
    for blank in blank_headers {
        let outcome = VerifyOutcome::Success {
            consumer: None,
            external_identity: Some("alice".to_string()),
            external_identity_header: Some(blank.to_string()),
            credential_deadline: None,
        };
        let ctx = context();
        assert!(
            authentication_attempt_can_commit(&ctx, &outcome, true),
            "blank header {blank:?} must not fail preflight"
        );
        let mut ctx = context();
        let committed = commit_authentication_attempt(
            &mut ctx,
            AuthenticationAttempt::new(),
            outcome,
            "jwks_auth",
            true,
        )
        .expect("blank header is discarded, not rejected");
        assert!(committed);
        assert_eq!(ctx.authenticated_identity.as_deref(), Some("alice"));
        assert_eq!(
            ctx.authenticated_identity_header, None,
            "blank header {blank:?} must normalize away"
        );
    }
}

/// When external identities are not permitted the claim is discarded before the
/// bound applies, so a mapped Consumer still commits normally.
#[test]
fn oversized_claim_is_ignored_when_external_identity_is_not_allowed() {
    let mut ctx = context();
    let consumer = std::sync::Arc::new(create_test_consumer());
    let outcome = commit_authentication_attempt(
        &mut ctx,
        AuthenticationAttempt::new(),
        VerifyOutcome::success(
            Some(consumer),
            Some("a".repeat(MAX_AUTHENTICATED_IDENTITY_BYTES + 1)),
            None,
        ),
        "key_auth",
        false,
    )
    .expect("consumer-only commit is accepted");
    assert!(outcome);
    assert_eq!(
        ctx.identified_consumer
            .as_ref()
            .map(|c| c.username.as_str()),
        Some("testuser")
    );
    assert_eq!(ctx.authenticated_identity, None);
}
