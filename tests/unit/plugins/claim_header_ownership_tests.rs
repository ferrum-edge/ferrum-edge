//! Coverage for gateway-owned `claim_headers` destinations
//! (GHSA-99wm-qwwv-33v9): a plugin instance sanitizes and installs exactly the
//! destinations it configures, so a client-supplied value can never survive an
//! authenticated request and one instance can never consume or erase another
//! instance's verified value.

use std::collections::HashMap;

use chrono::Utc;
use serde_json::{Value, json};

use ferrum_edge::ConsumerIndex;
use ferrum_edge::config::types::{Consumer, default_namespace};
use ferrum_edge::plugins::utils::auth_attempt::AuthenticationAttempt;
use ferrum_edge::plugins::utils::auth_flow::{VerifyOutcome, commit_authentication_attempt};
use ferrum_edge::plugins::utils::claim_header_fanout::{
    ClaimHeaderDestinations, ClaimHeaderMapping, apply_claim_headers_from_context,
    emit_claim_headers_to_attempt, parse_claim_headers,
};
use ferrum_edge::plugins::{Plugin, RequestContext, jwks_auth::JwksAuth};

use super::jwks_auth_support::{build_rsa_jwks_from_pem, create_rs256_token, default_client};
use super::plugin_utils::assert_continue;

const PREFIX: &str = "test_auth.claim_header.";

fn ctx() -> RequestContext {
    RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/protected".to_string(),
    )
}

fn consumer(id: &str, username: &str) -> Consumer {
    Consumer {
        labels: Default::default(),
        id: id.to_string(),
        username: username.to_string(),
        namespace: default_namespace(),
        custom_id: None,
        credentials: HashMap::new(),
        acl_groups: Vec::new(),
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

fn mappings(config: &Value) -> Vec<ClaimHeaderMapping> {
    parse_claim_headers(
        config.as_object().expect("object"),
        "claim_headers",
        "test_auth",
        PREFIX,
    )
    .expect("valid claim_headers")
}

/// Authenticate an external principal and install claim headers over `headers`.
fn authenticate_and_apply(claims: &Value, config: &Value, headers: &mut HashMap<String, String>) {
    let mapped = mappings(config);
    let destinations =
        ClaimHeaderDestinations::from_mapping_groups(std::iter::once(mapped.as_slice()));

    let mut ctx = ctx();
    let mut attempt = AuthenticationAttempt::new();
    emit_claim_headers_to_attempt(&mut attempt, claims, &mapped, ",");
    commit_authentication_attempt(
        &mut ctx,
        attempt,
        VerifyOutcome::success(None, Some("alice@example.test".to_string()), None),
        "test_auth",
        true,
    )
    .expect("attempt commits");

    apply_claim_headers_from_context(&mut ctx, headers, &destinations);
}

#[test]
fn present_claim_replaces_client_supplied_destination() {
    let config = json!({"claim_headers": {"email": "X-Authenticated-Email"}});
    let mut headers = HashMap::from([(
        "X-Authenticated-Email".to_string(),
        "attacker@example.test".to_string(),
    )]);

    authenticate_and_apply(
        &json!({"email": "verified@example.test"}),
        &config,
        &mut headers,
    );

    assert_eq!(
        headers.get("x-authenticated-email").map(String::as_str),
        Some("verified@example.test")
    );
    assert!(
        !headers.contains_key("X-Authenticated-Email"),
        "the client's case-variant copy must not survive alongside the gateway value"
    );
    assert_eq!(headers.len(), 1);
}

#[test]
fn absent_claim_leaves_destination_absent_instead_of_client_input() {
    let config = json!({"claim_headers": {"email": "X-Authenticated-Email"}});
    let mut headers = HashMap::from([(
        "X-Authenticated-Email".to_string(),
        "attacker@example.test".to_string(),
    )]);

    // Authenticated, but the token carries no `email` claim.
    authenticate_and_apply(&json!({"sub": "alice"}), &config, &mut headers);

    assert!(
        headers.is_empty(),
        "an absent claim must strip the gateway-owned destination, got {headers:?}"
    );
}

#[test]
fn unusable_claim_shapes_all_produce_an_absent_destination() {
    let config = json!({"claim_headers": {"email": "X-Authenticated-Email"}});
    for claims in [
        json!({"email": null}),
        json!({"email": ""}),
        json!({"email": "   "}),
        json!({"email": 42}),
        json!({"email": true}),
        json!({"email": []}),
        json!({"email": ["", "  "]}),
        json!({"email": [1, 2]}),
        json!({"email": {"nested": "value"}}),
    ] {
        let mut headers = HashMap::from([(
            "x-authenticated-email".to_string(),
            "attacker@example.test".to_string(),
        )]);
        authenticate_and_apply(&claims, &config, &mut headers);
        assert!(
            headers.is_empty(),
            "claims {claims} must leave the destination absent, got {headers:?}"
        );
    }
}

#[test]
fn every_case_variant_of_a_destination_is_removed() {
    let config = json!({"claim_headers": {"email": "X-Authenticated-Email"}});
    let mut headers = HashMap::from([
        (
            "X-Authenticated-Email".to_string(),
            "one@example.test".to_string(),
        ),
        (
            "x-AUTHENTICATED-email".to_string(),
            "two@example.test".to_string(),
        ),
        (
            "X-AUTHENTICATED-EMAIL".to_string(),
            "three@example.test".to_string(),
        ),
        ("X-Unrelated".to_string(), "keep-me".to_string()),
    ]);

    authenticate_and_apply(&json!({"sub": "alice"}), &config, &mut headers);

    assert_eq!(
        headers,
        HashMap::from([("X-Unrelated".to_string(), "keep-me".to_string())]),
        "only the gateway-owned destination may be stripped"
    );
}

#[test]
fn an_instance_never_strips_a_destination_it_does_not_own() {
    let config = json!({"claim_headers": {"email": "X-Owned"}});
    let mut headers = HashMap::from([
        ("X-Owned".to_string(), "attacker".to_string()),
        (
            "X-Other-Plugin-Destination".to_string(),
            "other".to_string(),
        ),
    ]);

    authenticate_and_apply(&json!({"sub": "alice"}), &config, &mut headers);

    assert!(!headers.contains_key("X-Owned"));
    assert_eq!(
        headers
            .get("X-Other-Plugin-Destination")
            .map(String::as_str),
        Some("other"),
        "another instance's destination must be untouched"
    );
}

#[test]
fn provider_override_destinations_are_owned_and_sanitized() {
    // Plugin-level mapping plus a provider override that targets a different
    // destination: both belong to the owned set.
    let plugin_level = mappings(&json!({"claim_headers": {"email": "X-Plugin-Email"}}));
    let provider_level = mappings(&json!({"claim_headers": {"email": "X-Provider-Email"}}));
    let destinations = ClaimHeaderDestinations::from_mapping_groups([
        plugin_level.as_slice(),
        provider_level.as_slice(),
    ]);
    let owned: Vec<&str> = destinations.names().collect();
    assert_eq!(
        owned,
        vec!["x-plugin-email", "x-provider-email"],
        "the owned set is the deduplicated union across provider overrides"
    );

    let mut ctx = ctx();
    let mut attempt = AuthenticationAttempt::new();
    // The matched provider staged only its own destination.
    emit_claim_headers_to_attempt(
        &mut attempt,
        &json!({"email": "verified@example.test"}),
        &provider_level,
        ",",
    );
    commit_authentication_attempt(
        &mut ctx,
        attempt,
        VerifyOutcome::success(None, Some("alice@example.test".to_string()), None),
        "test_auth",
        true,
    )
    .expect("attempt commits");

    let mut headers = HashMap::from([
        (
            "X-Plugin-Email".to_string(),
            "attacker@example.test".to_string(),
        ),
        (
            "X-Provider-Email".to_string(),
            "attacker@example.test".to_string(),
        ),
    ]);
    apply_claim_headers_from_context(&mut ctx, &mut headers, &destinations);

    assert_eq!(
        headers.get("x-provider-email").map(String::as_str),
        Some("verified@example.test")
    );
    assert!(
        !headers.contains_key("X-Plugin-Email") && !headers.contains_key("x-plugin-email"),
        "the unmatched plugin-level destination must be stripped, not left as client input"
    );
}

#[test]
fn a_later_instance_does_not_erase_a_shared_destination_already_installed() {
    let shared = mappings(&json!({"claim_headers": {"email": "X-Shared"}}));
    let destinations =
        ClaimHeaderDestinations::from_mapping_groups(std::iter::once(shared.as_slice()));

    let mut ctx = ctx();
    let mut attempt = AuthenticationAttempt::new();
    emit_claim_headers_to_attempt(
        &mut attempt,
        &json!({"email": "verified@example.test"}),
        &shared,
        ",",
    );
    commit_authentication_attempt(
        &mut ctx,
        attempt,
        VerifyOutcome::success(None, Some("alice@example.test".to_string()), None),
        "test_auth",
        true,
    )
    .expect("attempt commits");

    let mut headers =
        HashMap::from([("X-Shared".to_string(), "attacker@example.test".to_string())]);

    // First instance sanitizes and installs the verified value.
    apply_claim_headers_from_context(&mut ctx, &mut headers, &destinations);
    assert_eq!(
        headers.get("x-shared").map(String::as_str),
        Some("verified@example.test")
    );

    // A second instance sharing the destination has nothing staged; it must not
    // erase the value the first instance already installed.
    apply_claim_headers_from_context(&mut ctx, &mut headers, &destinations);
    assert_eq!(
        headers.get("x-shared").map(String::as_str),
        Some("verified@example.test"),
        "a shared destination is claimed once per request"
    );
}

#[test]
fn an_instance_never_installs_a_destination_owned_by_another_instance() {
    // Two instances of the same plugin type: they share the `claim_headers`
    // metadata prefix but own disjoint destinations. Only the second instance
    // authenticated, so only its destination has a staged value.
    let first_mappings = mappings(&json!({"claim_headers": {"email": "X-Instance-A-Email"}}));
    let second_mappings = mappings(&json!({"claim_headers": {"email": "X-Instance-B-Email"}}));
    let first =
        ClaimHeaderDestinations::from_mapping_groups(std::iter::once(first_mappings.as_slice()));
    let second =
        ClaimHeaderDestinations::from_mapping_groups(std::iter::once(second_mappings.as_slice()));

    let mut ctx = ctx();
    let mut attempt = AuthenticationAttempt::new();
    emit_claim_headers_to_attempt(
        &mut attempt,
        &json!({"email": "verified@example.test"}),
        &second_mappings,
        ",",
    );
    commit_authentication_attempt(
        &mut ctx,
        attempt,
        VerifyOutcome::success(None, Some("alice@example.test".to_string()), None),
        "test_auth",
        true,
    )
    .expect("attempt commits");

    let mut headers = HashMap::from([
        (
            "X-Instance-A-Email".to_string(),
            "attacker@example.test".to_string(),
        ),
        (
            "X-Instance-B-Email".to_string(),
            "attacker@example.test".to_string(),
        ),
    ]);

    // The non-authenticating instance runs first. It owns only its own
    // destination, so it strips that one and must neither install nor consume
    // the value staged for the other instance's destination.
    apply_claim_headers_from_context(&mut ctx, &mut headers, &first);
    assert!(
        !headers
            .keys()
            .any(|name| name.eq_ignore_ascii_case("x-instance-a-email")),
        "the earlier instance must strip its own unfilled destination, got {headers:?}"
    );

    // The true owner still has its staged value and installs it: the earlier
    // instance neither installed nor drained it.
    apply_claim_headers_from_context(&mut ctx, &mut headers, &second);
    assert_eq!(
        headers.get("x-instance-b-email").map(String::as_str),
        Some("verified@example.test"),
        "the authenticated instance's verified value must survive, got {headers:?}"
    );
    assert!(
        !headers.contains_key("X-Instance-B-Email"),
        "the client's copy of the owned destination must not survive, got {headers:?}"
    );
    assert_eq!(
        headers.len(),
        1,
        "no other header may be added: {headers:?}"
    );
}

#[tokio::test]
async fn jwks_auth_strips_client_claim_header_when_the_token_omits_the_claim() {
    let private_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_private.pem");
    let public_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_public.pem");
    let jwks = build_rsa_jwks_from_pem(public_key_pem);

    let plugin = JwksAuth::new(
        &json!({
            "providers": [{
                "jwks": jwks,
                "claim_headers": {"email": "X-Authenticated-Email"}
            }]
        }),
        default_client(),
    )
    .expect("valid jwks_auth config");
    assert!(plugin.modifies_request_headers());

    let consumer_index = ConsumerIndex::new(&[consumer("alice-id", "alice")]);
    // Valid token for an accepted principal, but with no `email` claim.
    let token = create_rs256_token(&json!({"sub": "alice"}), private_key_pem);

    let mut ctx = ctx();
    ctx.headers
        .insert("authorization".to_string(), format!("Bearer {token}"));
    ctx.headers.insert(
        "X-Authenticated-Email".to_string(),
        "attacker@example.test".to_string(),
    );
    assert_continue(plugin.authenticate(&mut ctx, &consumer_index).await);

    let mut headers = ctx.headers.clone();
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);

    assert!(
        !headers
            .keys()
            .any(|name| name.eq_ignore_ascii_case("x-authenticated-email")),
        "an authenticated request without the mapped claim must not forward client input, \
         got {headers:?}"
    );
}
