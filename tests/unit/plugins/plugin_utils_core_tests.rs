use ferrum_edge::plugins::RequestContext;
use ferrum_edge::plugins::utils::auth_flow::ExtractedCredential;
use ferrum_edge::plugins::utils::cert_hash::{sha256_base64url_no_pad, sha256_hex_lower};
use ferrum_edge::plugins::utils::claim_resolver::{
    extract_claim_string, extract_claim_string_exact, extract_claim_values, parse_claim_path_value,
};
use ferrum_edge::plugins::utils::json_escape::escape_json_string;
use ferrum_edge::plugins::utils::jwks_store::JwksKeyStore;
use ferrum_edge::plugins::utils::jwt_verifier::{
    JwtVerifyParams, peek_unverified_issuer, verify_jwt_with_jwks,
};
use ferrum_edge::plugins::utils::query::{
    CanonicalQuery, QueryAmbiguity, canonical_query_for_policy, has_conflicting_duplicate_query_key,
};
use ferrum_edge::plugins::utils::scope_role_check::{ScopeRoleRequirements, check};
use ferrum_edge::plugins::utils::sse::{
    MAX_ANTHROPIC_CONTENT_BLOCKS, MAX_GEMINI_CANDIDATES, SseReassembler, SseText, SseTextKind,
    parse_sse_data_frames_checked,
};
use ferrum_edge::plugins::utils::token_extract::{
    TokenHeaderLocation, TokenLocation, TokenLocationExtract, extract_authorization_bearer,
    extract_from_location,
};
use jsonwebtoken::{EncodingKey, Header, encode};
use serde_json::json;

#[test]
fn json_escape_escapes_backslash_and_quote() {
    assert_eq!(escape_json_string(r#"a"b\c"#), r#"a\"b\\c"#);
}

#[test]
fn json_escape_escapes_angle_brackets() {
    assert_eq!(escape_json_string("<script>"), "\\u003cscript\\u003e");
}

#[test]
fn json_escape_passes_plain_text_through() {
    assert_eq!(escape_json_string("hello world"), "hello world");
}

#[test]
fn json_escape_escapes_named_json_control_characters() {
    assert_eq!(
        escape_json_string("line\ncarriage\rthing\tback\u{08}form\u{0c}"),
        "line\\ncarriage\\rthing\\tback\\bform\\f"
    );
}

#[test]
fn json_escape_escapes_all_other_control_characters_as_unicode() {
    let raw: String = (0u8..=0x1f)
        .filter(|b| !matches!(*b, b'\n' | b'\r' | b'\t' | 0x08 | 0x0c))
        .map(char::from)
        .collect();
    let escaped = escape_json_string(&raw);

    assert!(!escaped.chars().any(|ch| ch < '\u{20}'));
    assert!(escaped.contains("\\u0000"));
    assert!(escaped.contains("\\u001f"));
}

#[test]
fn json_escape_output_can_be_interpolated_into_json_string() {
    let raw = "bad\"\n<script>\u{00}\u{1f}\\";
    let body = format!(r#"{{"message":"{}"}}"#, escape_json_string(raw));
    let parsed: serde_json::Value =
        serde_json::from_str(&body).expect("escaped string should be valid JSON");

    assert_eq!(parsed["message"], raw);
}

#[test]
fn query_duplicate_check_detects_conflicting_duplicate_values() {
    assert!(has_conflicting_duplicate_query_key("a=1&a=2"));
}

#[test]
fn query_duplicate_check_allows_identical_duplicate_values() {
    assert!(!has_conflicting_duplicate_query_key("a=1&a=1"));
}

#[test]
fn query_duplicate_check_detects_percent_encoded_key_collision() {
    assert!(has_conflicting_duplicate_query_key("a%20b=1&a%20b=2"));
}

#[test]
fn query_duplicate_check_detects_plus_and_percent_space_key_collision() {
    assert!(has_conflicting_duplicate_query_key("a+b=1&a%20b=2"));
}

#[test]
fn query_duplicate_check_allows_percent_encoded_keys_with_same_value() {
    assert!(!has_conflicting_duplicate_query_key("a%20b=1&a%20b=1"));
}

#[test]
fn query_duplicate_check_normalizes_plus_in_values() {
    assert!(!has_conflicting_duplicate_query_key(
        "a=hello+world&a=hello%20world"
    ));
}

#[test]
fn query_duplicate_check_detects_encoded_plus_vs_raw_plus_value_conflict() {
    // `%2B` decodes to literal plus; raw `+` is form-urlencoded space.
    assert!(has_conflicting_duplicate_query_key("a=%2B&a=+"));
}

#[test]
fn query_duplicate_check_preserves_encoded_plus_as_literal_plus() {
    assert!(!has_conflicting_duplicate_query_key("a=%2B&a=%2B"));
}

#[test]
fn query_duplicate_check_does_not_collapse_encoded_plus_and_raw_plus_keys() {
    // `a%2Bb` decodes to `a+b`; raw `a+b` is the distinct key `a b`.
    assert!(!has_conflicting_duplicate_query_key("a%2Bb=1&a+b=2"));
}

#[test]
fn query_duplicate_check_normalizes_raw_plus_and_percent_space_key_aliases() {
    assert!(!has_conflicting_duplicate_query_key("a+b=1&a%20b=1"));
}

#[test]
fn query_duplicate_check_detects_keys_without_equals() {
    assert!(has_conflicting_duplicate_query_key("flag&flag=1"));
}

#[test]
fn query_duplicate_check_allows_distinct_keys_without_equals() {
    assert!(!has_conflicting_duplicate_query_key("flag&other"));
}

#[test]
fn query_duplicate_check_ignores_empty_pairs() {
    assert!(has_conflicting_duplicate_query_key("a=1&&a=2"));
    assert!(!has_conflicting_duplicate_query_key("a=1&&a=1"));
}

// --- CanonicalQuery: the shared representation every query-sensitive
// security consumer decides on (GHSA-j2j6-f9c7-hh85, GHSA-gr4p-3qw3-87r5).

fn ambiguities(raw: &str) -> Vec<QueryAmbiguity> {
    CanonicalQuery::parse(raw).ambiguities().to_vec()
}

#[test]
fn canonical_query_empty_input_is_empty_and_unambiguous() {
    let query = CanonicalQuery::parse("");
    assert!(query.is_empty());
    assert!(query.is_unambiguous());
    assert_eq!(query.get("anything"), None);
}

#[test]
fn canonical_query_preserves_wire_order() {
    let query = CanonicalQuery::parse("z=1&a=2&m=3");
    let names: Vec<&str> = query
        .params()
        .iter()
        .map(|param| param.name.as_str())
        .collect();
    assert_eq!(names, vec!["z", "a", "m"]);
}

#[test]
fn canonical_query_distinguishes_bare_from_explicit_empty_value() {
    let query = CanonicalQuery::parse("flag&empty=");
    assert!(query.is_unambiguous());
    assert_eq!(query.params()[0].name, "flag");
    assert_eq!(query.params()[0].value, "");
    assert!(query.params()[0].bare, "?flag has no '='");
    assert_eq!(query.params()[1].name, "empty");
    assert_eq!(query.params()[1].value, "");
    assert!(!query.params()[1].bare, "?empty= has an explicit '='");
}

#[test]
fn canonical_query_skips_empty_segments_like_the_frontend_counter() {
    // `count_query_params` treats `&&` as separators, not parameters; the
    // canonical view must agree or H1/H2/H3 admission and policy diverge.
    let query = CanonicalQuery::parse("&a=1&&b=2&");
    assert_eq!(query.len(), 2);
    assert!(query.is_unambiguous());
}

#[test]
fn canonical_query_flags_repeated_name() {
    assert_eq!(
        ambiguities("tenant=victim&tenant=admin"),
        vec![QueryAmbiguity::DuplicateName]
    );
}

#[test]
fn canonical_query_flags_identical_value_duplicate() {
    // Value equality does not remove the differential: an all-values backend
    // still receives a two-element list.
    assert_eq!(ambiguities("a=1&a=1"), vec![QueryAmbiguity::DuplicateName]);
}

#[test]
fn canonical_query_flags_percent_encoded_duplicate_alias() {
    // `a` and `%61` are the same decoded name, so this is one duplicate
    // rather than two distinct parameters.
    assert_eq!(
        ambiguities("a=1&%61=2"),
        vec![QueryAmbiguity::DuplicateName]
    );
    // `a%20b` and `a+b` decode to DIFFERENT names under RFC 3986 ("a b" vs
    // "a+b") but to the SAME name under form-urlencoded decoding. That is
    // precisely the differential, and the literal-plus classification is what
    // catches it — a duplicate-name check alone would not.
    assert_eq!(
        ambiguities("a%20b=1&a+b=2"),
        vec![QueryAmbiguity::LiteralPlus]
    );
}

#[test]
fn canonical_query_flags_bare_and_valued_pair_of_one_name() {
    assert_eq!(
        ambiguities("flag&flag=1"),
        vec![QueryAmbiguity::DuplicateName]
    );
}

#[test]
fn canonical_query_flags_literal_plus_in_name_or_value() {
    assert_eq!(
        ambiguities("action=delete+record"),
        vec![QueryAmbiguity::LiteralPlus]
    );
    assert_eq!(ambiguities("a+b=1"), vec![QueryAmbiguity::LiteralPlus]);
}

#[test]
fn canonical_query_accepts_percent_encoded_space_and_plus() {
    // `%20` -> space and `%2B` -> '+' are unambiguous; only the literal byte
    // is. Both readings of the advisory's inverse policy stay expressible.
    let query = CanonicalQuery::parse("action=delete%20record&sign=a%2Bb");
    assert!(query.is_unambiguous());
    assert_eq!(query.get("action"), Some("delete record"));
    assert_eq!(query.get("sign"), Some("a+b"));
}

#[test]
fn canonical_query_flags_malformed_percent_encoding() {
    for raw in ["a=%zz", "a=%", "a=%4", "%zz=1"] {
        assert!(
            ambiguities(raw).contains(&QueryAmbiguity::MalformedPercentEncoding),
            "{raw} must be flagged as malformed percent-encoding"
        );
    }
}

#[test]
fn canonical_query_flags_non_utf8_decodings() {
    // `%FF` is not valid UTF-8 once decoded.
    assert!(ambiguities("a=%FF").contains(&QueryAmbiguity::NonUtf8Value));
    assert!(ambiguities("%FF=1").contains(&QueryAmbiguity::NonUtf8Name));
}

#[test]
fn canonical_query_ambiguity_reasons_are_stable_tokens() {
    // These strings reach logs, plugin metadata, and OPA policy input.
    assert_eq!(QueryAmbiguity::LiteralPlus.reason(), "literal_plus");
    assert_eq!(
        QueryAmbiguity::MalformedPercentEncoding.reason(),
        "malformed_percent_encoding"
    );
    assert_eq!(QueryAmbiguity::NonUtf8Name.reason(), "non_utf8_name");
    assert_eq!(QueryAmbiguity::NonUtf8Value.reason(), "non_utf8_value");
    assert_eq!(QueryAmbiguity::DuplicateName.reason(), "duplicate_name");
}

#[test]
fn canonical_query_ambiguities_are_deduplicated_and_ordered() {
    // Many duplicate names collapse to one classification, and the order is
    // the order encountered so `first_ambiguity` is deterministic.
    let query = CanonicalQuery::parse("a=1&a=2&b=x+y&b=z");
    assert_eq!(
        query.ambiguities(),
        &[QueryAmbiguity::LiteralPlus, QueryAmbiguity::DuplicateName]
    );
    assert_eq!(query.first_ambiguity(), Some(QueryAmbiguity::LiteralPlus));
}

#[test]
fn canonical_query_get_returns_the_only_occurrence_when_unambiguous() {
    let query = CanonicalQuery::parse("a=1&b=two");
    assert!(query.is_unambiguous());
    assert_eq!(query.get("a"), Some("1"));
    assert_eq!(query.get("b"), Some("two"));
    assert_eq!(query.get("c"), None);
}

#[test]
fn cert_hash_sha256_hex_lower_matches_known_value() {
    assert_eq!(
        sha256_hex_lower(b"abc"),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
}

#[test]
fn cert_hash_sha256_base64url_no_pad_matches_known_value() {
    assert_eq!(
        sha256_base64url_no_pad(b"abc"),
        "ungWv48Bz-pBQUDeXa4iI7ADYaOWF3qctBD_YfIAFa0"
    );
}

#[test]
fn claim_resolver_resolves_hash_inside_path_segment() {
    let claims = json!({"cnf": {"x5t#S256": "thumbprint"}});
    assert_eq!(
        extract_claim_string(&claims, "cnf.x5t#S256").as_deref(),
        Some("thumbprint")
    );
}

#[test]
fn claim_resolver_rejects_blank_or_non_string_identity_values() {
    for claims in [
        json!({}),
        json!({"sub": null}),
        json!({"sub": 42}),
        json!({"sub": ""}),
        json!({"sub": "   \t"}),
    ] {
        assert_eq!(extract_claim_string(&claims, "sub"), None);
    }
}

#[test]
fn claim_resolver_exact_string_distinguishes_blank_from_missing() {
    let claims = json!({"display_name": "   \t"});

    assert_eq!(
        extract_claim_string_exact(&claims, "display_name").as_deref(),
        Some("   \t")
    );
    assert_eq!(extract_claim_string_exact(&claims, "missing"), None);
}

#[test]
fn claim_resolver_extracts_space_delimited_and_array_values() {
    let claims = json!({
        "scope": "read write",
        "realm_access": {"roles": ["admin", "editor"]}
    });
    assert_eq!(
        extract_claim_values(&claims, "scope"),
        vec!["read", "write"]
    );
    assert_eq!(
        extract_claim_values(&claims, "realm_access.roles"),
        vec!["admin", "editor"]
    );
}

#[test]
fn claim_resolver_rejects_empty_path_segments() {
    let err = parse_claim_path_value("scope_claim", &json!("realm..roles"), "test")
        .expect_err("path should be rejected");
    assert!(err.contains("scope_claim"));
}

#[test]
fn scope_role_check_accepts_required_scope_and_role() {
    let claims = json!({"scope": "read write", "roles": ["admin"]});
    let scopes = vec!["read".to_string()];
    let roles = vec!["admin".to_string()];
    let req = ScopeRoleRequirements {
        required_scopes: &scopes,
        required_roles: &roles,
        scope_claim: "scope",
        role_claim: "roles",
        plugin_name: "test",
    };

    assert!(check(&claims, &req).is_ok());
}

#[test]
fn scope_role_check_rejects_missing_scope() {
    let claims = json!({"scope": "read"});
    let scopes = vec!["write".to_string()];
    let req = ScopeRoleRequirements {
        required_scopes: &scopes,
        required_roles: &[],
        scope_claim: "scope",
        role_claim: "roles",
        plugin_name: "test",
    };

    let (status, body) = check(&claims, &req).expect_err("missing scope should reject");
    assert_eq!(status, 403);
    assert!(body.contains("Insufficient scope"));
}

#[test]
fn jwt_verifier_peeks_issuer_without_verifying_signature() {
    let token = encode(
        &Header::default(),
        &json!({"iss": "https://issuer", "exp": 9_999_999_999u64}),
        &EncodingKey::from_secret(b"secret"),
    )
    .expect("test token should encode");

    assert_eq!(
        peek_unverified_issuer(&token).as_deref(),
        Some("https://issuer")
    );
}

#[test]
fn jwt_verifier_malformed_token_has_no_issuer() {
    assert!(peek_unverified_issuer("not.a.jwt.extra").is_none());
}

fn jwt_verify_params() -> JwtVerifyParams<'static> {
    JwtVerifyParams {
        issuer: None,
        audiences: &[],
        require_exp: true,
        leeway_secs: 0,
        validate_nbf: false,
    }
}

fn two_key_store() -> JwksKeyStore {
    let key1 = super::jwks_auth_support::build_rsa_jwks_from_pem_with_kid(
        include_bytes!("../../../tests/fixtures/test_rsa_public.pem"),
        "key-1",
    );
    let key2 = super::jwks_auth_support::build_rsa_jwks_from_pem_with_kid(
        include_bytes!("../../../tests/fixtures/test_rsa_public_other.pem"),
        "key-2",
    );
    let jwks = json!({
        "keys": [key1["keys"][0].clone(), key2["keys"][0].clone()]
    });
    JwksKeyStore::from_inline_jwks(&jwks.to_string()).expect("inline JWKS")
}

#[tokio::test]
async fn jwt_verifier_rejects_missing_kid_without_trying_other_keys() {
    let token = super::jwks_auth_support::create_rs256_token_no_kid(
        &json!({"sub": "user"}),
        include_bytes!("../../../tests/fixtures/test_rsa_private.pem"),
    );
    assert!(
        verify_jwt_with_jwks(&token, &two_key_store(), &jwt_verify_params())
            .await
            .is_none()
    );
}

#[tokio::test]
async fn jwt_verifier_rejects_empty_kid_without_trying_other_keys() {
    let token = super::jwks_auth_support::create_rs256_token_with_kid(
        &json!({"sub": "user"}),
        include_bytes!("../../../tests/fixtures/test_rsa_private.pem"),
        "",
    );
    assert!(
        verify_jwt_with_jwks(&token, &two_key_store(), &jwt_verify_params())
            .await
            .is_none()
    );
}

#[tokio::test]
async fn jwt_verifier_rejects_unknown_kid_even_when_another_published_key_verifies() {
    let token = super::jwks_auth_support::create_rs256_token_with_kid(
        &json!({"sub": "user"}),
        include_bytes!("../../../tests/fixtures/test_rsa_private.pem"),
        "no-such-kid",
    );
    assert!(
        verify_jwt_with_jwks(&token, &two_key_store(), &jwt_verify_params())
            .await
            .is_none()
    );
}

#[tokio::test]
async fn jwt_verifier_rejects_known_kid_signed_by_a_different_published_key() {
    let token = super::jwks_auth_support::create_rs256_token_with_kid(
        &json!({"sub": "user"}),
        include_bytes!("../../../tests/fixtures/test_rsa_private_other.pem"),
        "key-1",
    );
    assert!(
        verify_jwt_with_jwks(&token, &two_key_store(), &jwt_verify_params())
            .await
            .is_none()
    );
}

/// A remote, refreshable two-key store. Unlike [`two_key_store`] this one can
/// admit an unknown-`kid` refetch trigger, so the verifier's rate-limited
/// signalling is observable (issue #4508).
async fn remote_two_key_store(server: &wiremock::MockServer) -> JwksKeyStore {
    let key1 = super::jwks_auth_support::build_rsa_jwks_from_pem_with_kid(
        include_bytes!("../../../tests/fixtures/test_rsa_public.pem"),
        "key-1",
    );
    let key2 = super::jwks_auth_support::build_rsa_jwks_from_pem_with_kid(
        include_bytes!("../../../tests/fixtures/test_rsa_public_other.pem"),
        "key-2",
    );
    let jwks = json!({"keys": [key1["keys"][0].clone(), key2["keys"][0].clone()]});
    wiremock::Mock::given(wiremock::matchers::method("GET"))
        .and(wiremock::matchers::path("/jwks"))
        .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(jwks))
        .mount(server)
        .await;
    let store = JwksKeyStore::new(
        format!("{}/jwks", server.uri()),
        ferrum_edge::plugins::PluginHttpClient::default(),
    );
    store.fetch_keys().await.expect("initial JWKS fetch");
    store
}

/// A non-empty unknown `kid` is the observable shape of an IdP key rotation,
/// so it asks the store for one out-of-band refresh — and the request that
/// observed the miss still fails closed.
#[tokio::test]
async fn jwt_verifier_unknown_kid_requests_one_rate_limited_refetch() {
    let server = wiremock::MockServer::start().await;
    let store = remote_two_key_store(&server).await;
    let token = super::jwks_auth_support::create_rs256_token_with_kid(
        &json!({"sub": "user"}),
        include_bytes!("../../../tests/fixtures/test_rsa_private.pem"),
        "rotated-kid",
    );

    assert!(
        verify_jwt_with_jwks(&token, &store, &jwt_verify_params())
            .await
            .is_none(),
        "the triggering request must still fail closed"
    );
    assert_eq!(store.kid_miss_refresh_requests(), 1);

    // A second unknown identifier inside the same cooldown window adds no
    // further trigger: random-`kid` spraying cannot become a fetch storm.
    for identifier in ["another-kid", "yet-another-kid"] {
        let sprayed = super::jwks_auth_support::create_rs256_token_with_kid(
            &json!({"sub": "user"}),
            include_bytes!("../../../tests/fixtures/test_rsa_private.pem"),
            identifier,
        );
        assert!(
            verify_jwt_with_jwks(&sprayed, &store, &jwt_verify_params())
                .await
                .is_none()
        );
    }
    assert_eq!(store.kid_miss_refresh_requests(), 1);
}

/// A missing or empty `kid` names no rotation, so it must trigger nothing.
#[tokio::test]
async fn jwt_verifier_missing_or_empty_kid_requests_no_refetch() {
    let server = wiremock::MockServer::start().await;
    let store = remote_two_key_store(&server).await;

    let no_kid = super::jwks_auth_support::create_rs256_token_no_kid(
        &json!({"sub": "user"}),
        include_bytes!("../../../tests/fixtures/test_rsa_private.pem"),
    );
    let empty_kid = super::jwks_auth_support::create_rs256_token_with_kid(
        &json!({"sub": "user"}),
        include_bytes!("../../../tests/fixtures/test_rsa_private.pem"),
        "",
    );
    for token in [no_kid, empty_kid] {
        assert!(
            verify_jwt_with_jwks(&token, &store, &jwt_verify_params())
                .await
                .is_none()
        );
    }
    assert_eq!(store.kid_miss_refresh_requests(), 0);
}

#[tokio::test]
async fn jwt_verifier_accepts_matching_kid_and_key() {
    let token = super::jwks_auth_support::create_rs256_token_with_kid(
        &json!({"sub": "user"}),
        include_bytes!("../../../tests/fixtures/test_rsa_private.pem"),
        "key-1",
    );
    let claims = verify_jwt_with_jwks(&token, &two_key_store(), &jwt_verify_params())
        .await
        .expect("matching kid must verify");
    assert_eq!(claims["sub"], "user");
}

fn ctx_with_header(name: &str, value: &str) -> RequestContext {
    let mut ctx = RequestContext::new("127.0.0.1".into(), "GET".into(), "/".into());
    ctx.headers.insert(name.to_string(), value.to_string());
    ctx
}

#[test]
fn token_extract_extracts_bearer_token_from_authorization() {
    let ctx = ctx_with_header("authorization", "Bearer abc");
    assert!(matches!(
        extract_authorization_bearer(&ctx),
        ExtractedCredential::BearerToken(token) if token == "abc"
    ));
}

#[test]
fn token_extract_treats_foreign_authorization_scheme_as_missing() {
    let ctx = ctx_with_header("authorization", "Basic dXNlcjpwYXNz");
    assert!(matches!(
        extract_authorization_bearer(&ctx),
        ExtractedCredential::Missing
    ));
}

#[test]
fn token_extract_configured_header_prefix_mismatch_is_missing() {
    let ctx = ctx_with_header("x-token", "Token abc");
    let location = TokenLocation::Header(TokenHeaderLocation {
        name: "x-token".to_string(),
        prefix: Some("Bearer ".to_string()),
    });
    assert!(matches!(
        extract_from_location(&location, &ctx),
        TokenLocationExtract::Missing
    ));
}

#[test]
fn token_extract_prefixless_authorization_location_classifies_bearer_scheme() {
    let location = TokenLocation::Header(TokenHeaderLocation {
        name: "authorization".to_string(),
        prefix: None,
    });

    let bearer_ctx = ctx_with_header("authorization", "Bearer abc");
    assert!(matches!(
        extract_from_location(&location, &bearer_ctx),
        TokenLocationExtract::Credential(ExtractedCredential::BearerToken(token))
            if token == "abc"
    ));

    let basic_ctx = ctx_with_header("authorization", "Basic dXNlcjpwYXNz");
    assert!(matches!(
        extract_from_location(&location, &basic_ctx),
        TokenLocationExtract::Missing
    ));
}

#[test]
fn token_extract_non_materialized_authorization_is_invalid_not_missing() {
    let ctx = super::plugin_utils::context_with_materialized_raw_header(
        "Authorization",
        "Bearer \u{3000}not-a-token",
    );
    assert!(matches!(
        extract_authorization_bearer(&ctx),
        ExtractedCredential::InvalidFormat(body)
            if body == r#"{"error":"Invalid Authorization header"}"#
    ));
}

#[test]
fn token_extract_non_materialized_custom_header_is_invalid_not_missing() {
    let ctx =
        super::plugin_utils::context_with_materialized_raw_header("X-Token", "value\u{3000}token");
    let location = TokenLocation::Header(TokenHeaderLocation {
        name: "x-token".to_string(),
        prefix: None,
    });
    assert!(matches!(
        extract_from_location(&location, &ctx),
        TokenLocationExtract::Credential(ExtractedCredential::InvalidFormat(body))
            if body == r#"{"error":"Invalid token"}"#
    ));
}

// --- H1/H2/H3 parity.
//
// H1/H2 call `materialize_query_params` (percent-decoded) while H3 calls
// `materialize_query_params_raw` (percent-escaped) unless a plugin opts in.
// The canonical policy view must be identical either way, because it decodes
// the forwarded query directly instead of reading that protocol-dependent map.

fn ctx_for(raw_query: &str) -> RequestContext {
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/api".to_string(),
    );
    ctx.set_raw_query_string(raw_query.to_string());
    ctx
}

#[test]
fn canonical_policy_view_is_identical_across_h1_h2_and_h3_materialization() {
    for raw_query in [
        "resource=%2Fadmin",
        "action=delete%20record",
        "sign=a%2Bb",
        "tenant=victim&tenant=admin",
        "action=delete+record",
        "flag&empty=",
        "&a=1&&b=2&",
        "name=%FF",
        "name=%zz",
    ] {
        let mut h1 = ctx_for(raw_query);
        h1.materialize_query_params();
        let mut h3 = ctx_for(raw_query);
        h3.materialize_query_params_raw();

        assert_eq!(
            canonical_query_for_policy(&h1),
            canonical_query_for_policy(&h3),
            "query {raw_query} must yield one policy view on every frontend protocol"
        );
    }
}

#[test]
fn canonical_policy_view_ignores_a_divergent_materialized_map() {
    // `%2Fadmin` is the advisory's cross-protocol case: H1/H2 put `/admin` in
    // the shared map and H3 puts `%2Fadmin`. Neither reaches policy.
    let mut h1 = ctx_for("resource=%2Fadmin");
    h1.materialize_query_params();
    assert_eq!(
        h1.query_params.get("resource").map(String::as_str),
        Some("/admin")
    );

    let mut h3 = ctx_for("resource=%2Fadmin");
    h3.materialize_query_params_raw();
    assert_eq!(
        h3.query_params.get("resource").map(String::as_str),
        Some("%2Fadmin")
    );

    for ctx in [&h1, &h3] {
        let query = canonical_query_for_policy(ctx);
        assert!(query.is_unambiguous());
        assert_eq!(query.get("resource"), Some("/admin"));
    }
}

#[test]
fn canonical_policy_view_follows_the_transformer_published_outbound_query() {
    // The forwarded bytes, not the wire bytes, are what policy must decide on.
    let mut ctx = ctx_for("page=1&drop=me");
    ctx.publish_transformed_query(
        "page=2".to_string(),
        [("page".to_string(), "2".to_string())]
            .into_iter()
            .collect(),
    );

    let query = canonical_query_for_policy(&ctx);
    assert_eq!(query.len(), 1);
    assert_eq!(query.get("page"), Some("2"));
    assert_eq!(query.get("drop"), None);
}

#[test]
fn canonical_policy_view_excludes_authentication_stripped_credentials() {
    let mut ctx = ctx_for("api_key=secret&page=1");
    ctx.metadata.insert(
        "auth.strip_query_param.api_key".to_string(),
        "true".to_string(),
    );

    let query = canonical_query_for_policy(&ctx);
    assert_eq!(query.len(), 1);
    assert_eq!(query.get("page"), Some("1"));
    assert_eq!(
        query.get("api_key"),
        None,
        "a stripped credential never reaches the backend, so policy must not see it"
    );
}

#[test]
fn canonical_policy_view_ignores_a_duplicate_only_the_strip_removes() {
    // Stripping runs before canonicalization, so a duplicate that exists only
    // among stripped pairs must not fail an otherwise clean request closed.
    let mut ctx = ctx_for("api_key=one&api%5Fkey=two&page=1");
    ctx.metadata.insert(
        "auth.strip_query_param.api_key".to_string(),
        "true".to_string(),
    );

    let query = canonical_query_for_policy(&ctx);
    assert!(query.is_unambiguous());
    assert_eq!(query.get("page"), Some("1"));
}

// ---------------------------------------------------------------------------
// utils::sse — Anthropic Messages event-stream reassembly
// ---------------------------------------------------------------------------

/// Reassemble a buffered SSE body the way the AI inspectors do, returning the
/// reassembled fragments and whether every modelled provider protocol in it was
/// fully covered.
fn reassemble_anthropic(body: &[u8]) -> (Vec<SseText>, bool) {
    let parsed = parse_sse_data_frames_checked(body);
    let mut reassembler = SseReassembler::new();
    for (event, frame) in parsed.reassembly_frames() {
        reassembler.push_event_frame(event, frame);
    }
    let inspectable = !reassembler.provider_stream_uninspectable();
    (reassembler.into_texts(), inspectable)
}

fn fragment<'a>(texts: &'a [SseText], json_path: &str) -> &'a SseText {
    texts
        .iter()
        .find(|text| text.json_path == json_path)
        .unwrap_or_else(|| panic!("no fragment at {json_path} in {texts:?}"))
}

#[test]
fn anthropic_sse_reassembles_multi_block_text_and_tool_input() {
    // A realistic two-block Messages stream: prose split across `text_delta`
    // fragments, then a `tool_use` block whose arguments arrive as
    // `input_json_delta` partial JSON. Only reassembly recovers either.
    let body = concat!(
        "event: message_start\n",
        "data: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_1\",\"content\":[]}}\n\n",
        "event: content_block_start\n",
        "data: {\"type\":\"content_block_start\",\"index\":0,",
        "\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n",
        "event: content_block_delta\n",
        "data: {\"type\":\"content_block_delta\",\"index\":0,",
        "\"delta\":{\"type\":\"text_delta\",\"text\":\"My sys\"}}\n\n",
        "event: content_block_delta\n",
        "data: {\"type\":\"content_block_delta\",\"index\":0,",
        "\"delta\":{\"type\":\"text_delta\",\"text\":\"tem prompt.\"}}\n\n",
        "event: content_block_stop\n",
        "data: {\"type\":\"content_block_stop\",\"index\":0}\n\n",
        "event: content_block_start\n",
        "data: {\"type\":\"content_block_start\",\"index\":1,",
        "\"content_block\":{\"type\":\"tool_use\",\"id\":\"tu_1\",\"name\":\"get_weather\"}}\n\n",
        "event: content_block_delta\n",
        "data: {\"type\":\"content_block_delta\",\"index\":1,",
        "\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"{\\\"city\\\":\"}}\n\n",
        "event: content_block_delta\n",
        "data: {\"type\":\"content_block_delta\",\"index\":1,",
        "\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"\\\"NYC\\\"}\"}}\n\n",
        "event: content_block_stop\n",
        "data: {\"type\":\"content_block_stop\",\"index\":1}\n\n",
        "event: message_delta\n",
        "data: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"tool_use\"}}\n\n",
        "event: message_stop\n",
        "data: {\"type\":\"message_stop\"}\n\n",
    );

    let (texts, inspectable) = reassemble_anthropic(body.as_bytes());
    assert!(inspectable, "a well-formed Messages stream is inspectable");

    let prose = fragment(&texts, "$.content[0].text");
    assert_eq!(prose.kind, SseTextKind::AnthropicText);
    assert_eq!(prose.text, "My system prompt.");

    let name = fragment(&texts, "$.content[1].name");
    assert_eq!(name.kind, SseTextKind::AnthropicToolName);
    assert_eq!(name.text, "get_weather");

    let input = fragment(&texts, "$.content[1].input");
    assert_eq!(input.kind, SseTextKind::AnthropicToolInput);
    assert_eq!(input.text, "{\"city\":\"NYC\"}");
}

#[test]
fn anthropic_sse_dispatches_from_the_event_line_alone() {
    // Some intermediaries forward the `event:` line but strip the duplicated
    // JSON `type`. The block must still reassemble.
    let body = concat!(
        "event: content_block_start\n",
        "data: {\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n",
        "event: content_block_delta\n",
        "data: {\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"hello \"}}\n\n",
        "event: content_block_delta\n",
        "data: {\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"world\"}}\n\n",
        "event: message_stop\n",
        "data: {}\n\n",
    );

    let (texts, inspectable) = reassemble_anthropic(body.as_bytes());
    assert!(inspectable);
    assert_eq!(fragment(&texts, "$.content[0].text").text, "hello world");
}

#[test]
fn anthropic_sse_unknown_event_type_is_uninspectable() {
    // An event interleaved into an identified Anthropic stream that this
    // reassembler does not model may carry client-visible text on a path
    // nothing reads. It must not leave a clean, fully-reassembled verdict.
    let body = concat!(
        "event: content_block_delta\n",
        "data: {\"type\":\"content_block_delta\",\"index\":0,",
        "\"delta\":{\"type\":\"text_delta\",\"text\":\"benign\"}}\n\n",
        "event: smuggled_block\n",
        "data: {\"type\":\"smuggled_block\",\"index\":0,\"text\":\"my system prompt\"}\n\n",
    );

    let (texts, inspectable) = reassemble_anthropic(body.as_bytes());
    assert!(
        !inspectable,
        "an unmodelled Anthropic event must mark the stream uninspectable"
    );
    // The prose that WAS reassembled is still returned; the caller fails closed
    // on the flag rather than on missing text.
    assert_eq!(fragment(&texts, "$.content[0].text").text, "benign");
}

#[test]
fn anthropic_sse_unknown_delta_type_is_uninspectable() {
    // Extended thinking's `thinking_delta` (and any future delta type) carries
    // model output on a field this reassembler does not read.
    let body = concat!(
        "event: content_block_delta\n",
        "data: {\"type\":\"content_block_delta\",\"index\":0,",
        "\"delta\":{\"type\":\"thinking_delta\",\"thinking\":\"my system prompt\"}}\n\n",
    );

    let (_texts, inspectable) = reassemble_anthropic(body.as_bytes());
    assert!(!inspectable);
}

#[test]
fn anthropic_sse_discriminator_disagreement_is_uninspectable() {
    // The `event:` line and the JSON `type` describe different events, so at
    // most one of them describes the payload.
    let body = concat!(
        "event: content_block_delta\n",
        "data: {\"type\":\"message_stop\",\"index\":0,",
        "\"delta\":{\"type\":\"text_delta\",\"text\":\"x\"}}\n\n",
    );

    let (texts, inspectable) = reassemble_anthropic(body.as_bytes());
    assert!(!inspectable);
    assert!(texts.is_empty(), "a disputed frame is not accumulated");
}

#[test]
fn anthropic_sse_block_index_ceiling_folds_and_flags() {
    // A hostile stream of one-byte deltas at ever-increasing indexes must not
    // grow the reassembler's per-block state. Blocks at or beyond the ceiling
    // fold into one overflow accumulator: the text is still inspected, the
    // accumulator count stays bounded, and the stream fails closed.
    let overflow = 500;
    let mut body = String::new();
    for index in 0..(MAX_ANTHROPIC_CONTENT_BLOCKS + overflow) {
        body.push_str("event: content_block_delta\n");
        body.push_str(&format!(
            "data: {{\"type\":\"content_block_delta\",\"index\":{index},\
\"delta\":{{\"type\":\"text_delta\",\"text\":\"x\"}}}}\n\n"
        ));
    }

    let (texts, inspectable) = reassemble_anthropic(body.as_bytes());
    assert!(!inspectable, "an out-of-range block index fails closed");
    assert_eq!(
        texts.len(),
        MAX_ANTHROPIC_CONTENT_BLOCKS + 1,
        "indexes past the ceiling share one overflow accumulator"
    );
    // Every delta byte is still present for inspection, none dropped.
    let total: usize = texts.iter().map(|text| text.text.len()).sum();
    assert_eq!(total, MAX_ANTHROPIC_CONTENT_BLOCKS + overflow);
}

#[test]
fn anthropic_sse_message_start_envelope_is_folded_in() {
    // Issue #4901 review: `message_start` carries the message envelope, and
    // Anthropic's SDK seeds its response snapshot from it. A populated
    // `content` array there is client-visible, so it must reassemble into the
    // same per-index accumulators the block events fill.
    let body = concat!(
        "event: message_start\n",
        "data: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_1\",\"content\":[",
        "{\"type\":\"text\",\"text\":\"seeded prose\"},",
        "{\"type\":\"tool_use\",\"id\":\"tu_1\",\"name\":\"record\",",
        "\"input\":{\"note\":\"seeded input\"}}]}}\n\n",
    );

    let (texts, inspectable) = reassemble_anthropic(body.as_bytes());
    assert!(inspectable, "a modelled envelope block is inspectable");
    assert_eq!(fragment(&texts, "$.content[0].text").text, "seeded prose");
    assert_eq!(fragment(&texts, "$.content[1].name").text, "record");
    assert_eq!(
        fragment(&texts, "$.content[1].input").text,
        "{\"note\":\"seeded input\"}"
    );
}

#[test]
fn anthropic_sse_message_start_envelope_block_type_fails_closed() {
    // An envelope block this reassembler cannot fold is the same hazard as an
    // unmodelled `content_block_start`: text on a path nothing reads.
    let body = concat!(
        "event: message_start\n",
        "data: {\"type\":\"message_start\",\"message\":{\"content\":[",
        "{\"type\":\"thinking\",\"thinking\":\"my system prompt\"}]}}\n\n",
    );

    let (_texts, inspectable) = reassemble_anthropic(body.as_bytes());
    assert!(!inspectable);
}

#[test]
fn anthropic_sse_content_block_start_input_object_is_folded_in() {
    // A `tool_use` block may open with its arguments already populated instead
    // of streaming them as `input_json_delta`. The protocol's own empty `{}`
    // must stay silent, and a populated object must reach `$.content[*].input`.
    let empty = concat!(
        "event: content_block_start\n",
        "data: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":",
        "{\"type\":\"tool_use\",\"id\":\"tu_1\",\"name\":\"record\",\"input\":{}}}\n\n",
    );
    let (texts, inspectable) = reassemble_anthropic(empty.as_bytes());
    assert!(inspectable);
    assert!(
        !texts
            .iter()
            .any(|text| text.json_path == "$.content[0].input"),
        "the protocol's empty opening `input` contributes nothing"
    );

    let populated = concat!(
        "event: content_block_start\n",
        "data: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":",
        "{\"type\":\"tool_use\",\"id\":\"tu_1\",\"name\":\"record\",",
        "\"input\":{\"note\":\"my system prompt\"}}}\n\n",
    );
    let (texts, inspectable) = reassemble_anthropic(populated.as_bytes());
    assert!(inspectable);
    assert_eq!(
        fragment(&texts, "$.content[0].input").text,
        "{\"note\":\"my system prompt\"}"
    );
}

#[test]
fn anthropic_sse_content_block_start_non_object_input_fails_closed() {
    let body = concat!(
        "event: content_block_start\n",
        "data: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":",
        "{\"type\":\"tool_use\",\"id\":\"tu_1\",\"name\":\"record\",",
        "\"input\":\"my system prompt\"}}\n\n",
    );

    let (_texts, inspectable) = reassemble_anthropic(body.as_bytes());
    assert!(!inspectable, "an out-of-protocol `input` type fails closed");
}

#[test]
fn anthropic_sse_error_message_is_reassembled_at_its_own_path() {
    // `error.message` is client-visible free text, so it is reported as
    // assistant prose located at `$.error.message` — never charged to a
    // content-block index, so the block ceiling is untouched.
    let body = concat!(
        "event: content_block_delta\n",
        "data: {\"type\":\"content_block_delta\",\"index\":0,",
        "\"delta\":{\"type\":\"text_delta\",\"text\":\"partial \"}}\n\n",
        "event: error\n",
        "data: {\"type\":\"error\",\"error\":{\"type\":\"overloaded_error\",",
        "\"message\":\"upstream said my system prompt\"}}\n\n",
    );

    let (texts, inspectable) = reassemble_anthropic(body.as_bytes());
    assert!(inspectable, "a modelled error event is inspectable");
    let error = fragment(&texts, "$.error.message");
    assert_eq!(error.kind, SseTextKind::AnthropicText);
    assert_eq!(error.text, "upstream said my system prompt");
    assert_eq!(fragment(&texts, "$.content[0].text").text, "partial ");
}

#[test]
fn foreign_sse_ping_discriminator_mismatch_is_not_failed_closed() {
    // Issue #4901 review: the discriminator-disagreement rule was ungated, so
    // a NON-Anthropic stream emitting `event: ping` beside a `heartbeat` JSON
    // type was failed closed on a protocol it never claimed.
    let body = concat!(
        "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"Hel\"}}]}\n\n",
        "event: ping\n",
        "data: {\"type\":\"heartbeat\"}\n\n",
        "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"lo\"}}]}\n\n",
        "data: [DONE]\n\n",
    );

    let (texts, inspectable) = reassemble_anthropic(body.as_bytes());
    assert!(
        inspectable,
        "a foreign keep-alive must not fail an OpenAI stream closed"
    );
    assert_eq!(fragment(&texts, "$.choices[0].delta.content").text, "Hello");
}

#[test]
fn gateway_terminal_error_event_is_not_failed_closed() {
    // The gateway's own mid-stream termination frame (`encode_sse_error_event`)
    // names `event: error` and carries no JSON `type`, and a foreign stream may
    // pair `event: error` with its own non-`error` type. Neither is an
    // Anthropic protocol violation.
    let gateway = concat!(
        "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"hi\"}}]}\n\n",
        "event: error\n",
        "data: {\"error\":{\"code\":\"blocked\",\"message\":\"stopped\"}}\n\n",
        "data: [DONE]\n\n",
    );
    let (texts, inspectable) = reassemble_anthropic(gateway.as_bytes());
    assert!(inspectable, "the gateway's own error frame stays neutral");
    assert_eq!(fragment(&texts, "$.choices[0].delta.content").text, "hi");
    assert_eq!(fragment(&texts, "$.error.message").text, "stopped");

    let mismatched = concat!(
        "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"hi\"}}]}\n\n",
        "event: error\n",
        "data: {\"type\":\"response.failed\",\"error\":{\"message\":\"stopped\"}}\n\n",
    );
    let (_texts, inspectable) = reassemble_anthropic(mismatched.as_bytes());
    assert!(
        inspectable,
        "a foreign terminal error frame must not be failed closed"
    );
}

// ---------------------------------------------------------------------------
// utils::sse — Google Gemini / Vertex streamGenerateContent reassembly
// ---------------------------------------------------------------------------

/// Reassemble a buffered Gemini SSE body, returning the reassembled fragments
/// and whether the stream was fully covered. Same shared entry point the AI
/// inspectors use — Gemini frames carry no `event:` line at all.
fn reassemble_gemini(body: &[u8]) -> (Vec<SseText>, bool) {
    reassemble_anthropic(body)
}

#[test]
fn gemini_sse_reassembles_multi_candidate_text_and_function_calls() {
    // A two-candidate `streamGenerateContent?alt=sse` response: each frame is a
    // complete `GenerateContentResponse` carrying one incremental fragment per
    // candidate, and the final frame adds a `functionCall` part plus the usage
    // envelope. Only reassembly recovers either candidate's prose.
    let body = concat!(
        "data: {\"candidates\":[",
        "{\"index\":0,\"content\":{\"role\":\"model\",\"parts\":[{\"text\":\"My sys\"}]}},",
        "{\"index\":1,\"content\":{\"role\":\"model\",\"parts\":[{\"text\":\"Second \"}]}}],",
        "\"modelVersion\":\"gemini-2.0\"}\n\n",
        "data: {\"candidates\":[",
        "{\"index\":0,\"content\":{\"role\":\"model\",\"parts\":[{\"text\":\"tem prompt.\"}]}},",
        "{\"index\":1,\"content\":{\"role\":\"model\",\"parts\":[{\"text\":\"answer.\"}]}}]}\n\n",
        "data: {\"candidates\":[{\"index\":0,\"content\":{\"role\":\"model\",\"parts\":[",
        "{\"functionCall\":{\"name\":\"get_weather\",\"args\":{\"city\":\"NYC\"}}}]},",
        "\"finishReason\":\"STOP\",\"safetyRatings\":[]}],",
        "\"usageMetadata\":{\"totalTokenCount\":12}}\n\n",
    );

    let (texts, inspectable) = reassemble_gemini(body.as_bytes());
    assert!(inspectable, "a well-formed Gemini stream is inspectable");

    let first = fragment(&texts, "$.candidates[0].content.parts[*].text");
    assert_eq!(first.kind, SseTextKind::GeminiText);
    assert_eq!(first.text, "My system prompt.");

    let second = fragment(&texts, "$.candidates[1].content.parts[*].text");
    assert_eq!(second.kind, SseTextKind::GeminiText);
    assert_eq!(second.text, "Second answer.");

    let name = fragment(&texts, "$.candidates[0].content.parts[*].functionCall.name");
    assert_eq!(name.kind, SseTextKind::GeminiFunctionCallName);
    assert_eq!(name.text, "get_weather");

    let args = fragment(&texts, "$.candidates[0].content.parts[*].functionCall.args");
    assert_eq!(args.kind, SseTextKind::GeminiFunctionCallArgs);
    assert_eq!(args.text, "{\"city\":\"NYC\"}");
}

#[test]
fn gemini_sse_joins_consecutive_text_parts_of_one_candidate() {
    // A single frame may carry several text parts for one candidate; a client
    // renders them as one string, so inspection must see them joined.
    let body = concat!(
        "data: {\"candidates\":[{\"content\":{\"parts\":[",
        "{\"text\":\"my sys\"},{\"text\":\"tem prompt\"}]}}]}\n\n",
    );

    let (texts, inspectable) = reassemble_gemini(body.as_bytes());
    assert!(inspectable);
    assert_eq!(
        fragment(&texts, "$.candidates[0].content.parts[*].text").text,
        "my system prompt"
    );
}

#[test]
fn gemini_sse_content_free_candidate_is_not_a_failure() {
    // A blocked or finished candidate legitimately carries no `content` (or a
    // `content` with no `parts`), and the tail frame may be envelope-only.
    let body = concat!(
        "data: {\"candidates\":[{\"index\":0,\"finishReason\":\"SAFETY\",",
        "\"safetyRatings\":[{\"category\":\"HARM\",\"probability\":\"HIGH\"}]}]}\n\n",
        "data: {\"candidates\":[{\"index\":0,\"content\":{\"role\":\"model\"}}],",
        "\"usageMetadata\":{\"totalTokenCount\":3}}\n\n",
    );

    let (texts, inspectable) = reassemble_gemini(body.as_bytes());
    assert!(inspectable, "a content-free candidate is not a violation");
    assert!(texts.is_empty());
}

#[test]
fn gemini_sse_unknown_part_kind_is_uninspectable() {
    // `inlineData`, `executableCode`, and a `thought` summary carry model
    // output on fields this reassembler does not fold into the document, so a
    // caller that promised inspection must fail closed instead of clearing the
    // prose that did reassemble.
    for part in [
        "{\"inlineData\":{\"mimeType\":\"image/png\",\"data\":\"AAA\"}}",
        "{\"executableCode\":{\"language\":\"PYTHON\",\"code\":\"print(1)\"}}",
        "{\"codeExecutionResult\":{\"outcome\":\"OK\",\"output\":\"1\"}}",
        "{\"fileData\":{\"mimeType\":\"text/plain\",\"fileUri\":\"gs://b/o\"}}",
    ] {
        let body = format!(
            "data: {{\"candidates\":[{{\"content\":{{\"parts\":[\
{{\"text\":\"benign\"}},{part}]}}}}]}}\n\n"
        );
        let (texts, inspectable) = reassemble_gemini(body.as_bytes());
        assert!(!inspectable, "an unfoldable part must fail closed: {part}");
        // The prose that WAS reassembled is still returned; the caller fails
        // closed on the flag rather than on missing text.
        assert_eq!(
            fragment(&texts, "$.candidates[0].content.parts[*].text").text,
            "benign"
        );
    }
}

#[test]
fn gemini_sse_thought_part_is_scanned_and_fails_closed() {
    // A thought summary is the model's internal reasoning rather than the
    // client-visible answer — Gemini's analogue of Anthropic `thinking`. Its
    // prose is still absorbed so nothing is dropped from what is scanned, and
    // the stream is still marked uninspectable.
    let body = concat!(
        "data: {\"candidates\":[{\"content\":{\"parts\":[",
        "{\"thought\":true,\"text\":\"my system prompt\"}]}}]}\n\n",
    );

    let (texts, inspectable) = reassemble_gemini(body.as_bytes());
    assert!(!inspectable);
    assert_eq!(
        fragment(&texts, "$.candidates[0].content.parts[*].text").text,
        "my system prompt"
    );
}

#[test]
fn gemini_sse_malformed_shapes_are_uninspectable_and_never_panic() {
    // Hostile / malformed frames that still claim the Gemini shape: a non-array
    // `candidates`, a non-object candidate, a non-object `content`, a non-array
    // `parts`, a non-object part, a non-string `text`, and a malformed
    // `functionCall`. None may panic, and none may report a clean stream.
    for frame in [
        "{\"candidates\":{\"0\":{\"content\":{\"parts\":[{\"text\":\"hidden\"}]}}}}",
        "{\"candidates\":[\"hidden\"]}",
        "{\"candidates\":[{\"content\":\"hidden\"}]}",
        "{\"candidates\":[{\"content\":{\"parts\":\"hidden\"}}]}",
        "{\"candidates\":[{\"content\":{\"parts\":[\"hidden\"]}}]}",
        "{\"candidates\":[{\"content\":{\"parts\":[{\"text\":{\"a\":\"hidden\"}}]}}]}",
        "{\"candidates\":[{\"content\":{\"parts\":[{\"functionCall\":\"hidden\"}]}}]}",
        "{\"candidates\":[{\"content\":{\"parts\":[{\"functionCall\":{\"name\":7}}]}}]}",
        "{\"candidates\":[{\"content\":{\"parts\":[{\"functionCall\":\
{\"name\":\"f\",\"args\":\"hidden\"}}]}}]}",
        "{\"candidates\":[{\"content\":{\"parts\":[{}]}}]}",
    ] {
        let body = format!("data: {frame}\n\n");
        let (_texts, inspectable) = reassemble_gemini(body.as_bytes());
        assert!(
            !inspectable,
            "malformed Gemini frame must fail closed: {frame}"
        );
    }
}

#[test]
fn gemini_sse_candidate_ceiling_folds_and_flags() {
    // A hostile stream of one-byte parts at ever-increasing candidate indexes
    // must not grow the reassembler's per-candidate state. Candidates at or
    // beyond the ceiling fold into one overflow accumulator: the text is still
    // inspected, the accumulator count stays bounded, and the stream fails
    // closed.
    let overflow = 500;
    let mut body = String::new();
    for index in 0..(MAX_GEMINI_CANDIDATES + overflow) {
        body.push_str(&format!(
            "data: {{\"candidates\":[{{\"index\":{index},\"content\":\
{{\"parts\":[{{\"text\":\"x\"}}]}}}}]}}\n\n"
        ));
    }

    let (texts, inspectable) = reassemble_gemini(body.as_bytes());
    assert!(!inspectable, "an out-of-range candidate index fails closed");
    assert_eq!(
        texts.len(),
        MAX_GEMINI_CANDIDATES + 1,
        "indexes past the ceiling share one overflow accumulator"
    );
    let total: usize = texts.iter().map(|text| text.text.len()).sum();
    assert_eq!(total, MAX_GEMINI_CANDIDATES + overflow);
}

#[test]
fn gemini_sse_frame_carrying_choices_or_type_stays_on_its_own_path() {
    // Detection is by shape, so a frame that also carries `choices` or an event
    // `type` belongs to the OpenAI / Anthropic paths and must not be read a
    // second time as a Gemini candidate.
    let body = concat!(
        "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"Hello\"}}],",
        "\"candidates\":[{\"content\":{\"parts\":[{\"text\":\"dup\"}]}}]}\n\n",
    );

    let (texts, inspectable) = reassemble_gemini(body.as_bytes());
    assert!(inspectable);
    assert_eq!(fragment(&texts, "$.choices[0].delta.content").text, "Hello");
    assert!(
        !texts
            .iter()
            .any(|text| text.kind == SseTextKind::GeminiText),
        "an OpenAI frame is not also reassembled as a Gemini candidate"
    );
}

#[test]
fn openai_and_anthropic_sse_reassembly_are_unaffected_by_gemini_support() {
    // Behaviour-neutrality for the two protocols that already reassembled:
    // neither carries a `candidates` member, so neither reaches the Gemini
    // path, and neither is failed closed by it.
    let openai = concat!(
        "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"Hel\"}}]}\n\n",
        "event: response.output_text.delta\n",
        "data: {\"type\":\"response.output_text.delta\",\"output_index\":0,",
        "\"content_index\":0,\"delta\":\"lo\"}\n\n",
        "data: [DONE]\n\n",
    );
    let (texts, inspectable) = reassemble_gemini(openai.as_bytes());
    assert!(inspectable, "an OpenAI stream is not a Gemini stream");
    assert_eq!(fragment(&texts, "$.choices[0].delta.content").text, "Hel");
    assert_eq!(fragment(&texts, "$.output[0].content[0].text").text, "lo");

    let anthropic = concat!(
        "event: content_block_delta\n",
        "data: {\"type\":\"content_block_delta\",\"index\":0,",
        "\"delta\":{\"type\":\"text_delta\",\"text\":\"hello \"}}\n\n",
        "event: content_block_delta\n",
        "data: {\"type\":\"content_block_delta\",\"index\":0,",
        "\"delta\":{\"type\":\"text_delta\",\"text\":\"world\"}}\n\n",
    );
    let (texts, inspectable) = reassemble_gemini(anthropic.as_bytes());
    assert!(inspectable, "an Anthropic stream is not a Gemini stream");
    assert_eq!(fragment(&texts, "$.content[0].text").text, "hello world");
    assert!(
        !texts
            .iter()
            .any(|text| text.kind == SseTextKind::GeminiText),
        "neither protocol produces Gemini fragments"
    );
}

// ---------------------------------------------------------------------------
// utils::sse — Hugging Face TGI /generate_stream reassembly
// ---------------------------------------------------------------------------

/// Reassemble a buffered TGI SSE body. Same shared entry point the AI
/// inspectors use — TGI frames carry no `event:` line at all.
fn reassemble_tgi(body: &[u8]) -> (Vec<SseText>, bool) {
    reassemble_anthropic(body)
}

#[test]
fn tgi_sse_reassembles_token_fragments_into_the_buffered_document_shape() {
    // `/generate_stream` emits one frame per token, then a terminal frame
    // carrying the completed `generated_text`. The fragments concatenate into
    // exactly the string a buffered `/generate` response carries at
    // `$[*].generated_text`, so the reassembled locator names that field.
    let body = concat!(
        "data: {\"index\":1,\"token\":{\"id\":10,\"text\":\"My sys\",\"logprob\":-0.5,",
        "\"special\":false},\"generated_text\":null,\"details\":null}\n\n",
        "data: {\"index\":2,\"token\":{\"id\":11,\"text\":\"tem prompt.\",\"logprob\":-0.2,",
        "\"special\":false},\"generated_text\":null,\"details\":null}\n\n",
        "data: {\"index\":3,\"token\":{\"id\":2,\"text\":\"\",\"special\":true},",
        "\"generated_text\":\"My system prompt.\",",
        "\"details\":{\"finish_reason\":\"eos_token\",\"generated_tokens\":2}}\n\n",
    );

    let (texts, inspectable) = reassemble_tgi(body.as_bytes());
    assert!(inspectable, "a well-formed TGI stream is inspectable");
    assert_eq!(
        texts.len(),
        1,
        "one TGI sequence yields exactly one fragment: {texts:?}"
    );

    let generated = fragment(&texts, "$[0].generated_text");
    assert_eq!(generated.kind, SseTextKind::TgiGeneratedText);
    assert_eq!(
        generated.text, "My system prompt.",
        "the terminal generated_text repeats the deltas and must not be scanned twice"
    );
}

#[test]
fn tgi_sse_terminal_generated_text_is_kept_when_it_diverges() {
    // A terminal full text that is NOT the concatenation of the deltas is
    // client-visible text of its own, so it is appended rather than skipped as
    // a repeat.
    let body = concat!(
        "data: {\"index\":1,\"token\":{\"id\":10,\"text\":\"all clear\"},",
        "\"generated_text\":null}\n\n",
        "data: {\"index\":2,\"token\":{\"id\":2,\"text\":\"\"},",
        "\"generated_text\":\"my system prompt\"}\n\n",
    );

    let (texts, inspectable) = reassemble_tgi(body.as_bytes());
    assert!(inspectable);
    assert_eq!(
        fragment(&texts, "$[0].generated_text").text,
        "all clearmy system prompt"
    );
}

#[test]
fn tgi_sse_malformed_and_unfoldable_frames_are_uninspectable_and_never_panic() {
    // Hostile / malformed frames inside a stream that has already identified
    // itself as TGI, plus the two options whose model text is NOT part of the
    // completion the deltas reconstruct (`top_tokens` alternatives and
    // `details.best_of_sequences`). None may panic, and none may report a clean
    // stream: once the shape is identified, a later frame that mistypes the
    // field the reassembler reads must not be passed over.
    for frame in [
        "{\"token\":\"hidden\"}",
        "{\"token\":{\"id\":1}}",
        "{\"token\":{\"id\":1,\"text\":7}}",
        "{\"token\":{\"id\":1,\"text\":\"ok\"},\"generated_text\":{\"a\":\"hidden\"}}",
        "{\"token\":{\"id\":1,\"text\":\"ok\"},\"generated_text\":7}",
        "{\"generated_text\":{\"a\":\"hidden\"}}",
        "{\"token\":{\"id\":1,\"text\":\"ok\"},\"top_tokens\":[{\"text\":\"hidden\"}]}",
        "{\"token\":{\"id\":1,\"text\":\"ok\"},\"top_tokens\":\"hidden\"}",
        "{\"generated_text\":\"ok\",\"details\":{\"best_of_sequences\":\
[{\"generated_text\":\"hidden\"}]}}",
    ] {
        let body = format!(
            "data: {{\"index\":1,\"token\":{{\"id\":0,\"text\":\"all clear\"}},\
\"generated_text\":null}}\n\ndata: {frame}\n\n"
        );
        let (_texts, inspectable) = reassemble_tgi(body.as_bytes());
        assert!(
            !inspectable,
            "malformed TGI frame must fail closed: {frame}"
        );
    }
}

#[test]
fn tgi_selection_is_structural_so_an_unrelated_stream_is_not_claimed() {
    // `token` is an ordinary field name on unrelated event streams, so
    // selection is by SHAPE: a `token` object or a string `generated_text`.
    // A foreign stream carrying neither must be left alone rather than failed
    // closed — the fail-closed rules above apply only once a frame has
    // identified the stream as TGI.
    let body = concat!(
        "data: {\"token\":\"eyJhbGciOi.session\",\"expires_in\":300}\n\n",
        "data: {\"generated_text\":42}\n\n",
        "data: {\"generated_text\":{\"a\":\"b\"}}\n\n",
    );

    let (texts, inspectable) = reassemble_tgi(body.as_bytes());
    assert!(
        inspectable,
        "an unrelated stream whose fields collide must not be failed closed"
    );
    assert!(
        texts.is_empty(),
        "and must contribute no reassembled text: {texts:?}"
    );
}

#[test]
fn tgi_sse_empty_top_tokens_and_absent_generated_text_stay_inspectable() {
    // The two benign shapes the fail-closed rules above must not catch: an
    // empty `top_tokens` array (the `top_n_tokens: 0` default some clients
    // send explicitly) and an ordinary non-terminal frame.
    let body = concat!(
        "data: {\"index\":1,\"token\":{\"id\":1,\"text\":\"hel\"},\"top_tokens\":[]}\n\n",
        "data: {\"index\":2,\"token\":{\"id\":2,\"text\":\"lo\"}}\n\n",
    );

    let (texts, inspectable) = reassemble_tgi(body.as_bytes());
    assert!(inspectable, "a benign TGI stream must not fail closed");
    assert_eq!(fragment(&texts, "$[0].generated_text").text, "hello");
}

#[test]
fn tgi_sse_frame_carrying_another_protocols_discriminator_stays_on_its_own_path() {
    // Detection is by shape, so a frame that also carries `choices`, an event
    // `type`, or `candidates` belongs to the OpenAI / Anthropic / Gemini paths
    // and must not be read a second time as a TGI token.
    let body = concat!(
        "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"Hello\"}}],",
        "\"token\":{\"id\":1,\"text\":\"dup\"}}\n\n",
    );

    let (texts, inspectable) = reassemble_tgi(body.as_bytes());
    assert!(inspectable);
    assert_eq!(fragment(&texts, "$.choices[0].delta.content").text, "Hello");
    assert!(
        !texts
            .iter()
            .any(|text| text.kind == SseTextKind::TgiGeneratedText),
        "an OpenAI frame is not also reassembled as a TGI token"
    );
}

#[test]
fn openai_anthropic_and_gemini_reassembly_are_unaffected_by_tgi_support() {
    // Behaviour-neutrality for the three protocols that already reassembled:
    // none carries a bare `token` / `generated_text` member, so none reaches
    // the TGI path, and none is failed closed by it.
    let openai = concat!(
        "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"Hel\"}}]}\n\n",
        "event: response.output_text.delta\n",
        "data: {\"type\":\"response.output_text.delta\",\"output_index\":0,",
        "\"content_index\":0,\"delta\":\"lo\"}\n\n",
        "data: [DONE]\n\n",
    );
    let (texts, inspectable) = reassemble_tgi(openai.as_bytes());
    assert!(inspectable, "an OpenAI stream is not a TGI stream");
    assert_eq!(fragment(&texts, "$.choices[0].delta.content").text, "Hel");

    let anthropic = concat!(
        "event: content_block_delta\n",
        "data: {\"type\":\"content_block_delta\",\"index\":0,",
        "\"delta\":{\"type\":\"text_delta\",\"text\":\"hello world\"}}\n\n",
    );
    let (texts, inspectable) = reassemble_tgi(anthropic.as_bytes());
    assert!(inspectable, "an Anthropic stream is not a TGI stream");
    assert_eq!(fragment(&texts, "$.content[0].text").text, "hello world");

    let gemini = concat!(
        "data: {\"candidates\":[{\"index\":0,\"content\":{\"role\":\"model\",",
        "\"parts\":[{\"text\":\"hello world\"}]}}]}\n\n",
    );
    let (texts, inspectable) = reassemble_tgi(gemini.as_bytes());
    assert!(inspectable, "a Gemini stream is not a TGI stream");
    assert_eq!(
        fragment(&texts, "$.candidates[0].content.parts[*].text").text,
        "hello world"
    );
    assert!(
        !texts
            .iter()
            .any(|text| text.kind == SseTextKind::TgiGeneratedText),
        "no already-modelled protocol produces TGI fragments"
    );
}

#[test]
fn openai_sse_reassembly_is_unaffected_by_anthropic_support() {
    // Behaviour-neutrality for the OpenAI paths: chat deltas still reassemble
    // per choice, and nothing about them trips the Anthropic fail-closed flag.
    let body = concat!(
        "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"Hel\"}}]}\n\n",
        "event: response.output_text.delta\n",
        "data: {\"type\":\"response.output_text.delta\",\"output_index\":0,",
        "\"content_index\":0,\"delta\":\"lo\"}\n\n",
        "data: [DONE]\n\n",
    );

    let (texts, inspectable) = reassemble_anthropic(body.as_bytes());
    assert!(inspectable, "an OpenAI stream is not an Anthropic stream");

    let chat = fragment(&texts, "$.choices[0].delta.content");
    assert_eq!(chat.kind, SseTextKind::ChatContent);
    assert_eq!(chat.text, "Hel");

    let responses = fragment(&texts, "$.output[0].content[0].text");
    assert_eq!(responses.kind, SseTextKind::ResponsesText);
    assert_eq!(responses.text, "lo");
}
