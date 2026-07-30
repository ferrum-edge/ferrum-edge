use ferrum_edge::plugins::RequestContext;
use ferrum_edge::plugins::utils::auth_flow::ExtractedCredential;
use ferrum_edge::plugins::utils::cert_hash::{sha256_base64url_no_pad, sha256_hex_lower};
use ferrum_edge::plugins::utils::claim_resolver::{
    extract_claim_string, extract_claim_string_exact, extract_claim_values, parse_claim_path_value,
};
use ferrum_edge::plugins::utils::json_escape::escape_json_string;
use ferrum_edge::plugins::utils::jwt_verifier::peek_unverified_issuer;
use ferrum_edge::plugins::utils::query::{
    CanonicalQuery, QueryAmbiguity, canonical_query_for_policy, has_conflicting_duplicate_query_key,
};
use ferrum_edge::plugins::utils::scope_role_check::{ScopeRoleRequirements, check};
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
fn query_duplicate_check_allows_percent_encoded_keys_with_same_value() {
    assert!(!has_conflicting_duplicate_query_key("a%20b=1&a%20b=1"));
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
