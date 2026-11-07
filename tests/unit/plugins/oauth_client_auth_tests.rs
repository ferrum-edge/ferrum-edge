//! Shared OAuth client-authentication mechanisms (`utils::oauth_client_auth`)
//! used by `oauth2_introspection` and `oidc_relying_party`.
//!
//! These pin the shared invariants once. Each plugin's own test file keeps
//! pinning its intentional differences (error grammar, assertion audience,
//! `client_id` source).

use base64::Engine;
use ferrum_edge::plugins::utils::oauth_client_auth::{
    BasicCredentialsError, CLIENT_ASSERTION_LIFETIME_SECS, CLIENT_ASSERTION_TYPE_JWT_BEARER,
    PrivateKeyDecodeError, basic_authorization_header, build_client_assertion, decode_private_key,
    form_encode_component, private_key_jwt_algorithm, probe_client_assertion_signing,
};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode};
use serde_json::Value;

const RSA_PRIVATE_PEM: &str = include_str!("../../fixtures/test_rsa_private.pem");
const RSA_PUBLIC_PEM: &str = include_str!("../../fixtures/test_rsa_public.pem");
const RSA_1024_PRIVATE_PEM: &str = include_str!("../../fixtures/test_rsa_1024_private.pem");

fn generated_pem(alg: &'static rcgen::SignatureAlgorithm) -> String {
    rcgen::KeyPair::generate_for(alg)
        .expect("test key generated")
        .serialize_pem()
}

fn jwt_part(token: &str, index: usize) -> Value {
    let part = token.split('.').nth(index).expect("compact JWT part");
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(part)
        .expect("base64url JWT part");
    serde_json::from_slice(&bytes).expect("JSON JWT part")
}

// ---------------------------------------------------------------------------
// RFC 6749 §2.3.1 client_secret_basic
// ---------------------------------------------------------------------------

#[test]
fn basic_header_form_encodes_each_component_before_base64() {
    for (client_id, client_secret, expected_credential) in [
        ("client:id", "s%cret", "client%3Aid:s%25cret"),
        ("plain", "secret", "plain:secret"),
        ("with space", "p+ss/word", "with+space:p%2Bss%2Fword"),
        ("caf\u{e9}", "\u{1f511}", "caf%C3%A9:%F0%9F%94%91"),
        ("a=b&c", "", "a%3Db%26c:"),
    ] {
        let header =
            basic_authorization_header(client_id, client_secret).expect("any &str pair encodes");
        let value = header.to_str().expect("ASCII header value");
        let encoded = value.strip_prefix("Basic ").expect("Basic scheme");
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .expect("standard base64");
        assert_eq!(
            std::str::from_utf8(&decoded).unwrap(),
            expected_credential,
            "credential for {client_id:?}"
        );
        assert!(
            header.is_sensitive(),
            "client credentials must be marked sensitive"
        );
    }
}

#[test]
fn basic_header_exact_bytes_match_the_pre_extraction_encoding() {
    // Same vector the introspection inline test pinned before extraction.
    let header = basic_authorization_header("client:id", "s%cret").unwrap();
    assert_eq!(header.as_bytes(), b"Basic Y2xpZW50JTNBaWQ6cyUyNWNyZXQ=");
}

#[test]
fn form_encode_component_is_application_x_www_form_urlencoded() {
    for (raw, expected) in [
        ("", ""),
        ("abc", "abc"),
        (" ", "+"),
        ("+", "%2B"),
        (":", "%3A"),
        ("%", "%25"),
        ("*-._", "*-._"),
        ("\u{e9}", "%C3%A9"),
    ] {
        assert_eq!(form_encode_component(raw).as_deref(), Some(expected));
    }
}

#[test]
fn basic_credentials_error_variants_are_distinct() {
    // Introspection maps the two variants to different diagnostics; keep them
    // distinguishable so a future refactor cannot fold them silently.
    assert_ne!(
        BasicCredentialsError::FormEncode,
        BasicCredentialsError::HeaderValue
    );
}

// ---------------------------------------------------------------------------
// private_key_jwt algorithm table and key decoding
// ---------------------------------------------------------------------------

#[test]
fn private_key_jwt_algorithm_table_is_exact_and_case_sensitive() {
    for (name, alg) in [
        ("RS256", Algorithm::RS256),
        ("RS384", Algorithm::RS384),
        ("RS512", Algorithm::RS512),
        ("ES256", Algorithm::ES256),
        ("ES384", Algorithm::ES384),
        ("EdDSA", Algorithm::EdDSA),
    ] {
        assert_eq!(private_key_jwt_algorithm(name), Some(alg), "{name}");
    }
    for rejected in [
        "", "rs256", "eddsa", "HS256", "HS512", "PS256", "ES512", "none", " RS256",
    ] {
        assert_eq!(
            private_key_jwt_algorithm(rejected),
            None,
            "{rejected:?} must not be a client-assertion algorithm"
        );
    }
}

#[test]
fn decode_private_key_selects_the_key_family_from_the_algorithm() {
    let p256 = generated_pem(&rcgen::PKCS_ECDSA_P256_SHA256);
    let ed25519 = generated_pem(&rcgen::PKCS_ED25519);

    for alg in [Algorithm::RS256, Algorithm::RS384, Algorithm::RS512] {
        assert!(decode_private_key(alg, RSA_PRIVATE_PEM).is_ok(), "{alg:?}");
        assert_eq!(
            decode_private_key(alg, "not a pem").err(),
            Some(PrivateKeyDecodeError::InvalidRsaPem)
        );
    }
    for alg in [Algorithm::ES256, Algorithm::ES384] {
        assert!(decode_private_key(alg, &p256).is_ok(), "{alg:?}");
        assert_eq!(
            decode_private_key(alg, RSA_PRIVATE_PEM).err(),
            Some(PrivateKeyDecodeError::InvalidEcPem)
        );
    }
    assert!(decode_private_key(Algorithm::EdDSA, &ed25519).is_ok());
    assert_eq!(
        decode_private_key(Algorithm::EdDSA, RSA_PRIVATE_PEM).err(),
        Some(PrivateKeyDecodeError::InvalidEdDsaPem)
    );
    for alg in [Algorithm::HS256, Algorithm::PS256] {
        assert_eq!(
            decode_private_key(alg, RSA_PRIVATE_PEM).err(),
            Some(PrivateKeyDecodeError::UnsupportedAlgorithm),
            "{alg:?} is outside the client-assertion table"
        );
    }
}

// ---------------------------------------------------------------------------
// RFC 7523 client assertion
// ---------------------------------------------------------------------------

#[test]
fn client_assertion_carries_the_rfc7523_claims_and_verifies() {
    let key = decode_private_key(Algorithm::RS256, RSA_PRIVATE_PEM).unwrap();
    let token = build_client_assertion(
        "client-1",
        "https://idp.example/token",
        &key,
        Algorithm::RS256,
        Some("kid-1"),
    )
    .expect("RSA fixture signs");

    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_audience(&["https://idp.example/token"]);
    validation.set_issuer(&["client-1"]);
    let verified = decode::<Value>(
        &token,
        &DecodingKey::from_rsa_pem(RSA_PUBLIC_PEM.as_bytes()).unwrap(),
        &validation,
    )
    .expect("the assertion verifies under the matching public key");
    let claims = verified.claims;
    assert_eq!(claims["iss"], "client-1");
    assert_eq!(claims["sub"], "client-1");
    assert_eq!(claims["aud"], "https://idp.example/token");
    let iat = claims["iat"].as_i64().expect("iat");
    let exp = claims["exp"].as_i64().expect("exp");
    assert_eq!(exp - iat, CLIENT_ASSERTION_LIFETIME_SECS);
    assert_eq!(CLIENT_ASSERTION_LIFETIME_SECS, 300);
    assert!(
        (iat - chrono::Utc::now().timestamp()).abs() <= 5,
        "iat is the signing instant"
    );
    assert!(
        uuid::Uuid::parse_str(claims["jti"].as_str().expect("jti")).is_ok(),
        "jti is a UUID"
    );

    let header = jwt_part(&token, 0);
    assert_eq!(header["alg"], "RS256");
    assert_eq!(header["kid"], "kid-1");
}

#[test]
fn client_assertion_jti_is_unique_and_kid_is_omitted_when_unset() {
    let key = decode_private_key(Algorithm::RS256, RSA_PRIVATE_PEM).unwrap();
    let first = build_client_assertion("c", "aud", &key, Algorithm::RS256, None).unwrap();
    let second = build_client_assertion("c", "aud", &key, Algorithm::RS256, None).unwrap();
    assert_ne!(jwt_part(&first, 1)["jti"], jwt_part(&second, 1)["jti"]);
    assert!(jwt_part(&first, 0).get("kid").is_none());
}

#[test]
fn client_assertion_type_is_the_rfc7523_jwt_bearer_urn() {
    assert_eq!(
        CLIENT_ASSERTION_TYPE_JWT_BEARER,
        "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
    );
}

// ---------------------------------------------------------------------------
// Admission signing probe (issues #5015 / #5032)
// ---------------------------------------------------------------------------

#[test]
fn signing_probe_rejects_keys_the_algorithm_cannot_sign_with() {
    let p256 = generated_pem(&rcgen::PKCS_ECDSA_P256_SHA256);
    let p384 = generated_pem(&rcgen::PKCS_ECDSA_P384_SHA384);

    // Curve mismatch: both PEMs decode as EC under either algorithm.
    for (alg, pem) in [(Algorithm::ES256, &p384), (Algorithm::ES384, &p256)] {
        let key = decode_private_key(alg, pem).expect("PEM parse alone admits the mismatch");
        assert!(
            probe_client_assertion_signing(&key, alg).is_err(),
            "{alg:?} must not sign with the other curve"
        );
    }

    // Undersized RSA modulus decodes but cannot sign.
    let small = decode_private_key(Algorithm::RS256, RSA_1024_PRIVATE_PEM).expect("RSA PEM");
    assert!(probe_client_assertion_signing(&small, Algorithm::RS256).is_err());
}

#[test]
fn signing_probe_admits_every_matching_pair() {
    let p256 = generated_pem(&rcgen::PKCS_ECDSA_P256_SHA256);
    let p384 = generated_pem(&rcgen::PKCS_ECDSA_P384_SHA384);
    let ed25519 = generated_pem(&rcgen::PKCS_ED25519);
    for (alg, pem) in [
        (Algorithm::RS256, RSA_PRIVATE_PEM),
        (Algorithm::RS384, RSA_PRIVATE_PEM),
        (Algorithm::RS512, RSA_PRIVATE_PEM),
        (Algorithm::ES256, p256.as_str()),
        (Algorithm::ES384, p384.as_str()),
        (Algorithm::EdDSA, ed25519.as_str()),
    ] {
        let key = decode_private_key(alg, pem).expect("matching PEM decodes");
        assert!(
            probe_client_assertion_signing(&key, alg).is_ok(),
            "{alg:?} must sign with a matching key"
        );
    }
}
