//! `jwks_auth` access-token algorithms beyond RS256/384/512 and ES256/384:
//! RSASSA-PSS (`PS256`/`PS384`/`PS512`) and Ed25519 (`EdDSA`), with the JWK
//! `alg` binding kept strict so PSS and PKCS#1 v1.5 never cross-verify.
//! (`EdDSA` is refused while FIPS mode is enforced; that refusal is pinned in
//! `tests/unit/tls/fips_key_admission_tests.rs`.)

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ferrum_edge::ConsumerIndex;
use ferrum_edge::plugins::{Plugin, PluginResult, jwks_auth::JwksAuth};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use serde_json::{Value, json};

use super::jwks_auth_support::{build_rsa_jwks_from_pem, default_client, make_ctx};
use super::plugin_utils::{assert_continue, assert_reject};

const ISSUER: &str = "https://algorithms.example.com";
const RSA_PRIVATE_PEM: &[u8] = include_bytes!("../../../tests/fixtures/test_rsa_private.pem");
const RSA_PUBLIC_PEM: &[u8] = include_bytes!("../../../tests/fixtures/test_rsa_public.pem");

/// The RSA fixture key published under `kid` `test-key-1` with the given JWK
/// `alg` (or none).
fn rsa_jwks(alg: Option<&str>) -> Value {
    let mut jwks = build_rsa_jwks_from_pem(RSA_PUBLIC_PEM);
    let key = jwks["keys"][0].as_object_mut().expect("JWK object");
    key.remove("alg");
    if let Some(alg) = alg {
        key.insert("alg".to_string(), json!(alg));
    }
    jwks
}

fn sign(alg: Algorithm, kid: &str, key: &EncodingKey, sub: &str) -> String {
    let mut header = Header::new(alg);
    header.kid = Some(kid.to_string());
    encode(
        &header,
        &json!({
            "iss": ISSUER,
            "sub": sub,
            "exp": chrono::Utc::now().timestamp() + 3600
        }),
        key,
    )
    .expect("token signs")
}

fn rsa_key() -> EncodingKey {
    EncodingKey::from_rsa_pem(RSA_PRIVATE_PEM).expect("RSA fixture key")
}

fn plugin_for(jwks: &Value) -> JwksAuth {
    JwksAuth::new(
        &json!({"providers": [{"issuer": ISSUER, "jwks": jwks}]}),
        default_client(),
    )
    .expect("inline provider")
}

async fn authenticate(plugin: &JwksAuth, token: &str) -> (PluginResult, Option<String>) {
    let mut ctx = make_ctx();
    ctx.headers
        .insert("authorization".to_string(), format!("Bearer {token}"));
    let result = plugin
        .authenticate(&mut ctx, &ConsumerIndex::new(&[]))
        .await;
    let identity = ctx.authenticated_identity.clone();
    (result, identity)
}

#[tokio::test]
async fn rsassa_pss_tokens_verify_against_pss_bound_keys() {
    for (alg_name, alg) in [
        ("PS256", Algorithm::PS256),
        ("PS384", Algorithm::PS384),
        ("PS512", Algorithm::PS512),
    ] {
        let plugin = plugin_for(&rsa_jwks(Some(alg_name)));
        let (result, identity) =
            authenticate(&plugin, &sign(alg, "test-key-1", &rsa_key(), "pss-user")).await;
        assert_continue(result);
        assert_eq!(identity.as_deref(), Some("pss-user"), "{alg_name}");
    }
}

/// The JWK `alg` binds verification to exactly one algorithm: a PSS key never
/// verifies a PKCS#1 v1.5 token, a PKCS#1 v1.5 key never verifies a PSS token,
/// and a key with no `alg` keeps its RS256 default rather than accepting PSS.
#[tokio::test]
async fn pss_and_pkcs1_bindings_never_cross_verify() {
    for (key_alg, token_alg) in [
        (Some("PS256"), Algorithm::RS256),
        (Some("PS256"), Algorithm::PS384),
        (Some("RS256"), Algorithm::PS256),
        (None, Algorithm::PS256),
    ] {
        let plugin = plugin_for(&rsa_jwks(key_alg));
        let (result, identity) =
            authenticate(&plugin, &sign(token_alg, "test-key-1", &rsa_key(), "user")).await;
        assert_reject(result, Some(401));
        assert!(
            identity.is_none(),
            "key alg {key_alg:?} must not verify a {token_alg:?} token"
        );
    }
}

/// A fresh Ed25519 key pair: its public OKP JWK under `kid`, and its signing key.
fn ed25519(kid: &str) -> (Value, EncodingKey) {
    let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).expect("Ed25519 key");
    let jwk = json!({
        "kty": "OKP",
        "crv": "Ed25519",
        "kid": kid,
        "use": "sig",
        "alg": "EdDSA",
        "x": URL_SAFE_NO_PAD.encode(key_pair.public_key_raw())
    });
    let key = EncodingKey::from_ed_pem(key_pair.serialize_pem().as_bytes()).expect("Ed25519 PEM");
    (jwk, key)
}

#[tokio::test]
async fn eddsa_token_verifies_against_ed25519_jwk() {
    let (jwk, key) = ed25519("ed-key");
    let plugin = plugin_for(&json!({"keys": [jwk]}));

    let (result, identity) =
        authenticate(&plugin, &sign(Algorithm::EdDSA, "ed-key", &key, "ed-user")).await;
    assert_continue(result);
    assert_eq!(identity.as_deref(), Some("ed-user"));
}

#[tokio::test]
async fn eddsa_binding_rejects_other_keys_and_algorithms() {
    let (jwk, _) = ed25519("ed-key");
    let (_, other_key) = ed25519("unused");
    let plugin = plugin_for(&json!({"keys": [jwk]}));

    // Same `kid`, a different Ed25519 private key.
    let (result, identity) = authenticate(
        &plugin,
        &sign(Algorithm::EdDSA, "ed-key", &other_key, "user"),
    )
    .await;
    assert_reject(result, Some(401));
    assert!(identity.is_none());

    // An RSA token naming the OKP key's `kid` is bound to EdDSA and refused.
    let (result, identity) = authenticate(
        &plugin,
        &sign(Algorithm::RS256, "ed-key", &rsa_key(), "user"),
    )
    .await;
    assert_reject(result, Some(401));
    assert!(identity.is_none());
}

/// RSA, PSS, and Ed25519 keys coexist in one JWKS; each token verifies only
/// under the key its `kid` names.
#[tokio::test]
async fn mixed_jwks_routes_each_algorithm_to_its_own_key() {
    let (ed_jwk, ed_key) = ed25519("ed-key");
    let mut rsa = rsa_jwks(Some("RS256"))["keys"][0].clone();
    rsa["kid"] = json!("rsa-key");
    let mut pss = rsa_jwks(Some("PS256"))["keys"][0].clone();
    pss["kid"] = json!("pss-key");
    let plugin = plugin_for(&json!({"keys": [rsa, pss, ed_jwk]}));

    for (token, expected) in [
        (
            sign(Algorithm::RS256, "rsa-key", &rsa_key(), "rsa-user"),
            "rsa-user",
        ),
        (
            sign(Algorithm::PS256, "pss-key", &rsa_key(), "pss-user"),
            "pss-user",
        ),
        (
            sign(Algorithm::EdDSA, "ed-key", &ed_key, "ed-user"),
            "ed-user",
        ),
    ] {
        let (result, identity) = authenticate(&plugin, &token).await;
        assert_continue(result);
        assert_eq!(identity.as_deref(), Some(expected));
    }
}
