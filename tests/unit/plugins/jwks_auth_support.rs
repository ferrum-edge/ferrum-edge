use ferrum_edge::plugins::{PluginHttpClient, RequestContext};
use serde_json::{Value, json};
use std::sync::OnceLock;

/// Serializes tests that reset or depend on the process-global remote JWKS
/// cache (`jwks_cache_tests` in the a–j target; `oidc_relying_party_tests` and
/// `plugin_cache_tests` in the k–z target).
pub fn cache_test_lock() -> &'static tokio::sync::Mutex<()> {
    static LOCK: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| tokio::sync::Mutex::new(()))
}

pub fn default_client() -> PluginHttpClient {
    PluginHttpClient::default()
}

pub fn make_ctx() -> RequestContext {
    RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/test".to_string(),
    )
}

pub fn create_rs256_token(claims: &Value, private_key_pem: &[u8]) -> String {
    let mut claims = claims.clone();
    if let Some(obj) = claims.as_object_mut() {
        obj.entry("exp")
            .or_insert_with(|| json!(chrono::Utc::now().timestamp() + 3600));
    }

    create_rs256_token_exact(&claims, private_key_pem)
}

pub fn create_rs256_token_exact(claims: &Value, private_key_pem: &[u8]) -> String {
    encode_rs256_token(claims, private_key_pem, Some("test-key-1"))
}

pub fn create_rs256_token_with_kid(claims: &Value, private_key_pem: &[u8], kid: &str) -> String {
    let claims = claims_with_default_exp(claims);
    encode_rs256_token(&claims, private_key_pem, Some(kid))
}

pub fn create_rs256_token_no_kid(claims: &Value, private_key_pem: &[u8]) -> String {
    let claims = claims_with_default_exp(claims);
    encode_rs256_token(&claims, private_key_pem, None)
}

fn claims_with_default_exp(claims: &Value) -> Value {
    let mut claims = claims.clone();
    if let Some(obj) = claims.as_object_mut() {
        obj.entry("exp")
            .or_insert_with(|| json!(chrono::Utc::now().timestamp() + 3600));
    }
    claims
}

fn encode_rs256_token(claims: &Value, private_key_pem: &[u8], kid: Option<&str>) -> String {
    use jsonwebtoken::{EncodingKey, Header, encode};
    let mut header = Header::new(jsonwebtoken::Algorithm::RS256);
    header.kid = kid.map(ToOwned::to_owned);
    encode(
        &header,
        claims,
        &EncodingKey::from_rsa_pem(private_key_pem).unwrap(),
    )
    .unwrap()
}

pub fn build_rsa_jwks_from_pem(public_key_pem: &[u8]) -> serde_json::Value {
    build_rsa_jwks_from_pem_with_kid(public_key_pem, "test-key-1")
}

pub fn build_rsa_jwks_from_pem_with_kid(public_key_pem: &[u8], kid: &str) -> serde_json::Value {
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

    let pem_str = std::str::from_utf8(public_key_pem).unwrap();
    let der = extract_der_from_pem(pem_str);
    let (n, e) = parse_rsa_public_key_der(&der);

    json!({
        "keys": [{
            "kty": "RSA",
            "kid": kid,
            "use": "sig",
            "alg": "RS256",
            "n": URL_SAFE_NO_PAD.encode(&n),
            "e": URL_SAFE_NO_PAD.encode(&e)
        }]
    })
}

fn extract_der_from_pem(pem: &str) -> Vec<u8> {
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;
    let b64: String = pem
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect();
    STANDARD.decode(b64).unwrap()
}

fn parse_rsa_public_key_der(der: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let mut pos = 0;
    assert_eq!(der[pos], 0x30);
    pos += 1;
    let (_outer_len, consumed) = parse_asn1_length(&der[pos..]);
    pos += consumed;
    assert_eq!(der[pos], 0x30);
    pos += 1;
    let (algo_len, consumed) = parse_asn1_length(&der[pos..]);
    pos += consumed + algo_len;
    assert_eq!(der[pos], 0x03);
    pos += 1;
    let (_bs_len, consumed) = parse_asn1_length(&der[pos..]);
    pos += consumed + 1;
    assert_eq!(der[pos], 0x30);
    pos += 1;
    let (_inner_len, consumed) = parse_asn1_length(&der[pos..]);
    pos += consumed;
    assert_eq!(der[pos], 0x02);
    pos += 1;
    let (n_len, consumed) = parse_asn1_length(&der[pos..]);
    pos += consumed;
    let mut n = der[pos..pos + n_len].to_vec();
    pos += n_len;
    if !n.is_empty() && n[0] == 0 {
        n.remove(0);
    }
    assert_eq!(der[pos], 0x02);
    pos += 1;
    let (e_len, consumed) = parse_asn1_length(&der[pos..]);
    pos += consumed;
    let e = der[pos..pos + e_len].to_vec();
    (n, e)
}

fn parse_asn1_length(data: &[u8]) -> (usize, usize) {
    if data[0] < 0x80 {
        (data[0] as usize, 1)
    } else {
        let num_bytes = (data[0] & 0x7f) as usize;
        let mut length = 0usize;
        for &byte in &data[1..=num_bytes] {
            length = (length << 8) | byte as usize;
        }
        (length, 1 + num_bytes)
    }
}
