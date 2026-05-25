use std::collections::HashSet;

use base64::Engine;
use jsonwebtoken::{Algorithm, Validation, decode, decode_header};
use serde_json::Value;
use tracing::debug;

use super::jwks_store::JwksKeyStore;

pub struct JwtVerifyParams<'a> {
    pub issuer: Option<&'a str>,
    pub audiences: &'a [String],
    pub require_exp: bool,
    pub leeway_secs: u64,
    pub validate_nbf: bool,
}

pub async fn verify_jwt_with_jwks(
    token: &str,
    store: &JwksKeyStore,
    params: &JwtVerifyParams<'_>,
) -> Option<Value> {
    if !store.has_keys() {
        debug!("JWKS store has no cached keys; rejecting without hot-path fetch");
        return None;
    }

    let header = decode_header(token).ok()?;

    if let Some(kid) = &header.kid {
        if let Some(cached_key) = store.get_key(kid) {
            let validation = build_validation(cached_key.algorithm, params);
            if let Ok(td) = decode::<Value>(token, &cached_key.decoding_key, &validation) {
                return Some(td.claims);
            }
        }
        debug!("JWKS key not found for kid={}, trying all keys", kid);
    }

    let all_keys = store.all_keys();
    for cached_key in all_keys.values() {
        let validation = build_validation(cached_key.algorithm, params);
        if let Ok(td) = decode::<Value>(token, &cached_key.decoding_key, &validation) {
            return Some(td.claims);
        }
    }

    None
}

pub fn peek_unverified_issuer(token: &str) -> Option<String> {
    let mut parts = token.split('.');
    let _header = parts.next()?;
    let payload_segment = parts.next()?;
    let _signature = parts.next()?;
    if parts.next().is_some() {
        return None;
    }

    let payload_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload_segment)
        .ok()?;
    let payload: Value = serde_json::from_slice(&payload_bytes).ok()?;
    payload
        .get("iss")
        .and_then(|v| v.as_str())
        .map(ToOwned::to_owned)
}

fn build_validation(algorithm: Algorithm, params: &JwtVerifyParams<'_>) -> Validation {
    let mut validation = Validation::new(algorithm);
    validation.validate_exp = true;
    validation.leeway = params.leeway_secs;
    validation.validate_nbf = params.validate_nbf;
    if params.require_exp {
        validation.required_spec_claims = HashSet::from(["exp".to_string()]);
    } else {
        validation.required_spec_claims.clear();
    }
    if let Some(issuer) = params.issuer {
        validation.set_issuer(&[issuer]);
    }
    if !params.audiences.is_empty() {
        validation.set_audience(params.audiences);
    }
    validation
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{EncodingKey, Header, encode};
    use serde_json::json;

    #[test]
    fn peeks_issuer_without_verifying_signature() {
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
    fn malformed_token_has_no_issuer() {
        assert!(peek_unverified_issuer("not.a.jwt.extra").is_none());
    }
}
