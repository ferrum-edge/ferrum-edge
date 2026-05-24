use std::time::{Duration, Instant};

use base64::Engine;
use dashmap::DashMap;
use jsonwebtoken::jwk::{AlgorithmParameters, Jwk};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};

use super::auth_flow::constant_time_eq;
use super::claim_resolver::extract_claim_string;

pub struct DpopJtiCache {
    entries: DashMap<String, Instant>,
    max_entries: usize,
    ttl: Duration,
}

impl DpopJtiCache {
    pub fn new(max_entries: usize, ttl: Duration, shard_amount: usize) -> Self {
        Self {
            entries: DashMap::with_shard_amount(shard_amount),
            max_entries,
            ttl,
        }
    }

    pub fn check_and_insert(&self, jkt: &str, jti: &str, now: Instant) -> bool {
        self.evict_expired(now);
        let key = format!("{jkt}|{jti}");
        if self.entries.contains_key(&key) {
            return false;
        }
        if self.entries.len() >= self.max_entries {
            self.evict_one(now);
        }
        self.entries.insert(key, now + self.ttl);
        true
    }

    fn evict_expired(&self, now: Instant) {
        self.entries.retain(|_, expires_at| *expires_at > now);
    }

    fn evict_one(&self, now: Instant) {
        let victim = self
            .entries
            .iter()
            .find_map(|entry| (*entry.value() <= now).then(|| entry.key().clone()))
            .or_else(|| self.entries.iter().next().map(|entry| entry.key().clone()));
        if let Some(key) = victim {
            self.entries.remove(&key);
        }
    }
}

pub struct DpopVerifyInput<'a> {
    pub proof: &'a str,
    pub access_token: &'a str,
    pub access_token_claims: &'a Value,
    pub method: &'a str,
    pub htu: &'a str,
    pub clock_skew: Duration,
    pub cache: &'a DpopJtiCache,
}

#[derive(Debug, Deserialize)]
struct DpopClaims {
    htm: String,
    htu: String,
    iat: i64,
    exp: i64,
    jti: String,
    #[serde(default)]
    ath: Option<String>,
}

pub fn verify(input: DpopVerifyInput<'_>) -> Result<(), &'static str> {
    let header = decode_header(input.proof).map_err(|_| "Invalid DPoP proof")?;
    if header.typ.as_deref() != Some("dpop+jwt") {
        return Err("Invalid DPoP proof type");
    }
    if !matches!(header.alg, Algorithm::ES256 | Algorithm::RS256) {
        return Err("Unsupported DPoP algorithm");
    }
    let jwk = header.jwk.as_ref().ok_or("DPoP proof missing jwk")?;
    let jkt = jwk_thumbprint_sha256(jwk).map_err(|_| "Invalid DPoP jwk")?;
    let token_jkt = extract_claim_string(input.access_token_claims, "cnf.jkt")
        .ok_or("DPoP token binding missing")?;
    if !constant_time_eq(jkt.as_bytes(), token_jkt.as_bytes()) {
        return Err("DPoP binding mismatch");
    }

    let key = DecodingKey::from_jwk(jwk).map_err(|_| "Invalid DPoP jwk")?;
    let mut validation = Validation::new(header.alg);
    validation.validate_exp = true;
    validation.validate_nbf = false;
    validation.validate_aud = false;
    validation.leeway = input.clock_skew.as_secs();
    let token_data =
        decode::<DpopClaims>(input.proof, &key, &validation).map_err(|_| "Invalid DPoP proof")?;
    let claims = token_data.claims;

    if claims.htm != input.method.to_ascii_uppercase() {
        return Err("DPoP method mismatch");
    }
    if claims.htu != input.htu {
        return Err("DPoP URL mismatch");
    }
    let now = chrono::Utc::now().timestamp();
    let skew = input.clock_skew.as_secs() as i64;
    if claims.iat < now.saturating_sub(skew) || claims.iat > now.saturating_add(skew) {
        return Err("DPoP iat outside clock skew");
    }
    if claims.exp < now.saturating_sub(skew) {
        return Err("Invalid DPoP proof");
    }
    if let Some(ath) = claims.ath {
        let expected = access_token_hash(input.access_token);
        if !constant_time_eq(ath.as_bytes(), expected.as_bytes()) {
            return Err("DPoP access token hash mismatch");
        }
    }
    if !input
        .cache
        .check_and_insert(&jkt, &claims.jti, Instant::now())
    {
        return Err("DPoP replay");
    }

    Ok(())
}

pub fn canonical_htu(scheme: &str, host: &str, path: &str) -> Option<String> {
    let scheme = scheme.to_ascii_lowercase();
    if scheme != "http" && scheme != "https" {
        return None;
    }
    let mut host = host.trim().to_ascii_lowercase();
    if host.is_empty() {
        return None;
    }
    if (scheme == "http" && host.ends_with(":80")) || (scheme == "https" && host.ends_with(":443"))
    {
        let (without_port, _) = host.rsplit_once(':')?;
        host = without_port.to_string();
    }
    let path = if path.starts_with('/') {
        path.to_string()
    } else {
        format!("/{path}")
    };
    Some(format!("{scheme}://{host}{path}"))
}

pub fn jwk_thumbprint_sha256(jwk: &Jwk) -> Result<String, String> {
    let canonical = match &jwk.algorithm {
        AlgorithmParameters::EllipticCurve(params) => format!(
            r#"{{"crv":"{}","kty":"EC","x":"{}","y":"{}"}}"#,
            serde_json::to_value(&params.curve)
                .ok()
                .and_then(|value| value.as_str().map(ToOwned::to_owned))
                .ok_or_else(|| "unsupported EC curve".to_string())?,
            params.x,
            params.y
        ),
        AlgorithmParameters::RSA(params) => {
            format!(r#"{{"e":"{}","kty":"RSA","n":"{}"}}"#, params.e, params.n)
        }
        _ => return Err("unsupported JWK type".to_string()),
    };
    let mut hasher = Sha256::new();
    hasher.update(canonical.as_bytes());
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hasher.finalize()))
}

fn access_token_hash(access_token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(access_token.as_bytes());
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn canonical_htu_strips_default_ports() {
        assert_eq!(
            canonical_htu("HTTPS", "Example.COM:443", "/resource").as_deref(),
            Some("https://example.com/resource")
        );
    }

    #[test]
    fn thumbprint_is_stable_for_rsa_jwk() {
        let jwk: Jwk = serde_json::from_value(json!({
            "kty": "RSA",
            "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2ai3r1KQ5f8_4s6tQNm1i7cNtZ3uQKrK3Y9b9GdQ9kTLu5wC1fV480sB4L3lLrrJNmTtI4HBe4xzN2gDx4Z4DkEkL1nYz-ERaY3-E9S3lN_R5M6g7M8T6Yb5A",
            "e": "AQAB",
            "alg": "RS256"
        }))
        .expect("jwk should parse");
        assert_eq!(
            jwk_thumbprint_sha256(&jwk).expect("thumbprint"),
            "5QF4zPpD3AXv04VQpxrSR7aaWug6gy9p6s63t9Rbg3I"
        );
    }

    #[test]
    fn jti_cache_rejects_replay() {
        let cache = DpopJtiCache::new(10, Duration::from_secs(60), 4);
        let now = Instant::now();
        assert!(cache.check_and_insert("jkt", "jti", now));
        assert!(!cache.check_and_insert("jkt", "jti", now));
    }
}
