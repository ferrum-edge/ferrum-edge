use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use base64::Engine;
use dashmap::DashMap;
use dashmap::mapref::entry::Entry;
use jsonwebtoken::jwk::{AlgorithmParameters, Jwk};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};

use super::auth_flow::constant_time_eq;
use super::claim_resolver::extract_claim_string;

pub struct DpopJtiCache {
    entries: DashMap<String, DpopJtiEntry>,
    max_entries: usize,
    ttl: Duration,
    entry_count: AtomicUsize,
}

struct DpopJtiEntry {
    expires_at: Instant,
}

impl DpopJtiCache {
    pub fn new(max_entries: usize, ttl: Duration, shard_amount: usize) -> Self {
        Self {
            entries: DashMap::with_shard_amount(shard_amount),
            max_entries,
            ttl,
            entry_count: AtomicUsize::new(0),
        }
    }

    pub fn check_and_insert(&self, jkt: &str, jti: &str, now: Instant) -> bool {
        let mut key = format!("{jkt}|{jti}");
        loop {
            match self.entries.entry(key) {
                Entry::Occupied(mut existing) => {
                    if existing.get().expires_at > now {
                        return false;
                    }
                    // The proof carrying an expired cache entry has already
                    // passed its own `exp` check. Replacing that exact key is
                    // atomic under the DashMap shard lock and does not consume
                    // another capacity slot.
                    existing.insert(DpopJtiEntry {
                        expires_at: now + self.ttl,
                    });
                    return true;
                }
                Entry::Vacant(vacant) => {
                    if self.try_reserve_slot() {
                        vacant.insert(DpopJtiEntry {
                            expires_at: now + self.ttl,
                        });
                        return true;
                    }
                    // Do not scan other shards while holding this vacant-entry
                    // guard. At capacity we evict only expired entries; evicting
                    // a live replay marker would make that proof reusable.
                    key = vacant.into_key();
                }
            }

            if !self.evict_one_expired(now) {
                // Fail closed while every bounded slot protects a live proof.
                return false;
            }
        }
    }

    fn try_reserve_slot(&self) -> bool {
        self.entry_count
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                (count < self.max_entries).then_some(count + 1)
            })
            .is_ok()
    }

    fn evict_one_expired(&self, now: Instant) -> bool {
        loop {
            let victim = self
                .entries
                .iter()
                .find_map(|entry| (entry.value().expires_at <= now).then(|| entry.key().clone()));
            let Some(key) = victim else {
                return false;
            };
            if self
                .entries
                .remove_if(&key, |_, entry| entry.expires_at <= now)
                .is_some()
            {
                self.entry_count.fetch_sub(1, Ordering::AcqRel);
                return true;
            }
            // Another request won the removal race. Retry admission when that
            // request freed a slot, or scan again when other expired victims
            // remain; only report full when every remaining marker is live.
            if self.entry_count.load(Ordering::Acquire) < self.max_entries {
                return true;
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn max_entries(&self) -> usize {
        self.max_entries
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
    // RFC 9449 §4.3: compare `htu` ignoring query and fragment, and normalize
    // scheme/host case and default ports. `input.htu` is already canonical (the
    // caller built it via `canonical_htu`), so normalize the client-supplied
    // proof `htu` the same way before comparing. Reject if the proof's `htu`
    // cannot be parsed/normalized.
    let proof_htu = canonical_htu_from_url(&claims.htu).ok_or("DPoP URL mismatch")?;
    if proof_htu != input.htu {
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
    // RFC 9449 §4.3: when a DPoP proof is presented alongside an access token at
    // a protected resource, the resource server MUST verify that the proof's
    // `ath` claim matches the SHA-256 of the presented access token. This input
    // always carries a presented access token (and requires its `cnf.jkt`
    // binding above), so `ath` is mandatory here: a proof that omits it would
    // otherwise be bound only to the key, not to the specific token, letting a
    // proof minted for one token authorize use of a different token under the
    // same key. (A token-endpoint PoP flow without `ath` would need its own code
    // path, not a relaxation of this one.)
    let ath = claims.ath.ok_or("DPoP proof missing ath")?;
    let expected = access_token_hash(input.access_token);
    if !constant_time_eq(ath.as_bytes(), expected.as_bytes()) {
        return Err("DPoP access token hash mismatch");
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
    let raw_path = path
        .find(['?', '#'])
        .map(|idx| &path[..idx])
        .unwrap_or(path);
    let path = if raw_path.starts_with('/') {
        raw_path.to_string()
    } else {
        format!("/{raw_path}")
    };
    Some(format!("{scheme}://{host}{path}"))
}

/// Normalize a full `htu` URL string (e.g. the `htu` claim from a DPoP proof)
/// into the same canonical form as [`canonical_htu`]. Parses the URL, then
/// reconstructs `host[:port]` (the `url` crate omits default :80/:443 ports and
/// lowercases the host) and routes scheme/host/path through [`canonical_htu`] so
/// both sides of the comparison share one normalizer. Returns `None` if the URL
/// fails to parse, has no host, or contains userinfo. Per RFC 9449 §4.3, query
/// and fragment are ignored (dropped by `canonical_htu`), but userinfo is part
/// of the authority and must not be normalized away.
pub fn canonical_htu_from_url(raw: &str) -> Option<String> {
    let parsed = url::Url::parse(raw).ok()?;
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return None;
    }
    let host = parsed.host_str()?;
    let host_with_port = match parsed.port() {
        Some(port) => format!("{host}:{port}"),
        None => host.to_string(),
    };
    canonical_htu(parsed.scheme(), &host_with_port, parsed.path())
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
    fn canonical_htu_strips_query_and_fragment() {
        assert_eq!(
            canonical_htu("https", "example.com", "/resource?x=1#frag").as_deref(),
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

    #[test]
    fn expired_jti_is_not_treated_as_live_replay() {
        let cache = DpopJtiCache::new(10, Duration::from_secs(60), 4);
        let now = Instant::now();
        assert!(cache.check_and_insert("jkt", "jti", now));
        // Past the TTL the same jti is accepted again: lazy eviction means the
        // stale entry may still be present, so the replay check must compare
        // against `expires_at` rather than mere key presence.
        assert!(cache.check_and_insert("jkt", "jti", now + Duration::from_secs(61)));
    }

    #[test]
    fn jti_cache_evicts_oldest_live_entry_when_full() {
        let cache = DpopJtiCache::new(2, Duration::from_secs(60), 4);
        let now = Instant::now();
        assert!(cache.check_and_insert("jkt", "old", now));
        assert!(cache.check_and_insert("jkt", "new", now + Duration::from_secs(1)));
        assert!(cache.check_and_insert("jkt", "third", now + Duration::from_secs(2)));
        assert!(cache.check_and_insert("jkt", "old", now + Duration::from_secs(3)));
    }
}
