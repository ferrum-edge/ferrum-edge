//! RFC 9449 DPoP proof validation.
//!
//! This module owns the cryptographic and claim checks only. Single-use replay
//! protection is **not** local state here: it belongs to the shared
//! [`crate::plugins::utils::replay_authority`], which owns lane identity,
//! reload stability, cross-replica claims, capacity semantics, and fail-closed
//! classification for every proof-of-possession admission in the gateway.
//!
//! [`verify`] therefore performs signature, `typ`/`alg`, JWK thumbprint /
//! `cnf.jkt` binding, `htm`, `htu`, `iat`, `ath`, and — when a client sends the
//! non-standard claim at all — `exp` validation, and then
//! returns the [`ReplayMarker`] the caller must claim. Ordering is the point:
//! an unauthenticated proof never reaches replay state, so garbage cannot
//! consume capacity or a shared-backend round trip.
//!
//! ## Retention horizon
//!
//! A proof is acceptable only while `|iat - now| <= clock_skew`, so the widest
//! span over which one unchanged proof can ever be accepted is
//! `2 * MAX_DPOP_CLOCK_SKEW_SECS`, whatever a provider configures and whatever
//! a later reload widens it to. [`DPOP_MARKER_RETENTION_SECONDS`] is that span
//! plus one second for whole-second truncation, is fixed rather than
//! configurable, and is written identically by every generation and replica —
//! so a marker always outlives every window in which its proof could be
//! re-presented.

use crate::fips::approved::Sha256;
use std::time::Duration;

use base64::Engine;
use jsonwebtoken::jwk::{AlgorithmParameters, Jwk};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use serde::Deserialize;
use serde_json::Value;

use super::auth_flow::constant_time_eq;
use super::claim_resolver::extract_claim_string;
use super::replay_authority::{ReplayDomain, ReplayMarker};

/// Versioned proof profile bound into every DPoP protection domain.
pub const DPOP_REPLAY_PROFILE: &str = "ferrum-dpop-proof-v1";

/// Widest admissible `dpop_clock_skew_secs`.
pub const MAX_DPOP_CLOCK_SKEW_SECS: u64 = 300;

/// Fixed retention horizon for an admitted DPoP proof marker.
///
/// Dominates `2 * MAX_DPOP_CLOCK_SKEW_SECS` — the widest acceptance span any
/// admissible provider configuration can open for one unchanged proof — plus
/// one second for whole-second truncation.
pub const DPOP_MARKER_RETENTION_SECONDS: u64 = 2 * MAX_DPOP_CLOCK_SKEW_SECS + 1;

const _: () = assert!(DPOP_MARKER_RETENTION_SECONDS > 2 * MAX_DPOP_CLOCK_SKEW_SECS);

pub struct DpopVerifyInput<'a> {
    pub proof: &'a str,
    pub access_token: &'a str,
    pub access_token_claims: &'a Value,
    pub method: &'a str,
    pub htu: &'a str,
    pub clock_skew: Duration,
    /// Precomputed protection domain for the provider that required this proof.
    pub domain: &'a ReplayDomain,
}

#[derive(Debug, Deserialize)]
struct DpopClaims {
    htm: String,
    htu: String,
    iat: i64,
    /// RFC 9449 §4.2 does not define `exp` for a proof JWT, and conformant
    /// client libraries do not emit one, so requiring it would make
    /// `require_dpop` unusable with standards-compliant clients. Freshness is
    /// bounded by `iat` ± the provider's clock skew, which is also what the
    /// fixed marker retention horizon is derived from. A proof that does carry
    /// `exp` is still held to it (see [`verify`]).
    #[serde(default)]
    exp: Option<i64>,
    jti: String,
    #[serde(default)]
    ath: Option<String>,
}

/// Validate a DPoP proof and return the replay marker the caller must claim.
///
/// Returning the marker instead of claiming it here is deliberate: the claim is
/// an `async` operation against a possibly shared authority, and it must happen
/// **after** every check below. A caller that drops the returned marker has
/// validated a proof without making it single-use, which is why the only
/// production caller feeds it straight into
/// [`crate::plugins::utils::replay_authority::ReplayAuthority::admit`].
#[must_use = "a validated DPoP proof is only single-use once its marker is claimed"]
pub fn verify(input: DpopVerifyInput<'_>) -> Result<ReplayMarker, &'static str> {
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
    // `validate_exp` rejects a PRESENT-and-past (or unparseable) `exp`;
    // `required_spec_claims` is the separate mechanism that rejects an ABSENT
    // one, and `Validation::new` seeds it with `exp`. RFC 9449 §4.2 defines no
    // `exp` proof claim, so presence must not be required — but the value is
    // still enforced whenever a client chooses to send it.
    validation.required_spec_claims.clear();
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
    if let Some(exp) = claims.exp
        && exp < now.saturating_sub(skew)
    {
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

    // Every cryptographic and claim check has passed. The marker binds the
    // provider's protection domain to the proof's key thumbprint and `jti`;
    // neither the thumbprint nor the `jti` survives this call.
    Ok(input
        .domain
        .marker(&[jkt.as_bytes(), claims.jti.as_bytes()]))
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
    fn retention_horizon_dominates_the_widest_admissible_acceptance_window() {
        // A proof is acceptable only inside `iat ± clock_skew`, so the widest
        // window any admissible provider (or any later reload that widens the
        // skew) can open is `2 * MAX_DPOP_CLOCK_SKEW_SECS`.
        const {
            assert!(DPOP_MARKER_RETENTION_SECONDS > 2 * MAX_DPOP_CLOCK_SKEW_SECS);
        }
    }
}
