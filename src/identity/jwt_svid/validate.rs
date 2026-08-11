//! Fail-closed JWT-SVID validation.
//!
//! Everything here is deliberately conservative: an input that is merely
//! *unusual* is rejected rather than interpreted. The checks, in order:
//!
//! 1. **Structure** — size cap, exactly three non-empty base64url segments,
//!    decoded-segment size caps.
//! 2. **Header** — duplicate-key-free JSON; `alg` present, not `none`, not
//!    HMAC; no `crit` (we understand no critical headers); no `enc` (a JWE is
//!    not a JWT-SVID); `typ`, if present, is `JWT` or `JOSE`; `kid`, if
//!    present, is a bounded string.
//! 3. **Claims peek** — duplicate-key-free JSON; `sub` is a syntactically
//!    valid SPIFFE ID; `aud` is present, non-empty, and contains the audience
//!    the caller asked about; `exp` is present and numeric; `iss`, if present,
//!    names the same trust domain as `sub`. This peek reads *unverified*
//!    bytes and is used only to select the candidate bundle — every claim is
//!    re-validated after signature verification, over the very same bytes the
//!    signature covers.
//! 4. **Authority admission** — *every* trust domain's complete authority set is
//!    put through
//!    [`validate_published_authorities`](super::validate_published_authorities)
//!    before any of it is scanned: count cap, trust-domain binding, duplicate
//!    `kid`, key-id / PEM / DER / key-type / key-size constraints, and total
//!    JWKS size. This is the *same* gate `FetchJWTBundles` uses, so validation
//!    can never accept material publication would have refused, and a malformed
//!    or oversized externally supplied SPIRE / federated bundle fails closed
//!    instead of driving an unbounded scan.
//! 5. **Authority selection** — the `sub` trust domain must have a bundle;
//!    `kid` must match exactly one authority in it (with no `kid`, the bundle
//!    must hold exactly one authority, otherwise the token is ambiguous).
//! 6. **Signature and time** — verified with the algorithm set the *authority*
//!    permits, never the token's own `alg` claim, so `alg` substitution and HMAC
//!    confusion cannot validate. That set is the authority's declared `alg` when
//!    it declared one, `RS256` alone for an undeclared RSA key, and otherwise
//!    what the key type can produce (see
//!    [`decoding_key_for_authority`](super::decoding_key_for_authority)). `exp`
//!    validation is mandatory; `nbf` is enforced when present; a future-dated
//!    `iat` is refused.
//!
//! No rejection reason ever contains token bytes, claim values, audiences, or
//! key material.

use std::collections::BTreeMap;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jsonwebtoken::{Algorithm, Validation};
use serde_json::{Map, Value};

use super::{
    JWT_SVID_CLOCK_SKEW_LEEWAY_SECS, JwtSvidError, MAX_JWT_BUNDLE_TRUST_DOMAINS,
    MAX_JWT_CLAIMS_JSON_BYTES, MAX_JWT_KEY_ID_BYTES, MAX_JWT_SVID_SEGMENT_BYTES,
    MAX_JWT_SVID_TOKEN_BYTES, decoding_key_for_authority, parse_strict_json_object,
    validate_audience_value, validate_published_authorities,
};
use crate::identity::ca::PublishedJwtAuthority;
use crate::identity::spiffe::{SpiffeId, TrustDomain};

/// The result of a successful `ValidateJWTSVID`.
///
/// Exactly the contract-defined surface: the validated SPIFFE ID and the
/// token's claim set. Nothing derived from the signing key, and nothing the
/// caller did not already hold.
#[derive(Debug, Clone)]
pub struct ValidatedJwtSvid {
    pub spiffe_id: SpiffeId,
    /// JSON-encoded claims (the `claims_json` field of
    /// `ValidateJWTSVIDResponse`).
    pub claims_json: Vec<u8>,
}

/// Validate a JWT-SVID against a set of per-trust-domain JWT authorities.
///
/// `bundles` must contain every trust domain the caller is willing to trust
/// (the local one plus any federated ones). An empty map means the active
/// backend publishes no JWT authority at all and is reported as
/// [`JwtSvidError::NoJwtAuthority`] so the RPC layer can answer
/// `UNIMPLEMENTED` rather than "invalid token".
pub fn validate_jwt_svid(
    token: &str,
    audience: &str,
    bundles: &BTreeMap<TrustDomain, Vec<PublishedJwtAuthority>>,
) -> Result<ValidatedJwtSvid, JwtSvidError> {
    validate_audience_value(audience)?;
    if bundles.is_empty() || bundles.values().all(|authorities| authorities.is_empty()) {
        return Err(JwtSvidError::NoJwtAuthority(
            "no JWT authority is available to validate against",
        ));
    }
    // Bound the number of trust domains before validating any of them: the
    // bundle map can come from an external SPIRE / federated source, and the
    // per-domain admission below is real work.
    if bundles.len() > MAX_JWT_BUNDLE_TRUST_DOMAINS {
        return Err(JwtSvidError::InvalidAuthority(
            "more JWT bundle trust domains than one response may carry",
        ));
    }
    // Hold EVERY domain's authority set to the same bounds `FetchJWTBundles`
    // enforces, before anything is scanned or used as a key. A malformed
    // federated bundle must fail the call closed rather than be quietly skipped
    // while the local domain still validates: an operator who configured that
    // federation expects it to be honoured or to fail loudly.
    for (trust_domain, authorities) in bundles {
        validate_published_authorities(trust_domain, authorities)?;
    }

    let (header_segment, claims_segment) = split_token(token)?;
    let header_bytes = decode_segment(header_segment)?;
    let claims_bytes = decode_segment(claims_segment)?;

    let header = parse_strict_json_object(&header_bytes)?;
    let key_id = check_header(&header)?;

    let claims = parse_strict_json_object(&claims_bytes)?;
    let spiffe_id = check_claims(&claims, audience)?;

    let trust_domain = spiffe_id.trust_domain();
    let authorities = bundles.get(trust_domain).ok_or(JwtSvidError::InvalidToken(
        "no JWT bundle is held for the token's trust domain",
    ))?;
    let authority = select_authority(authorities, key_id.as_deref(), trust_domain)?;

    let (decoding_key, allowed_algorithms) = decoding_key_for_authority(authority)?;
    let verified = verify(token, audience, &decoding_key, &allowed_algorithms)?;

    // The signature covers the header and claims segments byte for byte, so
    // the peeked claims are the verified claims. Re-assert the binding anyway:
    // a mismatch would mean the two parses disagreed, which must fail closed
    // rather than resolve in favour of either one.
    let verified_subject =
        verified
            .get("sub")
            .and_then(Value::as_str)
            .ok_or(JwtSvidError::InvalidToken(
                "verified claims have no subject",
            ))?;
    if verified_subject != spiffe_id.as_str() {
        return Err(JwtSvidError::InvalidToken(
            "verified subject does not match the presented subject",
        ));
    }

    let claims_json = serde_json::to_vec(&Value::Object(claims))
        .map_err(|e| JwtSvidError::Internal(format!("claims re-encoding failed: {e}")))?;
    if claims_json.len() > MAX_JWT_CLAIMS_JSON_BYTES {
        return Err(JwtSvidError::InvalidToken("claims document is too large"));
    }

    Ok(ValidatedJwtSvid {
        spiffe_id,
        claims_json,
    })
}

/// Split into `(header, claims)` after checking the JWS Compact Serialization
/// shape. The signature segment is validated for shape only — `jsonwebtoken`
/// consumes it.
fn split_token(token: &str) -> Result<(&str, &str), JwtSvidError> {
    if token.is_empty() {
        return Err(JwtSvidError::InvalidToken("token is empty"));
    }
    if token.len() > MAX_JWT_SVID_TOKEN_BYTES {
        return Err(JwtSvidError::InvalidToken("token is too large"));
    }
    let mut segments = token.split('.');
    let header = segments.next().unwrap_or_default();
    let claims = segments.next().unwrap_or_default();
    let signature = segments.next().unwrap_or_default();
    if segments.next().is_some() {
        return Err(JwtSvidError::InvalidToken(
            "token is not a three-part JWS compact serialization",
        ));
    }
    for segment in [header, claims, signature] {
        if segment.is_empty() {
            return Err(JwtSvidError::InvalidToken("token has an empty segment"));
        }
        if !segment
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return Err(JwtSvidError::InvalidToken(
                "token segment is not unpadded base64url",
            ));
        }
    }
    Ok((header, claims))
}

fn decode_segment(segment: &str) -> Result<Vec<u8>, JwtSvidError> {
    let decoded = URL_SAFE_NO_PAD
        .decode(segment.as_bytes())
        .map_err(|_| JwtSvidError::InvalidToken("token segment is not valid base64url"))?;
    if decoded.is_empty() || decoded.len() > MAX_JWT_SVID_SEGMENT_BYTES {
        return Err(JwtSvidError::InvalidToken(
            "token segment is empty or too large",
        ));
    }
    Ok(decoded)
}

/// Validate the JOSE header and return the `kid`, when present.
fn check_header(header: &Map<String, Value>) -> Result<Option<String>, JwtSvidError> {
    if header.contains_key("crit") {
        return Err(JwtSvidError::InvalidToken(
            "token declares critical headers this validator does not understand",
        ));
    }
    if header.contains_key("enc") {
        return Err(JwtSvidError::InvalidToken(
            "token is encrypted (JWE); a JWT-SVID is a signed JWS",
        ));
    }

    let alg = header
        .get("alg")
        .and_then(Value::as_str)
        .ok_or(JwtSvidError::InvalidToken("token header has no algorithm"))?;
    if alg.eq_ignore_ascii_case("none") {
        return Err(JwtSvidError::InvalidToken(
            "token declares the unsecured 'none' algorithm",
        ));
    }
    if alg.len() > 16 {
        return Err(JwtSvidError::InvalidToken(
            "token algorithm identifier is not recognised",
        ));
    }
    // Symmetric algorithms are never usable against a JWT bundle: a bundle
    // publishes public keys, so accepting HS* would let anyone who can read
    // the bundle forge a token. Refuse before touching any key material.
    if alg.eq_ignore_ascii_case("HS256")
        || alg.eq_ignore_ascii_case("HS384")
        || alg.eq_ignore_ascii_case("HS512")
    {
        return Err(JwtSvidError::InvalidToken(
            "token declares a symmetric algorithm; JWT-SVIDs must be asymmetrically signed",
        ));
    }

    if let Some(typ) = header.get("typ") {
        let typ = typ.as_str().ok_or(JwtSvidError::InvalidToken(
            "token header 'typ' is not a string",
        ))?;
        if !typ.eq_ignore_ascii_case("JWT") && !typ.eq_ignore_ascii_case("JOSE") {
            return Err(JwtSvidError::InvalidToken(
                "token header 'typ' is neither JWT nor JOSE",
            ));
        }
    }

    match header.get("kid") {
        None => Ok(None),
        Some(Value::String(kid)) => {
            if kid.is_empty() || kid.len() > MAX_JWT_KEY_ID_BYTES {
                return Err(JwtSvidError::InvalidToken(
                    "token key id is empty or too long",
                ));
            }
            if kid.chars().any(|c| c.is_control()) {
                return Err(JwtSvidError::InvalidToken(
                    "token key id contains control characters",
                ));
            }
            Ok(Some(kid.clone()))
        }
        Some(_) => Err(JwtSvidError::InvalidToken(
            "token header 'kid' is not a string",
        )),
    }
}

/// Validate the claim set's SPIFFE semantics and return the subject.
fn check_claims(claims: &Map<String, Value>, audience: &str) -> Result<SpiffeId, JwtSvidError> {
    let subject = claims
        .get("sub")
        .and_then(Value::as_str)
        .ok_or(JwtSvidError::InvalidToken("token has no subject claim"))?;
    let spiffe_id = SpiffeId::new(subject)
        .map_err(|_| JwtSvidError::InvalidToken("token subject is not a valid SPIFFE ID"))?;

    let audiences = claim_audiences(claims)?;
    if !audiences.iter().any(|value| value == audience) {
        return Err(JwtSvidError::InvalidToken(
            "token audience does not include the requested audience",
        ));
    }

    let exp = numeric_claim(claims, "exp")?
        .ok_or(JwtSvidError::InvalidToken("token has no expiry claim"))?;
    let now = chrono::Utc::now().timestamp();
    let leeway = JWT_SVID_CLOCK_SKEW_LEEWAY_SECS as i64;
    if let Some(iat) = numeric_claim(claims, "iat")?
        && iat > now.saturating_add(leeway)
    {
        return Err(JwtSvidError::InvalidToken("token is issued in the future"));
    }
    if let Some(nbf) = numeric_claim(claims, "nbf")?
        && exp <= nbf
    {
        return Err(JwtSvidError::InvalidToken(
            "token expires before it becomes valid",
        ));
    }

    // SPIFFE JWT-SVIDs do not define `iss`. If a token carries one anyway it
    // must not disagree with the subject's trust domain — a token that claims
    // one issuer while being anchored in another domain's bundle is exactly
    // the confusion this check exists to refuse.
    if let Some(issuer) = claims.get("iss") {
        let issuer = issuer.as_str().ok_or(JwtSvidError::InvalidToken(
            "token issuer claim is not a string",
        ))?;
        let trust_domain = spiffe_id.trust_domain();
        let issuer_matches = issuer == trust_domain.as_uri()
            || issuer == trust_domain.as_str()
            || SpiffeId::new(issuer).is_ok_and(|id| id.trust_domain() == trust_domain);
        if !issuer_matches {
            return Err(JwtSvidError::InvalidToken(
                "token issuer is not in the subject's trust domain",
            ));
        }
    }

    Ok(spiffe_id)
}

/// RFC 7519 §4.1.3: `aud` is either a string or an array of strings.
fn claim_audiences(claims: &Map<String, Value>) -> Result<Vec<String>, JwtSvidError> {
    match claims.get("aud") {
        None => Err(JwtSvidError::InvalidToken("token has no audience claim")),
        Some(Value::String(single)) => {
            validate_audience_value(single)
                .map_err(|_| JwtSvidError::InvalidToken("token audience is malformed"))?;
            Ok(vec![single.clone()])
        }
        Some(Value::Array(values)) => {
            if values.is_empty() || values.len() > super::MAX_JWT_SVID_AUDIENCES {
                return Err(JwtSvidError::InvalidToken(
                    "token audience list is empty or too large",
                ));
            }
            let mut audiences = Vec::with_capacity(values.len());
            for value in values {
                let value = value.as_str().ok_or(JwtSvidError::InvalidToken(
                    "token audience list contains a non-string entry",
                ))?;
                validate_audience_value(value)
                    .map_err(|_| JwtSvidError::InvalidToken("token audience is malformed"))?;
                audiences.push(value.to_string());
            }
            Ok(audiences)
        }
        Some(_) => Err(JwtSvidError::InvalidToken(
            "token audience claim is neither a string nor an array of strings",
        )),
    }
}

/// Read an integral NumericDate claim. A present-but-non-numeric (or
/// fractional-only, or out-of-range) value fails closed rather than being
/// treated as absent.
fn numeric_claim(claims: &Map<String, Value>, name: &str) -> Result<Option<i64>, JwtSvidError> {
    match claims.get(name) {
        None => Ok(None),
        Some(Value::Number(number)) => {
            if let Some(value) = number.as_i64() {
                Ok(Some(value))
            } else if let Some(value) = number.as_f64() {
                // NumericDate may legitimately be fractional; anything outside
                // the i64 range (or NaN / infinity) is refused rather than
                // saturated into a plausible-looking timestamp.
                // `i64::MAX as f64` rounds up to exactly 2^63. The upper bound
                // must therefore be exclusive: including it would admit the
                // out-of-range JSON integer 9223372036854775808 and Rust's
                // float-to-int cast would silently saturate it to `i64::MAX`.
                if value.is_finite() && (i64::MIN as f64..i64::MAX as f64).contains(&value) {
                    Ok(Some(value.trunc() as i64))
                } else {
                    Err(JwtSvidError::InvalidToken(
                        "token carries a time claim outside the representable range",
                    ))
                }
            } else {
                Err(JwtSvidError::InvalidToken(
                    "token carries a time claim outside the representable range",
                ))
            }
        }
        Some(_) => Err(JwtSvidError::InvalidToken(
            "token carries a non-numeric time claim",
        )),
    }
}

/// Pick the single authority that could have signed this token.
fn select_authority<'a>(
    authorities: &'a [PublishedJwtAuthority],
    key_id: Option<&str>,
    trust_domain: &TrustDomain,
) -> Result<&'a PublishedJwtAuthority, JwtSvidError> {
    if authorities.is_empty() {
        return Err(JwtSvidError::InvalidToken(
            "no JWT bundle is held for the token's trust domain",
        ));
    }
    let mut matched: Option<&PublishedJwtAuthority> = None;
    for authority in authorities {
        if authority.trust_domain != *trust_domain {
            // A bundle keyed under one trust domain must not carry an
            // authority stamped with another; refuse the whole lookup rather
            // than silently skipping the odd entry.
            return Err(JwtSvidError::InvalidAuthority(
                "a published JWT authority does not belong to its bundle's trust domain",
            ));
        }
        if let Some(key_id) = key_id
            && authority.key_id != key_id
        {
            continue;
        }
        if matched.is_some() {
            return Err(JwtSvidError::InvalidToken(
                "token does not identify which JWT authority signed it",
            ));
        }
        matched = Some(authority);
    }
    matched.ok_or(JwtSvidError::InvalidToken(
        "no JWT authority matches the token key id",
    ))
}

/// Signature + registered-claim verification.
fn verify(
    token: &str,
    audience: &str,
    decoding_key: &jsonwebtoken::DecodingKey,
    allowed_algorithms: &[Algorithm],
) -> Result<Map<String, Value>, JwtSvidError> {
    if allowed_algorithms.is_empty() {
        return Err(JwtSvidError::InvalidAuthority(
            "JWT authority key type permits no signature algorithm",
        ));
    }
    let mut validation = Validation::new(allowed_algorithms[0]);
    // Bound the accepted algorithms by the authority's key type, not by the
    // token header. `jsonwebtoken` rejects any header `alg` outside this list.
    validation.algorithms = allowed_algorithms.to_vec();
    validation.leeway = JWT_SVID_CLOCK_SKEW_LEEWAY_SECS;
    // Mandatory per the repository-wide JWT rule and the JWT-SVID standard.
    validation.validate_exp = true;
    validation.validate_nbf = true;
    validation.validate_aud = true;
    validation.set_audience(&[audience]);
    validation.set_required_spec_claims(&["exp", "aud", "sub"]);

    let decoded = jsonwebtoken::decode::<Value>(token, decoding_key, &validation)
        .map_err(map_decode_error)?;
    match decoded.claims {
        Value::Object(claims) => Ok(claims),
        _ => Err(JwtSvidError::InvalidToken("token claims are not an object")),
    }
}

/// Map a `jsonwebtoken` failure onto a fixed reason.
///
/// The library's own `Display` can embed serde detail derived from the token,
/// so it is never propagated.
fn map_decode_error(error: jsonwebtoken::errors::Error) -> JwtSvidError {
    use jsonwebtoken::errors::ErrorKind;
    match error.kind() {
        ErrorKind::ExpiredSignature => JwtSvidError::InvalidToken("token has expired"),
        ErrorKind::ImmatureSignature => JwtSvidError::InvalidToken("token is not yet valid"),
        ErrorKind::InvalidAudience => {
            JwtSvidError::InvalidToken("token audience does not include the requested audience")
        }
        ErrorKind::InvalidIssuer => JwtSvidError::InvalidToken("token issuer is not accepted"),
        ErrorKind::InvalidSubject => JwtSvidError::InvalidToken("token subject is not accepted"),
        ErrorKind::InvalidSignature => JwtSvidError::InvalidToken("token signature is invalid"),
        ErrorKind::InvalidAlgorithm | ErrorKind::InvalidAlgorithmName => {
            JwtSvidError::InvalidToken(
                "token algorithm is not the one the signing authority's key permits",
            )
        }
        ErrorKind::MissingRequiredClaim(_) => {
            JwtSvidError::InvalidToken("token is missing a required claim")
        }
        _ => JwtSvidError::InvalidToken("token could not be verified"),
    }
}
