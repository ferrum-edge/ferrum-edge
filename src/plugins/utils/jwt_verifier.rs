use std::collections::{HashMap, HashSet};

use base64::Engine;
use jsonwebtoken::{Algorithm, Header, Validation, decode, decode_header};
use serde_json::Value;

use super::jwks_store::{CachedJwk, JwksKeyStore};

pub struct JwtVerifyParams<'a> {
    pub issuer: Option<&'a str>,
    pub audiences: &'a [String],
    pub require_exp: bool,
    pub leeway_secs: u64,
    pub validate_nbf: bool,
}

/// Verify a JWT against a trusted JWKS snapshot.
///
/// Key selection is exclusively the JWT header `kid`:
/// - missing or empty `kid` fails closed
/// - a `kid` absent from the current trusted map fails closed
/// - a matching `kid` binds verification to that one key
///
/// There is no all-keys fallback. A token signed by a different published key
/// is rejected even when that other key would verify the signature. Failures
/// return `None` with no token, claim, key, or `kid` logging.
///
/// A token that names a *non-empty* `kid` the trusted map does not contain is
/// the observable shape of an identity-provider key rotation, so it asks the
/// store for one rate-limited out-of-band refresh. That request is never
/// awaited and this call still fails closed; a later request verifies once the
/// refreshed snapshot is published. A missing or empty `kid` triggers nothing —
/// it names no rotation and would otherwise be a free fetch-spray vector.
pub async fn verify_jwt_with_jwks(
    token: &str,
    store: &JwksKeyStore,
    params: &JwtVerifyParams<'_>,
) -> Option<Value> {
    let all_keys = store.trusted_keys()?;
    let header = decode_header(token).ok()?;
    let cached_key = match key_for_header_kid(&header, &all_keys) {
        Some(cached_key) => cached_key,
        None => {
            if header.kid.as_deref().is_some_and(|kid| !kid.is_empty()) {
                store.request_refresh_on_kid_miss();
            }
            return None;
        }
    };
    let validation = build_validation(cached_key.algorithm, params);
    decode_with_validation(token, cached_key, &validation, !params.audiences.is_empty())
}

/// Every asymmetric algorithm a [`JwksKeyStore`] key can bind verification
/// to. [`CompiledJwtValidation`] precomputes one [`Validation`] per entry.
pub const JWKS_VERIFICATION_ALGORITHMS: [Algorithm; 9] = [
    Algorithm::RS256,
    Algorithm::RS384,
    Algorithm::RS512,
    Algorithm::PS256,
    Algorithm::PS384,
    Algorithm::PS512,
    Algorithm::ES256,
    Algorithm::ES384,
    Algorithm::EdDSA,
];

/// Immutable verification policy compiled once per provider.
///
/// [`verify_jwt_with_jwks`] rebuilds a [`Validation`] — including copies of
/// the issuer, every configured audience, and the required-claim set — on
/// each call. Those inputs are provider configuration, so a request-path
/// caller that verifies against the same provider repeatedly compiles them
/// here once (at construction / reload) and borrows the result. The policy is
/// identical to [`verify_jwt_with_jwks`]: one [`Validation`] per admitted key
/// algorithm, each built by the same `build_validation`, so verification
/// stays bound to exactly the selected key's algorithm.
#[derive(Clone)]
pub struct CompiledJwtValidation {
    validations: Vec<(Algorithm, Validation)>,
    audiences_configured: bool,
}

impl CompiledJwtValidation {
    pub fn new(params: &JwtVerifyParams<'_>) -> Self {
        let validations = JWKS_VERIFICATION_ALGORITHMS
            .iter()
            .map(|algorithm| (*algorithm, build_validation(*algorithm, params)))
            .collect();
        Self {
            validations,
            audiences_configured: !params.audiences.is_empty(),
        }
    }

    fn for_algorithm(&self, algorithm: Algorithm) -> Option<&Validation> {
        self.validations
            .iter()
            .find(|(candidate, _)| *candidate == algorithm)
            .map(|(_, validation)| validation)
    }
}

/// [`verify_jwt_with_jwks`] against a precompiled provider policy.
///
/// Same `kid` binding, unknown-`kid` refresh trigger, algorithm binding, and
/// registered-claim shape checks; the only difference is that no per-call
/// [`Validation`] is built.
pub fn verify_jwt_with_compiled_validation(
    token: &str,
    store: &JwksKeyStore,
    compiled: &CompiledJwtValidation,
) -> Option<Value> {
    let all_keys = store.trusted_keys()?;
    let header = decode_header(token).ok()?;
    let cached_key = match key_for_header_kid(&header, &all_keys) {
        Some(cached_key) => cached_key,
        None => {
            if header.kid.as_deref().is_some_and(|kid| !kid.is_empty()) {
                store.request_refresh_on_kid_miss();
            }
            return None;
        }
    };
    let validation = compiled.for_algorithm(cached_key.algorithm)?;
    decode_with_validation(token, cached_key, validation, compiled.audiences_configured)
}

fn decode_with_validation(
    token: &str,
    cached_key: &CachedJwk,
    validation: &Validation,
    audiences_configured: bool,
) -> Option<Value> {
    decode::<Value>(token, &cached_key.decoding_key, validation)
        .ok()
        .map(|td| td.claims)
        .filter(issuer_claim_is_single_string)
        .filter(|claims| audience_claim_is_acceptable(claims, audiences_configured))
}

/// Re-check the registered `aud` claim at Ferrum's verified-claims boundary.
///
/// `jsonwebtoken` rejects a parsed `aud` string or string array that does not
/// match (or, with no audiences configured, any parsed `aud`), but it treats a
/// malformed value — `null`, a number, an object, or an array with non-string
/// members — as absent or unparsed and accepts the token. RFC 7519 §4.1.3
/// defines `aud` as a `StringOrURI` or an array of them, so:
///
/// - an absent `aud` is acceptable (presence is enforced through
///   `required_spec_claims` whenever audiences are configured);
/// - with no audiences configured, any present `aud` (whatever its shape) is
///   refused, because no acceptable audience exists;
/// - with audiences configured, only a string or a non-empty array of strings
///   is acceptable (matching is still `jsonwebtoken`'s job).
pub fn audience_claim_is_acceptable(claims: &Value, audiences_configured: bool) -> bool {
    match claims.get("aud") {
        None => true,
        Some(_) if !audiences_configured => false,
        Some(Value::String(_)) => true,
        Some(Value::Array(items)) => !items.is_empty() && items.iter().all(Value::is_string),
        Some(_) => false,
    }
}

/// Re-check the registered `iss` claim's shape at Ferrum's verified-claims
/// boundary.
///
/// RFC 7519 §4.1.1 defines `iss` as a single `StringOrURI`, so an array is not
/// a token that legitimately claims several issuers — it is a malformed claim.
/// `jsonwebtoken` nonetheless models a multi-valued issuer internally and
/// matches by set INTERSECTION, so `["https://issuer", "https://attacker"]`
/// satisfies an exactly configured `https://issuer` (issue #5522). Configuring
/// several *accepted* issuers is an operator decision about which issuers this
/// gateway trusts; it never licenses one token to claim more than one.
///
/// An absent claim is not this predicate's concern — presence is enforced
/// through `required_spec_claims` by `build_validation` whenever an issuer is
/// configured. Every other JSON shape (array, object, number, boolean, null)
/// fails closed.
pub fn issuer_claim_is_single_string(claims: &Value) -> bool {
    match claims.get("iss") {
        None => true,
        Some(value) => value.is_string(),
    }
}

/// Bind verification to the single trusted key named by the JWT header `kid`.
///
/// Missing, empty, and unknown identifiers return `None`. The identifier itself
/// is never logged.
fn key_for_header_kid<'a>(
    header: &Header,
    keys: &'a HashMap<String, CachedJwk>,
) -> Option<&'a CachedJwk> {
    let kid = header.kid.as_deref().filter(|kid| !kid.is_empty())?;
    keys.get(kid)
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
    // Build `required_spec_claims` additively. `jsonwebtoken`'s
    // `set_issuer`/`set_audience` reject only a *mismatching* claim — a
    // token that simply OMITS `iss`/`aud` is still accepted. When a caller
    // configures an issuer or audiences they intend those claims to be
    // mandatory, so insert them into `required_spec_claims` (the only
    // mechanism that enforces presence).
    let mut required: HashSet<String> = HashSet::new();
    if params.require_exp {
        required.insert("exp".to_string());
    }
    if let Some(issuer) = params.issuer {
        validation.set_issuer(&[issuer]);
        required.insert("iss".to_string());
    }
    if !params.audiences.is_empty() {
        validation.set_audience(params.audiences);
        required.insert("aud".to_string());
    }
    validation.required_spec_claims = required;
    // When no audiences are configured, `validation.aud` stays `None` and
    // jsonwebtoken's default `validate_aud = true` is kept. Tokens without
    // `aud` still pass; a token that carries `aud` is rejected because no
    // acceptable audience is configured (RFC 7519 §4.1.3). Do not set
    // `validate_aud = false` — that would let a token minted for another
    // service authenticate whenever the JWKS kid matches.
    validation
}
