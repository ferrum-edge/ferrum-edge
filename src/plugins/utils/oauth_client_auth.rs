//! OAuth 2.0 client-authentication wire mechanisms shared by the plugins that
//! authenticate *to* an authorization server: `oauth2_introspection` (RFC 7662
//! introspection endpoint) and `oidc_relying_party` (token, refresh, and
//! revocation endpoints).
//!
//! Only the mechanisms live here: the RFC 6749 §2.3.1 `client_secret_basic`
//! encoding, the supported `private_key_jwt` algorithm table, private-key
//! decoding, the RFC 7523 client-assertion builder, and the admission-time
//! signing probe. Each plugin keeps its own config parsing, field typing,
//! endpoint gating, and error grammar, and maps the typed errors returned here
//! onto its own diagnostics — introspection reports plugin-prefixed config
//! errors, the OIDC relying party answers runtime failures with a fixed JSON
//! body. Security fixes to these mechanisms used to land twice (issues #5015 /
//! #5032 for the signing probe, #5026 for the Basic form-encoding); keeping one
//! copy makes the next one land once.

use base64::Engine as _;
use http::HeaderValue;
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use serde_json::json;

/// RFC 7523 §2.2 `client_assertion_type` for a JWT bearer client assertion.
pub const CLIENT_ASSERTION_TYPE_JWT_BEARER: &str =
    "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

/// Lifetime (`exp - iat`) of every client assertion this gateway signs.
pub const CLIENT_ASSERTION_LIFETIME_SECS: i64 = 300;

/// `iss`/`sub`/`aud` of the throwaway assertion signed by
/// [`probe_client_assertion_signing`]. The probe never leaves the process.
const PROBE_ASSERTION_CLAIM: &str = "urn:ferrum-edge:client-assertion-probe";

/// Which step of building a `client_secret_basic` header failed. Both are
/// unreachable for `&str` input; callers still map them explicitly instead of
/// panicking.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BasicCredentialsError {
    /// `application/x-www-form-urlencoded` encoding of a component failed.
    FormEncode,
    /// The assembled `Basic …` value was not a valid header value.
    HeaderValue,
}

/// `application/x-www-form-urlencoded` encoding of one credential component,
/// as RFC 6749 §2.3.1 requires before the Basic join.
pub fn form_encode_component(value: &str) -> Option<String> {
    let mut serializer = url::form_urlencoded::Serializer::new(String::new());
    serializer.append_pair("value", value);
    serializer
        .finish()
        .strip_prefix("value=")
        .map(ToOwned::to_owned)
}

/// Build the RFC 6749 §2.3.1 `client_secret_basic` `Authorization` header.
///
/// The client identifier and secret are form-encoded FIRST and only then joined
/// with `:` and base64-encoded. Feeding the raw values to a generic HTTP Basic
/// encoder makes a legitimate credential containing `:`, `+`, `%`, a space, or a
/// non-ASCII character decode to the wrong pair at a conforming provider
/// (issue #5026). The returned value is marked sensitive so it is redacted from
/// `Debug` output and HPACK/QPACK indexing.
pub fn basic_authorization_header(
    client_id: &str,
    client_secret: &str,
) -> Result<HeaderValue, BasicCredentialsError> {
    let encoded_client_id =
        form_encode_component(client_id).ok_or(BasicCredentialsError::FormEncode)?;
    let encoded_client_secret =
        form_encode_component(client_secret).ok_or(BasicCredentialsError::FormEncode)?;
    let mut credential = String::with_capacity(
        encoded_client_id
            .len()
            .saturating_add(encoded_client_secret.len())
            .saturating_add(1),
    );
    credential.push_str(&encoded_client_id);
    credential.push(':');
    credential.push_str(&encoded_client_secret);
    let encoded = base64::engine::general_purpose::STANDARD.encode(credential.as_bytes());
    let mut value = String::with_capacity("Basic ".len().saturating_add(encoded.len()));
    value.push_str("Basic ");
    value.push_str(&encoded);
    let mut header = HeaderValue::from_bytes(value.as_bytes())
        .map_err(|_| BasicCredentialsError::HeaderValue)?;
    header.set_sensitive(true);
    Ok(header)
}

/// The `private_key_jwt_alg` names both plugins accept, mapped to their
/// signing algorithm. `None` for any other name. Typing of the config value
/// (string or not, default when absent) stays with each plugin.
pub fn private_key_jwt_algorithm(name: &str) -> Option<Algorithm> {
    match name {
        "RS256" => Some(Algorithm::RS256),
        "RS384" => Some(Algorithm::RS384),
        "RS512" => Some(Algorithm::RS512),
        "ES256" => Some(Algorithm::ES256),
        "ES384" => Some(Algorithm::ES384),
        "EdDSA" => Some(Algorithm::EdDSA),
        _ => None,
    }
}

/// Why [`decode_private_key`] refused a PEM. Never carries key material.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrivateKeyDecodeError {
    InvalidRsaPem,
    InvalidEcPem,
    InvalidEdDsaPem,
    /// The algorithm is outside [`private_key_jwt_algorithm`]'s table.
    UnsupportedAlgorithm,
}

/// Decode `pem` as the key family `alg` signs with.
///
/// A successful decode only proves the PEM is a well-formed key of that
/// family; [`probe_client_assertion_signing`] proves the pair can sign.
pub fn decode_private_key(alg: Algorithm, pem: &str) -> Result<EncodingKey, PrivateKeyDecodeError> {
    match alg {
        Algorithm::RS256 | Algorithm::RS384 | Algorithm::RS512 => {
            EncodingKey::from_rsa_pem(pem.as_bytes())
                .map_err(|_| PrivateKeyDecodeError::InvalidRsaPem)
        }
        Algorithm::ES256 | Algorithm::ES384 => EncodingKey::from_ec_pem(pem.as_bytes())
            .map_err(|_| PrivateKeyDecodeError::InvalidEcPem),
        Algorithm::EdDSA => EncodingKey::from_ed_pem(pem.as_bytes())
            .map_err(|_| PrivateKeyDecodeError::InvalidEdDsaPem),
        _ => Err(PrivateKeyDecodeError::UnsupportedAlgorithm),
    }
}

/// Sign an RFC 7523 §3 client assertion: `iss` = `sub` = `client_id`, the
/// caller-chosen `aud`, `iat` now, `exp` [`CLIENT_ASSERTION_LIFETIME_SECS`]
/// later, a fresh UUIDv4 `jti`, and `kid` in the header when configured.
///
/// The audience is a call-site decision: the OIDC relying party always uses the
/// token endpoint, introspection lets the operator override it.
pub fn build_client_assertion(
    client_id: &str,
    audience: &str,
    key: &EncodingKey,
    alg: Algorithm,
    kid: Option<&str>,
) -> Result<String, jsonwebtoken::errors::Error> {
    let now = chrono::Utc::now().timestamp();
    let mut header = Header::new(alg);
    header.kid = kid.map(ToOwned::to_owned);
    encode(
        &header,
        &json!({
            "iss": client_id,
            "sub": client_id,
            "aud": audience,
            "iat": now,
            "exp": now + CLIENT_ASSERTION_LIFETIME_SECS,
            "jti": uuid::Uuid::new_v4().to_string()
        }),
        key,
    )
}

/// Prove at admission that `key` can actually sign with `alg`.
///
/// `jsonwebtoken` binds the curve to the algorithm only when it signs, so a
/// P-384 key decodes cleanly under `ES256` and an undersized RSA modulus
/// decodes cleanly too; the mismatch otherwise surfaces on the first live
/// request (issues #5015, #5032). Signing one throwaway assertion is the
/// cheapest complete check: no I/O, discarded immediately, never sent.
pub fn probe_client_assertion_signing(
    key: &EncodingKey,
    alg: Algorithm,
) -> Result<(), jsonwebtoken::errors::Error> {
    build_client_assertion(PROBE_ASSERTION_CLAIM, PROBE_ASSERTION_CLAIM, key, alg, None).map(|_| ())
}
