//! SPIFFE JWT-SVID mint / validate / bundle support.
//!
//! This module owns everything the SPIFFE Workload API needs for the three
//! JWT RPCs (`FetchJWTSVID`, `FetchJWTBundles`, `ValidateJWTSVID`) while
//! staying independent of the gRPC layer so it can be unit-tested directly:
//!
//! - [`authority`] — [`LocalJwtAuthority`], the JWT signing authority used by
//!   CA backends that actually own signing material (today:
//!   [`crate::identity::ca::internal::InternalCa`]). It loads **operator-
//!   configured** ES256 signing material (so the trust domain's JWT authority
//!   survives a restart and is identical across replicas sharing that
//!   material), signs bounded short-lived JWT-SVIDs, and rotates with a
//!   documented, provable verification overlap.
//! - [`jwks`] — conversion between the CA-published
//!   [`PublishedJwtAuthority`](crate::identity::ca::PublishedJwtAuthority)
//!   (SPKI PEM + key id) and both a JWKS document and a `jsonwebtoken`
//!   [`DecodingKey`](jsonwebtoken::DecodingKey), plus the reverse direction
//!   (JWKS → SPKI PEM) used to consume an external SPIRE / federated JWT
//!   bundle.
//! - [`validate`] — fail-closed JWT-SVID validation.
//!
//! ## Security posture
//!
//! - **The subject is never caller-selected.** The Workload API server mints
//!   only for the attested workload identity; a caller-supplied
//!   `JWTSVIDRequest.spiffe_id` is accepted only when it is byte-equal to the
//!   attested SPIFFE ID.
//! - **Only asymmetric algorithms.** Ferrum mints ES256 and validates against
//!   the algorithm family implied by the *authority's own public key*, never
//!   the one advertised in the token header. `alg: none` cannot even be
//!   deserialized by `jsonwebtoken` (there is no `Algorithm::None`), and the
//!   HMAC family is never in an allowed set, so both HMAC substitution and
//!   algorithm confusion fail closed.
//! - **Errors never reflect hostile input.** Every rejection reason is a fixed
//!   `&'static str`; token bytes, claim values, and key material never appear
//!   in an error, a log line, or a `Debug` rendering.
//! - **Everything is bounded.** Audience count/size, token size, per-segment
//!   size, claim-document size, authority count, key-id size, PEM size, and
//!   the JWKS document itself all have hard caps checked before any parse or
//!   publication.
//! - **The same authority bounds gate publication *and* validation.** Every
//!   trust domain's complete authority set goes through
//!   [`validate_published_authorities`] before it is published in a JWT bundle
//!   *and* before it is scanned to select a verification key, so
//!   `ValidateJWTSVID` can never accept material `FetchJWTBundles` would have
//!   refused, and a hostile/oversized externally supplied bundle can never
//!   drive an unbounded scan.

pub mod authority;
pub mod jwks;
mod strict_json;
pub mod validate;

// `#[allow(unused_imports)]` on each re-export, matching `workload_api::mod`:
// the binary target compiles these modules directly, so a re-export consumed
// only from `tests/` (or only as a return type) is an unused import *there*
// even though the library surface needs it.
#[allow(unused_imports)]
pub use authority::{
    JwtSvidSigner, LocalJwtAuthority, LocalJwtAuthorityConfig, MintedJwtSvid, SharedJwtSvidSigner,
};
#[allow(unused_imports)]
pub use jwks::{
    authorities_from_jwks, decoding_key_for_authority, jwks_document, published_authority_key_id,
    validate_published_authorities,
};
#[allow(unused_imports)]
pub use validate::{ValidatedJwtSvid, validate_jwt_svid};

pub(crate) use strict_json::parse_strict_json_object;

/// Maximum number of audiences a single `FetchJWTSVID` request may name.
pub const MAX_JWT_SVID_AUDIENCES: usize = 32;
/// Maximum byte length of one audience value.
pub const MAX_JWT_SVID_AUDIENCE_BYTES: usize = 512;
/// Maximum accepted serialized JWT-SVID size. SPIFFE JWT-SVIDs are small;
/// anything larger is a resource-exhaustion attempt, not a real token.
pub const MAX_JWT_SVID_TOKEN_BYTES: usize = 8 * 1024;
/// Maximum decoded size of a single JOSE segment (header or claims).
pub const MAX_JWT_SVID_SEGMENT_BYTES: usize = 4 * 1024;
/// Maximum number of JWT authorities published for one trust domain.
pub const MAX_JWT_AUTHORITIES_PER_TRUST_DOMAIN: usize = 16;
/// Maximum byte length of a JWT authority key id (`kid`).
pub const MAX_JWT_KEY_ID_BYTES: usize = 256;
/// Maximum byte length of an authority's SPKI PEM document.
pub const MAX_JWT_PUBLIC_KEY_PEM_BYTES: usize = 8 * 1024;
/// Maximum serialized size of one trust domain's JWKS document.
pub const MAX_JWKS_DOCUMENT_BYTES: usize = 64 * 1024;
/// Maximum number of trust domains in one `FetchJWTBundles` response.
pub const MAX_JWT_BUNDLE_TRUST_DOMAINS: usize = 64;
/// Maximum serialized size of the claims document returned by
/// `ValidateJWTSVID`.
pub const MAX_JWT_CLAIMS_JSON_BYTES: usize = 8 * 1024;
/// Default JWT-SVID lifetime. Deliberately short — a JWT-SVID is a bearer
/// credential with no revocation channel.
pub const DEFAULT_JWT_SVID_TTL_SECS: u64 = 300;
/// Hard ceiling on JWT-SVID lifetime. Also the basis for the rotation
/// verification overlap: a token minted one instant before a rotation stays
/// verifiable for at most this long.
pub const MAX_JWT_SVID_TTL_SECS: u64 = 3600;
/// Clock-skew leeway applied to `exp` / `nbf` / `iat` validation and added on
/// top of [`MAX_JWT_SVID_TTL_SECS`] when computing the rotation overlap.
pub const JWT_SVID_CLOCK_SKEW_LEEWAY_SECS: u64 = 60;
/// Default lifetime of a local JWT signing key before it is rotated out.
///
/// **`0` — in-process time-based rotation is off by default**, and it is only
/// ever available to an *ephemeral* (dev/test) authority. Operator-configured
/// signing material is rotated **externally**, by supplying a new
/// `FERRUM_MESH_JWT_SIGNING_KEY_PEM` plus the outgoing key as
/// `FERRUM_MESH_JWT_PREVIOUS_SIGNING_KEY_PEM`. An in-process replacement for
/// configured material would be a *different random key per replica* that no
/// restart can reload, which is exactly the continuity this authority exists to
/// provide — see [`authority::LocalJwtAuthority`].
pub const DEFAULT_JWT_KEY_LIFETIME_SECS: u64 = 0;

/// Default lifetime of an **ephemeral** (dev/test) JWT signing key. Only
/// meaningful when [`authority::LocalJwtAuthorityConfig::allow_ephemeral_key`]
/// is set: a process-local key is already discontinuous across restart, so
/// rotating it in process costs nothing that was not already lost.
pub const DEFAULT_EPHEMERAL_JWT_KEY_LIFETIME_SECS: u64 = 24 * 3600;

/// The rotation verification overlap: how long a retired signing key stays
/// published after it is replaced.
///
/// Every minted token's lifetime is clamped to `max_ttl_secs`, so a token
/// minted one instant before a rotation is still within its permitted lifetime
/// for at most `max_ttl_secs + JWT_SVID_CLOCK_SKEW_LEEWAY_SECS`. A retired key
/// must therefore remain published for exactly that long, and **must not be
/// evicted earlier to satisfy a retention cap**.
pub fn rotation_overlap_secs(max_ttl_secs: u64) -> u64 {
    max_ttl_secs.saturating_add(JWT_SVID_CLOCK_SKEW_LEEWAY_SECS)
}

/// Number of retired-but-still-verifiable keys a scheduled rotation cadence can
/// produce, i.e. the retention cap a `key_lifetime_secs` schedule *requires*.
///
/// With rotations at `0, L, 2L, …` a key retired at `T - kL` is still inside its
/// overlap while `kL < overlap`, so at most `ceil(overlap / L)` retired keys are
/// simultaneously live. `0` for `key_lifetime_secs == 0` (time-based rotation
/// disabled — nothing is scheduled, so nothing accumulates).
///
/// This is the relationship that makes the overlap guarantee *provable*: as long
/// as `max_retained_keys >= required_retained_keys(...)`, a scheduled rotation
/// never needs to evict a key that could still validate a live token.
pub fn required_retained_keys(max_ttl_secs: u64, key_lifetime_secs: u64) -> u64 {
    if key_lifetime_secs == 0 {
        return 0;
    }
    rotation_overlap_secs(max_ttl_secs).div_ceil(key_lifetime_secs)
}

/// Shortest `key_lifetime_secs` whose required retention still fits inside
/// [`MAX_JWT_AUTHORITIES_PER_TRUST_DOMAIN`] (the active key occupies one slot,
/// leaving `MAX - 1` for retired ones).
///
/// A shorter lifetime cannot be honoured without either exceeding the published
/// authority cap or evicting a key that can still validate a live token, so it
/// is refused at construction rather than silently accepted.
pub fn min_key_lifetime_secs(max_ttl_secs: u64) -> u64 {
    let retained_slots = MAX_JWT_AUTHORITIES_PER_TRUST_DOMAIN.saturating_sub(1) as u64;
    if retained_slots == 0 {
        return u64::MAX;
    }
    rotation_overlap_secs(max_ttl_secs).div_ceil(retained_slots)
}

/// Errors raised by the JWT-SVID mint / validate / bundle paths.
///
/// Every variant except [`JwtSvidError::Internal`] carries a fixed
/// `&'static str`: rejection reasons must never echo caller-supplied token
/// bytes, claim values, audiences, or key material back to the caller.
/// `Internal` is only ever constructed from Ferrum-authored text.
#[derive(Debug, thiserror::Error)]
pub enum JwtSvidError {
    /// The request itself is malformed (audience list, requested subject,
    /// oversized input). Maps to gRPC `INVALID_ARGUMENT`.
    #[error("JWT-SVID request rejected: {0}")]
    InvalidRequest(&'static str),
    /// The presented token failed a structural, cryptographic, or claim
    /// check. Maps to gRPC `INVALID_ARGUMENT`.
    #[error("JWT-SVID rejected: {0}")]
    InvalidToken(&'static str),
    /// The caller asked for an identity it is not entitled to. Maps to gRPC
    /// `PERMISSION_DENIED`.
    #[error("JWT-SVID request denied: {0}")]
    Denied(&'static str),
    /// The active backend has no JWT signing authority at all. Maps to gRPC
    /// `UNIMPLEMENTED` — this is the honest "this backend cannot do JWT-SVID"
    /// signal, distinct from "there are zero trusted authorities".
    #[error("JWT-SVID unsupported: {0}")]
    NoJwtAuthority(&'static str),
    /// Published authority material is malformed or out of bounds and must
    /// not be republished. Maps to gRPC `INTERNAL`.
    #[error("JWT authority material rejected: {0}")]
    InvalidAuthority(&'static str),
    /// A rotation was refused because completing it would have evicted a
    /// retired key that can still validate a token inside its permitted
    /// lifetime. The current key stays active and every already-minted token
    /// stays verifiable, so refusing is strictly safer than rotating.
    #[error("JWT-SVID rotation refused: {0}")]
    RotationRefused(&'static str),
    /// The configured JWT signing material is unusable or absent where it is
    /// mandatory. Startup-only; never reachable from an RPC path.
    #[error("JWT-SVID signing material rejected: {0}")]
    InvalidSigningMaterial(&'static str),
    /// Ferrum-side failure. Maps to gRPC `INTERNAL`.
    #[error("JWT-SVID internal error: {0}")]
    Internal(String),
}

/// Validate and canonicalize a requested audience list.
///
/// SPIFFE Workload API §5.3: `FetchJWTSVID` requires at least one audience.
/// We additionally require every entry to be non-empty and free of control
/// characters, bound the count and each entry's length, and collapse exact
/// duplicates while preserving first-occurrence order so the minted `aud`
/// array is canonical.
pub fn canonical_audiences(requested: &[String]) -> Result<Vec<String>, JwtSvidError> {
    if requested.is_empty() {
        return Err(JwtSvidError::InvalidRequest(
            "at least one audience is required",
        ));
    }
    if requested.len() > MAX_JWT_SVID_AUDIENCES {
        return Err(JwtSvidError::InvalidRequest("too many audiences requested"));
    }
    let mut canonical: Vec<String> = Vec::with_capacity(requested.len());
    for audience in requested {
        validate_audience_value(audience)?;
        if !canonical.iter().any(|existing| existing == audience) {
            canonical.push(audience.clone());
        }
    }
    // Unreachable while `requested` is non-empty and every entry is accepted,
    // but keep the post-condition explicit: an empty `aud` array must never
    // be minted.
    if canonical.is_empty() {
        return Err(JwtSvidError::InvalidRequest(
            "at least one audience is required",
        ));
    }
    Ok(canonical)
}

/// Bounds and character checks shared by mint and validate.
pub fn validate_audience_value(audience: &str) -> Result<(), JwtSvidError> {
    if audience.is_empty() {
        return Err(JwtSvidError::InvalidRequest("audience must not be empty"));
    }
    if audience.len() > MAX_JWT_SVID_AUDIENCE_BYTES {
        return Err(JwtSvidError::InvalidRequest("audience is too long"));
    }
    if audience.trim().is_empty() {
        return Err(JwtSvidError::InvalidRequest(
            "audience must not be whitespace only",
        ));
    }
    if audience.chars().any(|c| c.is_control()) {
        return Err(JwtSvidError::InvalidRequest(
            "audience must not contain control characters",
        ));
    }
    Ok(())
}
