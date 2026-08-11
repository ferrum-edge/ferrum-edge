//! JWT signing authority for one trust domain.
//!
//! [`LocalJwtAuthority`] is the JWT half of a CA backend that actually owns
//! signing material. It is used by
//! [`InternalCa`](crate::identity::ca::internal::InternalCa); backends that
//! delegate issuance to an external agent (SPIRE) deliberately do **not**
//! construct one — see [`JwtSvidSigner`].
//!
//! ## Trust-domain continuity across restart and replicas
//!
//! A trust domain's JWT signing authority is **operator-configured material**,
//! not a per-process accident:
//! [`LocalJwtAuthorityConfig::signing_key_pem`] carries an ES256 (P-256)
//! private key and [`LocalJwtAuthorityConfig::retired_key_pems`] carries keys
//! that are published for verification only. Two instances handed the same
//! material publish the *same* `kid` and the *same* JWKS, and a restart keeps
//! every token it minted moments earlier verifiable.
//!
//! An **ephemeral, process-local** key is generated only when
//! [`LocalJwtAuthorityConfig::allow_ephemeral_key`] is explicitly set (dev and
//! test). With it unset and no configured material, construction fails closed
//! rather than silently minting tokens that no peer or restart can verify.
//!
//! ## Rotation: configured material rotates *externally*
//!
//! There are two postures, and they rotate by different mechanisms because only
//! one of them **can** rotate without destroying continuity.
//!
//! **Configured material (the production posture) is externally rotated.** A
//! replacement key generated inside one process would be a different random key
//! on every replica and would be lost on the next restart, so tokens minted from
//! it would validate nowhere else and nowhere later — the precise failure this
//! authority exists to prevent. Ferrum therefore never generates one:
//!
//! - `key_lifetime_secs` is **normalized to `0`** at construction for a
//!   configured authority (an explicitly nonzero value is additionally rejected
//!   at config-validation time, so an operator sees the misconfiguration rather
//!   than a silent downgrade), so [`LocalJwtAuthority::rotate_if_due`] is a
//!   permanent no-op;
//! - an explicit [`LocalJwtAuthority::rotate`] is **refused** with
//!   [`JwtSvidError::RotationRefused`].
//!
//! Rotation is instead a two-key rolling config change: the new primary goes in
//! `signing_key_pem`, the outgoing one in `retired_key_pems`. Configured retired
//! keys are published for verification for as long as they stay configured — not
//! for a process-relative window — so two replicas of one trust domain publish a
//! byte-identical JWKS at every instant and a restart republishes exactly the
//! same set. The operator drops the previous key from configuration once the
//! overlap ([`rotation_overlap_secs`]`(max_ttl_secs)`) has elapsed.
//!
//! **An ephemeral key may rotate in process**, because a process-local key is
//! already discontinuous across a restart and identical to no replica: rotating
//! it costs nothing that was not already lost. Reads go through a lock-free
//! [`ArcSwap`] snapshot; rotation is serialized by an async gate and never runs
//! on a request path. The replaced key is *retained for verification only* for
//! [`rotation_overlap_secs`]`(max_ttl_secs)`. Because every minted token's
//! lifetime is clamped to `max_ttl_secs`, a token minted one instant before a
//! rotation stays verifiable for its whole bounded lifetime, and a retired key
//! becomes unusable as soon as no token it signed can still be live.
//!
//! Retention is additionally capped at `max_retained_keys` entries, and the two
//! bounds are made *consistent* rather than left to collide:
//!
//! - construction refuses a `key_lifetime_secs` shorter than
//!   [`min_key_lifetime_secs`], because no cap within
//!   [`MAX_JWT_AUTHORITIES_PER_TRUST_DOMAIN`] could then hold every still-live
//!   key;
//! - construction raises `max_retained_keys` to
//!   [`required_retained_keys`]`(max_ttl, lifetime)` when it is configured
//!   lower, so the *scheduled* cadence provably never needs an eviction;
//! - a rotation that would nevertheless have to drop a key still inside its
//!   overlap (reachable only by driving [`LocalJwtAuthority::rotate`] manually,
//!   far faster than the schedule) is **refused** with
//!   [`JwtSvidError::RotationRefused`]. The active key stays active and every
//!   minted token stays verifiable — never the other way around.
//!
//! ## Key material
//!
//! Every private PEM exists only long enough for `jsonwebtoken` to copy it into
//! an [`EncodingKey`], and is held in a [`Zeroizing`] buffer until then. Neither
//! a private key, nor its source, nor a minted token appears in `Debug`,
//! `Display`, logs, or errors — only the public `kid`, which is by construction
//! published in the JWT bundle.
//!
//! **A retired key is not a key.** "Verification-only retention" is enforced by
//! the type system, not by convention: the retired set holds `RetainedPublicKey`
//! (`kid` + algorithm + SPKI public PEM) and there is no `EncodingKey` anywhere
//! in it. A configured previous private PEM is parsed only long enough to
//! validate it and derive that public metadata, and the private half is dropped
//! before construction returns; an ephemeral rotation likewise copies only the
//! outgoing key's public metadata, leaving its signing object with the
//! superseded state to be released. So a key the trust domain has rotated off
//! cannot sign in this process even by mistake.

use std::fmt;
use std::sync::Arc;

use arc_swap::ArcSwap;
use chrono::{DateTime, Utc};
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde::Serialize;
use tracing::{debug, info, warn};
use zeroize::Zeroizing;

use super::{
    DEFAULT_EPHEMERAL_JWT_KEY_LIFETIME_SECS, DEFAULT_JWT_KEY_LIFETIME_SECS,
    DEFAULT_JWT_SVID_TTL_SECS, JwtSvidError, MAX_JWT_AUTHORITIES_PER_TRUST_DOMAIN,
    MAX_JWT_SVID_TTL_SECS, canonical_audiences, jwks, min_key_lifetime_secs,
    required_retained_keys, rotation_overlap_secs,
};
use crate::identity::ca::PublishedJwtAuthority;
use crate::identity::spiffe::{SpiffeId, TrustDomain};

/// Algorithm Ferrum mints JWT-SVIDs with. ES256 keeps tokens small and is
/// supported by every SPIFFE consumer; it is asymmetric, so a JWT bundle
/// never carries anything a holder could sign with.
const JWT_SVID_SIGNING_ALG: Algorithm = Algorithm::ES256;

/// Default cap on retained verification-only keys (the active key plus this
/// many retired ones is the worst case published in a JWT bundle).
pub const DEFAULT_MAX_RETAINED_JWT_KEYS: usize = 3;

/// A JWT signing authority that can mint JWT-SVIDs for one trust domain.
///
/// Implemented by [`LocalJwtAuthority`]. A CA backend returns `Some` from
/// [`CertificateAuthority::jwt_signer`](crate::identity::ca::CertificateAuthority::jwt_signer)
/// only when it genuinely owns JWT signing material; the default is `None`,
/// which makes `FetchJWTSVID` fail closed with `UNIMPLEMENTED` rather than
/// inventing JWT trust for a backend that cannot supply it.
#[async_trait::async_trait]
pub trait JwtSvidSigner: Send + Sync + 'static {
    /// The trust domain this authority signs for. A mint request for any
    /// other trust domain must be refused.
    fn trust_domain(&self) -> &TrustDomain;

    /// Mint a JWT-SVID for `spiffe_id` targeting `audiences`.
    ///
    /// The caller is responsible for having *attested* `spiffe_id`; this
    /// method re-checks only that it belongs to this authority's trust
    /// domain. `ttl_secs == 0` selects the configured default; anything above
    /// the configured ceiling is clamped down, never up.
    fn mint(
        &self,
        spiffe_id: &SpiffeId,
        audiences: &[String],
        ttl_secs: u64,
    ) -> Result<MintedJwtSvid, JwtSvidError>;

    /// The authorities currently valid for verification: the active signing
    /// key plus every retired key still inside its rotation overlap.
    fn authorities(&self) -> Vec<PublishedJwtAuthority>;

    /// Monotonic generation counter, bumped on every rotation. Bundle streams
    /// use it to skip republishing an unchanged authority set.
    fn generation(&self) -> u64;

    /// Rotate the signing key if it has outlived its configured lifetime.
    ///
    /// Returns the new generation when a rotation happened. Driven from the
    /// background rotation task — key generation must never run on an RPC
    /// path.
    ///
    /// An authority built from operator-configured material never rotates in
    /// process and always answers `Ok(None)`; it is rotated by rolling new
    /// configuration. Only an ephemeral (dev/test) authority has a cadence.
    async fn rotate_if_due(&self) -> Result<Option<u64>, JwtSvidError>;
}

/// Shared handle to a JWT signing authority.
pub type SharedJwtSvidSigner = Arc<dyn JwtSvidSigner>;

/// A freshly minted JWT-SVID.
///
/// `token` is a bearer credential: the [`fmt::Debug`] impl redacts it, and it
/// must never be logged.
pub struct MintedJwtSvid {
    pub spiffe_id: SpiffeId,
    pub token: String,
    pub key_id: String,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

impl fmt::Debug for MintedJwtSvid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MintedJwtSvid")
            .field("spiffe_id", &self.spiffe_id)
            .field("token", &"<redacted>")
            .field("key_id", &self.key_id)
            .field("issued_at", &self.issued_at)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

/// Construction-time configuration for [`LocalJwtAuthority`].
///
/// The [`fmt::Debug`] impl reports only *whether* signing material was supplied
/// and how many retired keys came with it — never the material itself.
#[derive(Clone)]
pub struct LocalJwtAuthorityConfig {
    pub trust_domain: TrustDomain,
    /// Lifetime applied when a mint request asks for `0` seconds.
    pub default_ttl_secs: u64,
    /// Hard ceiling on minted JWT-SVID lifetime. Also the basis of the
    /// rotation overlap.
    pub max_ttl_secs: u64,
    /// How long an **ephemeral** signing key stays active before
    /// [`LocalJwtAuthority::rotate_if_due`] replaces it. `0` disables
    /// time-based rotation.
    ///
    /// Only meaningful together with [`Self::allow_ephemeral_key`]. For
    /// operator-configured material this is normalized to `0` at construction
    /// and in-process rotation is refused outright — see the module docs.
    pub key_lifetime_secs: u64,
    /// Upper bound on retained verification-only keys. Raised at construction
    /// to [`required_retained_keys`] when configured lower, so the scheduled
    /// rotation cadence can never need to evict a still-live key.
    pub max_retained_keys: usize,
    /// Operator-configured ES256 (P-256) private key, PKCS#8 or SEC1 PEM.
    ///
    /// This is the trust domain's *stable* signing identity: the same material
    /// on two replicas publishes the same `kid`, and a restart with the same
    /// material keeps previously minted tokens verifiable. Resolved through the
    /// ordinary `_VAULT` / `_AWS` / `_AZURE` / `_GCP` / `_FILE` secret suffixes
    /// before it reaches here.
    pub signing_key_pem: Option<Zeroizing<String>>,
    /// Keys published for **verification only**, in newest-first order.
    ///
    /// Set the previous primary here across a rotation so tokens it signed stay
    /// verifiable for their whole permitted lifetime while the new primary takes
    /// over. A configured entry is published for as long as it stays configured
    /// — deliberately **not** for a process-relative window, so two replicas of
    /// one trust domain publish a byte-identical JWKS at every instant and a
    /// restart republishes exactly the same set. The operator removes the entry
    /// once [`rotation_overlap_secs`]`(max_ttl_secs)` has elapsed since the
    /// rotation.
    pub retired_key_pems: Vec<Zeroizing<String>>,
    /// Permit generating an ephemeral, process-local signing key when no
    /// material is configured.
    ///
    /// Dev/test only, and never a default: an ephemeral key breaks trust-domain
    /// continuity across restart and diverges across replicas, so with this
    /// unset and nothing configured, construction fails closed.
    pub allow_ephemeral_key: bool,
}

impl fmt::Debug for LocalJwtAuthorityConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LocalJwtAuthorityConfig")
            .field("trust_domain", &self.trust_domain)
            .field("default_ttl_secs", &self.default_ttl_secs)
            .field("max_ttl_secs", &self.max_ttl_secs)
            .field("key_lifetime_secs", &self.key_lifetime_secs)
            .field("max_retained_keys", &self.max_retained_keys)
            .field("signing_key_pem", &self.signing_key_pem.is_some())
            .field("retired_key_pems", &self.retired_key_pems.len())
            .field("allow_ephemeral_key", &self.allow_ephemeral_key)
            .finish()
    }
}

impl LocalJwtAuthorityConfig {
    /// Defaults for a trust domain: 5 min tokens, 1 h ceiling, **no** in-process
    /// key rotation ([`DEFAULT_JWT_KEY_LIFETIME_SECS`] is `0`), 3 retained keys,
    /// **no** signing material and **no** ephemeral fallback — a caller must
    /// supply one or the other explicitly.
    pub fn new(trust_domain: TrustDomain) -> Self {
        Self {
            trust_domain,
            default_ttl_secs: DEFAULT_JWT_SVID_TTL_SECS,
            max_ttl_secs: MAX_JWT_SVID_TTL_SECS,
            key_lifetime_secs: DEFAULT_JWT_KEY_LIFETIME_SECS,
            max_retained_keys: DEFAULT_MAX_RETAINED_JWT_KEYS,
            signing_key_pem: None,
            retired_key_pems: Vec::new(),
            allow_ephemeral_key: false,
        }
    }

    /// Attach operator-configured signing material.
    pub fn with_signing_key_pem(mut self, pem: impl Into<String>) -> Self {
        self.signing_key_pem = Some(Zeroizing::new(pem.into()));
        self
    }

    /// Attach verification-only retired signing material, newest first.
    pub fn with_retired_key_pems<I, S>(mut self, pems: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.retired_key_pems = pems
            .into_iter()
            .map(|pem| Zeroizing::new(pem.into()))
            .collect();
        self
    }

    /// Dev/test escape hatch: generate a process-local key when nothing is
    /// configured. Documented as breaking restart/HA continuity.
    ///
    /// Because an ephemeral key has no continuity to preserve, in-process
    /// rotation is available to it; this sets the default ephemeral cadence
    /// ([`DEFAULT_EPHEMERAL_JWT_KEY_LIFETIME_SECS`]) unless the caller has
    /// already chosen one.
    pub fn allowing_ephemeral_key(mut self) -> Self {
        self.allow_ephemeral_key = true;
        if self.key_lifetime_secs == 0 {
            self.key_lifetime_secs = DEFAULT_EPHEMERAL_JWT_KEY_LIFETIME_SECS;
        }
        self
    }
}

/// One signing key and its published public half.
struct JwtSigningKey {
    key_id: String,
    algorithm: Algorithm,
    /// Private signing key. Never exposed, never rendered.
    encoding: EncodingKey,
    /// SPKI PEM of the public half — this is what goes into JWT bundles.
    public_key_pem: String,
}

/// The **public-only** representation of a key retained for verification.
///
/// Deliberately a distinct type from [`JwtSigningKey`] rather than a reuse of
/// it. "Verification-only retention" is a claim the documentation makes to
/// operators, and holding an `Arc<JwtSigningKey>` in the retired set would have
/// made it false: every configured previous private PEM would stay loaded as a
/// usable [`EncodingKey`] for the whole process lifetime, one `authorities()`
/// refactor away from signing with a key the trust domain has already rotated
/// off. There is no private material here to misuse — the private half of a
/// configured retired PEM is parsed only long enough to validate it and derive
/// this public metadata, then dropped.
struct RetainedPublicKey {
    key_id: String,
    algorithm: Algorithm,
    /// SPKI PEM of the public half — this is what goes into JWT bundles.
    public_key_pem: String,
}

impl RetainedPublicKey {
    /// Copy the public metadata of a key this process is retiring. Used on the
    /// ephemeral rotation path, which is the only place a former *active* key
    /// becomes a retired one in process; the [`EncodingKey`] is left behind with
    /// the old [`AuthorityState`] and released with it.
    fn from_signing_key(key: &JwtSigningKey) -> Self {
        Self {
            key_id: key.key_id.clone(),
            algorithm: key.algorithm,
            public_key_pem: key.public_key_pem.clone(),
        }
    }
}

/// A key kept for verification only.
struct RetiredJwtKey {
    key: Arc<RetainedPublicKey>,
    /// Instant after which the key is dropped from published authorities.
    ///
    /// `None` for **operator-configured** retired material: its publication
    /// window is owned by configuration, not by this process's uptime. Expiring
    /// it on a process-relative clock would make two replicas started at
    /// different times publish different JWKS for the same configuration, and a
    /// restart resurrect a key the previous process had already dropped.
    /// `Some(instant)` only for a key this process retired itself, which is
    /// reachable only on the ephemeral (dev/test) rotation path.
    verifiable_until: Option<DateTime<Utc>>,
}

impl RetiredJwtKey {
    /// Whether this key is still published at `now`.
    fn is_live_at(&self, now: DateTime<Utc>) -> bool {
        match self.verifiable_until {
            None => true,
            Some(until) => until > now,
        }
    }
}

/// Immutable snapshot swapped atomically on rotation.
struct AuthorityState {
    generation: u64,
    active: Arc<JwtSigningKey>,
    active_since: DateTime<Utc>,
    retired: Vec<RetiredJwtKey>,
}

/// Process-local JWT signing authority.
pub struct LocalJwtAuthority {
    trust_domain: TrustDomain,
    state: ArcSwap<AuthorityState>,
    /// Serializes rotation so two concurrent rotations cannot drop one
    /// another's retired set. Never taken on a mint / read path.
    rotate_gate: tokio::sync::Mutex<()>,
    default_ttl_secs: u64,
    max_ttl_secs: u64,
    key_lifetime_secs: u64,
    max_retained_keys: usize,
    /// True when the active key was generated in-process because no material
    /// was configured. Public information (a boolean posture flag), never key
    /// material.
    ///
    /// It is also the **rotation gate**: only an ephemeral authority may
    /// generate a replacement key in process. See the module docs.
    ephemeral_key: bool,
}

impl fmt::Debug for LocalJwtAuthority {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let state = self.state.load();
        f.debug_struct("LocalJwtAuthority")
            .field("trust_domain", &self.trust_domain)
            .field("generation", &state.generation)
            .field("active_key_id", &state.active.key_id)
            .field("retained_keys", &state.retired.len())
            .field("ephemeral_key", &self.ephemeral_key)
            .finish()
    }
}

impl LocalJwtAuthority {
    /// Load the configured signing material (or, when explicitly permitted,
    /// generate an ephemeral key) and build the authority.
    ///
    /// Fails closed on: absent material with no ephemeral opt-in, unusable /
    /// wrong-key-type material, a duplicate `kid` across the primary and retired
    /// keys, more retired keys than the published-authority cap allows, and a
    /// `key_lifetime_secs` too short for the overlap guarantee to be provable.
    ///
    /// For **configured** material `key_lifetime_secs` is normalized to `0`:
    /// in-process rotation is unavailable to that posture at all, so accepting a
    /// cadence here would only schedule a permanent no-op (or, worse, imply a
    /// rotation that never happens). The env-config layer additionally rejects
    /// an explicitly nonzero value so the operator is told rather than silently
    /// overridden.
    pub fn new(config: LocalJwtAuthorityConfig) -> Result<Self, JwtSvidError> {
        let default_ttl_secs = if config.default_ttl_secs == 0 {
            DEFAULT_JWT_SVID_TTL_SECS
        } else {
            config.default_ttl_secs
        };
        let max_ttl_secs = if config.max_ttl_secs == 0 {
            MAX_JWT_SVID_TTL_SECS
        } else {
            config.max_ttl_secs.min(MAX_JWT_SVID_TTL_SECS)
        };

        // Only an ephemeral authority can rotate in process, so only an
        // ephemeral authority has a cadence at all. Determined here, before the
        // cadence bounds below, because those bounds exist purely to make the
        // *scheduled* rotation's retention provable.
        let ephemeral_key = config.signing_key_pem.is_none() && config.allow_ephemeral_key;
        let key_lifetime_secs = if ephemeral_key {
            config.key_lifetime_secs
        } else {
            0
        };

        // Refuse a cadence whose required retention cannot fit inside the
        // published-authority cap. Accepting it would force a choice between
        // over-publishing and evicting a key that can still validate a live
        // token — the exact conflict this check exists to remove.
        if key_lifetime_secs > 0 && key_lifetime_secs < min_key_lifetime_secs(max_ttl_secs) {
            return Err(JwtSvidError::InvalidSigningMaterial(
                "JWT signing key lifetime is shorter than the rotation overlap permits; \
                 no retention cap within the published-authority limit could keep every \
                 still-verifiable key",
            ));
        }
        // The cap is *derived up* from the cadence rather than trusted: a
        // configured value below the requirement would make the overlap
        // guarantee unprovable.
        let required = required_retained_keys(max_ttl_secs, key_lifetime_secs) as usize;
        let max_retained_keys = config.max_retained_keys.max(required).max(1);
        if max_retained_keys > MAX_JWT_AUTHORITIES_PER_TRUST_DOMAIN.saturating_sub(1) {
            return Err(JwtSvidError::InvalidSigningMaterial(
                "JWT retained-key cap exceeds the published-authority limit for one trust domain",
            ));
        }

        // Validated here even though it is only consumed by `rotate_locked`:
        // an out-of-range overlap must be a startup failure, not a surprise on
        // the first rotation.
        let _ = overlap_duration(max_ttl_secs)?;
        let now = Utc::now();

        // Retired material first: it is published for verification only, and a
        // `kid` collision with the primary must be caught before either is
        // installed.
        if config.retired_key_pems.len() > max_retained_keys {
            return Err(JwtSvidError::InvalidSigningMaterial(
                "more retired JWT signing keys are configured than the retention cap allows",
            ));
        }
        let mut retired: Vec<RetiredJwtKey> = Vec::with_capacity(config.retired_key_pems.len());
        for pem in &config.retired_key_pems {
            // Validated exactly as a primary key is — same PEM bounds, same
            // P-256 requirement, same `kid` derivation — but only the *public*
            // half survives the call. A configured previous key must not remain
            // usable for signing anywhere in this process.
            let key = Arc::new(retained_public_key_from_pem(pem)?);
            if retired.iter().any(|entry| entry.key.key_id == key.key_id) {
                return Err(JwtSvidError::InvalidSigningMaterial(
                    "two configured retired JWT signing keys are the same key",
                ));
            }
            retired.push(RetiredJwtKey {
                key,
                // Configured material: published for as long as it is
                // configured. See `RetiredJwtKey::verifiable_until`.
                verifiable_until: None,
            });
        }

        // Kept in step with `ephemeral_key` above by construction: that flag is
        // exactly `signing_key_pem.is_none() && allow_ephemeral_key`, which is
        // the arm this match takes.
        let active = match config.signing_key_pem.as_ref() {
            Some(pem) => Arc::new(signing_key_from_pem(pem)?),
            None if config.allow_ephemeral_key => Arc::new(generate_signing_key()?),
            None => {
                return Err(JwtSvidError::InvalidSigningMaterial(
                    "no JWT signing key is configured for this trust domain; configure stable \
                     signing material so the authority survives restart and matches every replica",
                ));
            }
        };
        if retired
            .iter()
            .any(|entry| entry.key.key_id == active.key_id)
        {
            return Err(JwtSvidError::InvalidSigningMaterial(
                "the active JWT signing key is also configured as a retired key",
            ));
        }

        if ephemeral_key {
            // Loud, because this posture cannot serve a restart or a second
            // replica. Only the public key id is named.
            warn!(
                trust_domain = %config.trust_domain,
                key_id = %active.key_id,
                "JWT-SVID authority generated an EPHEMERAL process-local signing key: tokens it \
                 mints become unverifiable on restart and differ from every other replica. \
                 Dev/test only — configure stable JWT signing material for any shared or \
                 restart-surviving deployment"
            );
        } else {
            if config.key_lifetime_secs != 0 {
                // Normalized rather than honoured. Say so, so an operator who
                // set a cadence does not believe a rotation is scheduled.
                info!(
                    trust_domain = %config.trust_domain,
                    "configured JWT signing material rotates externally (new primary + previous \
                     verification key); the in-process JWT key lifetime is normalized to 0"
                );
            }
            info!(
                trust_domain = %config.trust_domain,
                key_id = %active.key_id,
                retained_keys = retired.len(),
                key_lifetime_secs,
                max_retained_keys,
                "JWT-SVID authority initialised from configured signing material"
            );
        }

        Ok(Self {
            trust_domain: config.trust_domain,
            state: ArcSwap::new(Arc::new(AuthorityState {
                generation: 1,
                active,
                active_since: now,
                retired,
            })),
            rotate_gate: tokio::sync::Mutex::new(()),
            default_ttl_secs: default_ttl_secs.min(max_ttl_secs),
            max_ttl_secs,
            key_lifetime_secs,
            max_retained_keys,
            ephemeral_key,
        })
    }

    /// Whether this authority's active key was generated in-process rather than
    /// loaded from configured material.
    ///
    /// Callers use this to refuse a posture that needs restart/HA continuity;
    /// it discloses nothing about the key itself.
    pub fn uses_ephemeral_key(&self) -> bool {
        self.ephemeral_key
    }

    /// Whether this authority may generate a replacement signing key in
    /// process.
    ///
    /// True only for an **ephemeral** (dev/test) authority. Operator-configured
    /// material is rotated externally, because an unpersisted random
    /// replacement would diverge across replicas and be lost on restart — see
    /// the module docs.
    pub fn allows_in_process_rotation(&self) -> bool {
        self.ephemeral_key
    }

    /// Replace the active signing key, retaining the previous one for
    /// verification through the overlap window.
    ///
    /// Returns the new generation. Key generation is deliberately done here
    /// and never on a mint path.
    ///
    /// **Refused outright for an operator-configured authority.** Generating an
    /// unpersisted replacement would give each replica a different signing key
    /// and lose the signer of every still-live token on the next restart, so the
    /// only safe in-process answer is to keep the configured key and let the
    /// operator roll new material. See the module docs for the two-key external
    /// rotation procedure.
    ///
    /// Also refuses with [`JwtSvidError::RotationRefused`] rather than evicting a
    /// retired key that can still validate a token inside its permitted
    /// lifetime. The scheduled cadence cannot reach that refusal (construction
    /// derives the cap from it); driving `rotate` manually far faster than the
    /// schedule can, and the safe answer there is to keep the current key.
    pub async fn rotate(&self) -> Result<u64, JwtSvidError> {
        let _gate = self.rotate_gate.lock().await;
        self.rotate_locked().await
    }

    /// Rotation body. The caller must already hold `rotate_gate`, so the
    /// read-modify-write of `state` below cannot interleave with another
    /// rotation.
    async fn rotate_locked(&self) -> Result<u64, JwtSvidError> {
        if !self.ephemeral_key {
            // The FIRST thing checked, before any state is read or any key is
            // generated: for configured material there is no correct in-process
            // rotation, so there is nothing to attempt.
            return Err(JwtSvidError::RotationRefused(
                "this JWT signing authority is operator-configured and rotates externally; \
                 generating a process-local replacement would publish a different key on every \
                 replica and lose the signer of every still-live token on restart. Roll a new \
                 primary key with the previous one configured for verification instead",
            ));
        }
        let now = Utc::now();
        let overlap = overlap_duration(self.max_ttl_secs)?;
        let previous = self.state.load_full();

        // Decide the retained set BEFORE generating a key, so a refusal costs
        // nothing and leaves no orphaned material.
        let mut retained: Vec<RetiredJwtKey> = Vec::with_capacity(self.max_retained_keys);
        retained.push(RetiredJwtKey {
            // Public metadata only: the outgoing key's `EncodingKey` stays with
            // the superseded `AuthorityState` and is released with it, so a
            // retired key is never a signing capability.
            key: Arc::new(RetainedPublicKey::from_signing_key(&previous.active)),
            verifiable_until: Some(now + overlap),
        });
        for entry in &previous.retired {
            if !entry.is_live_at(now) {
                // Genuinely expired: no token it signed can still be live, so
                // dropping it is not an eviction.
                continue;
            }
            if retained.len() >= self.max_retained_keys {
                // Dropping this key would strand tokens that are still inside
                // their permitted lifetime. Refuse the rotation instead — the
                // current key stays active and nothing already minted breaks.
                return Err(JwtSvidError::RotationRefused(
                    "rotating now would drop a retired JWT signing key that can still validate \
                     a token inside its permitted lifetime",
                ));
            }
            retained.push(RetiredJwtKey {
                key: Arc::clone(&entry.key),
                verifiable_until: entry.verifiable_until,
            });
            // NOTE: a `None` window (configured material) is carried through
            // unchanged, so an ephemeral rotation can never silently expire a
            // key configuration still publishes.
        }

        let fresh = Arc::new(generate_signing_key()?);
        let generation = previous.generation.saturating_add(1);
        let key_id = fresh.key_id.clone();
        self.state.store(Arc::new(AuthorityState {
            generation,
            active: fresh,
            active_since: now,
            retired: retained,
        }));
        info!(
            trust_domain = %self.trust_domain,
            generation,
            key_id = %key_id,
            "JWT-SVID signing key rotated"
        );
        Ok(generation)
    }

    /// Whether the active key has outlived `key_lifetime_secs`.
    fn rotation_due(&self, state: &AuthorityState) -> bool {
        if self.key_lifetime_secs == 0 {
            return false;
        }
        let age = Utc::now()
            .signed_duration_since(state.active_since)
            .num_seconds();
        // A configured cadence is a `u64`. Casting it to `i64` would turn a
        // value above `i64::MAX` negative and make a brand-new key appear due
        // immediately. Convert the non-negative observed age instead: a clock
        // step backwards is not evidence that the key has reached its cadence,
        // and every `u64` setting remains representable for comparison.
        u64::try_from(age).is_ok_and(|age| age >= self.key_lifetime_secs)
    }

    /// Key id of the active signing key. Public information (it is the `kid`
    /// of every token this authority currently mints).
    pub fn active_key_id(&self) -> String {
        self.state.load().active.key_id.clone()
    }

    /// Everything this authority retains for a retired key: its `kid` and its
    /// SPKI public PEM, newest first.
    ///
    /// This is the whole of the retained representation — `RetainedPublicKey`
    /// has no other field, and in particular no `EncodingKey` — so the accessor
    /// is both the diagnostic surface and the introspection seam tests use to
    /// pin "verification-only" as a structural property rather than a promise.
    /// Both values are public by construction: they are exactly what the JWT
    /// bundle publishes.
    pub fn retained_public_material(&self) -> Vec<(String, String)> {
        let state = self.state.load();
        state
            .retired
            .iter()
            .map(|entry| (entry.key.key_id.clone(), entry.key.public_key_pem.clone()))
            .collect()
    }

    fn clamp_ttl(&self, requested: u64) -> u64 {
        let ttl = if requested == 0 {
            self.default_ttl_secs
        } else {
            requested
        };
        ttl.min(self.max_ttl_secs).max(1)
    }
}

#[async_trait::async_trait]
impl JwtSvidSigner for LocalJwtAuthority {
    fn trust_domain(&self) -> &TrustDomain {
        &self.trust_domain
    }

    fn mint(
        &self,
        spiffe_id: &SpiffeId,
        audiences: &[String],
        ttl_secs: u64,
    ) -> Result<MintedJwtSvid, JwtSvidError> {
        if spiffe_id.trust_domain() != &self.trust_domain {
            return Err(JwtSvidError::Denied(
                "SPIFFE ID is not in this authority's trust domain",
            ));
        }
        // Re-validate rather than trust the caller: this is the last gate
        // before an audience reaches a signed token.
        let audiences = canonical_audiences(audiences)?;
        let ttl = self.clamp_ttl(ttl_secs);

        let now = Utc::now();
        let lifetime = chrono::Duration::try_seconds(ttl as i64).ok_or_else(|| {
            JwtSvidError::Internal("JWT-SVID lifetime is out of range".to_string())
        })?;
        let expires_at = now + lifetime;

        let state = self.state.load();
        let key = Arc::clone(&state.active);
        drop(state);

        let mut header = Header::new(key.algorithm);
        header.typ = Some("JWT".to_string());
        header.kid = Some(key.key_id.clone());

        let claims = JwtSvidClaims {
            sub: spiffe_id.as_str(),
            aud: &audiences,
            exp: expires_at.timestamp(),
            iat: now.timestamp(),
            nbf: now.timestamp(),
            jti: random_token_id()?,
        };

        let token = jsonwebtoken::encode(&header, &claims, &key.encoding)
            // The error can carry serialization detail; keep it fixed so no
            // claim value can be reflected out of the mint path.
            .map_err(|_| JwtSvidError::Internal("JWT-SVID signing failed".to_string()))?;

        debug!(
            spiffe_id = %spiffe_id,
            key_id = %key.key_id,
            audiences = audiences.len(),
            ttl_secs = ttl,
            "minted JWT-SVID"
        );

        Ok(MintedJwtSvid {
            spiffe_id: spiffe_id.clone(),
            token,
            key_id: key.key_id.clone(),
            issued_at: now,
            expires_at,
        })
    }

    fn authorities(&self) -> Vec<PublishedJwtAuthority> {
        let state = self.state.load();
        let now = Utc::now();
        let mut published = Vec::with_capacity(1 + state.retired.len());
        published.push(PublishedJwtAuthority {
            trust_domain: self.trust_domain.clone(),
            key_id: state.active.key_id.clone(),
            public_key_pem: state.active.public_key_pem.clone(),
            // Ferrum's own authorities always declare their algorithm: we know
            // exactly what they sign with, so leaving it unstated would only
            // widen what a verifier accepts.
            declared_alg: Some(state.active.algorithm),
        });
        for entry in &state.retired {
            if entry.is_live_at(now) {
                published.push(PublishedJwtAuthority {
                    trust_domain: self.trust_domain.clone(),
                    key_id: entry.key.key_id.clone(),
                    public_key_pem: entry.key.public_key_pem.clone(),
                    declared_alg: Some(entry.key.algorithm),
                });
            }
        }
        published
    }

    fn generation(&self) -> u64 {
        self.state.load().generation
    }

    async fn rotate_if_due(&self) -> Result<Option<u64>, JwtSvidError> {
        // Configured material has no in-process cadence at all (construction
        // normalizes `key_lifetime_secs` to 0). Checked explicitly as well as
        // implicitly so a future caller that sets the field directly still gets
        // a silent no-op rather than a scheduled refusal every tick.
        if !self.ephemeral_key || self.key_lifetime_secs == 0 {
            return Ok(None);
        }
        // Cheap unlocked pre-check so the common "nothing due" tick never
        // contends the gate. It is advisory only — the authoritative check
        // happens below, under the gate.
        {
            let state = self.state.load();
            if !self.rotation_due(&state) {
                return Ok(None);
            }
        }

        let _gate = self.rotate_gate.lock().await;
        // RE-CHECK under the gate. Two callers can both observe the same due
        // state before either takes the gate; without this the second one would
        // rotate a key the first had just installed, burning a retention slot
        // and halving the effective key lifetime for one observation.
        {
            let state = self.state.load();
            if !self.rotation_due(&state) {
                return Ok(None);
            }
        }
        self.rotate_locked().await.map(Some)
    }
}

/// SPIFFE JWT-SVID claim set.
///
/// `sub` is the SPIFFE ID and `aud` / `exp` are required by the JWT-SVID
/// standard. `iat` / `nbf` bound the token at the front, and `jti` gives each
/// token a unique identity so a relying party can detect replay.
///
/// `iss` is deliberately **not** minted: the SPIFFE JWT-SVID standard does not
/// define one, and validators key trust off the `sub` trust domain plus the
/// bundle the key came from.
#[derive(Serialize)]
struct JwtSvidClaims<'a> {
    sub: &'a str,
    aud: &'a [String],
    exp: i64,
    iat: i64,
    nbf: i64,
    jti: String,
}

/// The rotation overlap as a `chrono::Duration`.
fn overlap_duration(max_ttl_secs: u64) -> Result<chrono::Duration, JwtSvidError> {
    chrono::Duration::try_seconds(rotation_overlap_secs(max_ttl_secs) as i64).ok_or_else(|| {
        JwtSvidError::Internal("JWT-SVID rotation overlap is out of range".to_string())
    })
}

/// Maximum accepted private-key PEM size. An ES256 PKCS#8 key is a few hundred
/// bytes; anything larger is a misconfiguration or a resource-exhaustion
/// attempt, not a signing key.
const MAX_JWT_SIGNING_KEY_PEM_BYTES: usize = 8 * 1024;

/// Load an operator-configured ES256 signing key.
///
/// Accepted material is a **single** P-256 private key PEM (PKCS#8
/// `PRIVATE KEY` or SEC1 `EC PRIVATE KEY`). Every rejection reason is a fixed
/// string that names no part of the material and no source path: the caller's
/// error surface is startup diagnostics, and a key or its provenance must not
/// reach it. Anything other than P-256 is refused rather than signed with under
/// a mislabelled `alg`.
fn signing_key_from_pem(pem: &Zeroizing<String>) -> Result<JwtSigningKey, JwtSvidError> {
    if pem.trim().is_empty() {
        return Err(JwtSvidError::InvalidSigningMaterial(
            "configured JWT signing key PEM is empty",
        ));
    }
    if pem.len() > MAX_JWT_SIGNING_KEY_PEM_BYTES {
        return Err(JwtSvidError::InvalidSigningMaterial(
            "configured JWT signing key PEM is too large",
        ));
    }
    let key_pair = rcgen::KeyPair::from_pem(pem).map_err(|_| {
        JwtSvidError::InvalidSigningMaterial(
            "configured JWT signing key is not a usable private key PEM",
        )
    })?;
    if !key_pair.is_compatible(&rcgen::PKCS_ECDSA_P256_SHA256) {
        return Err(JwtSvidError::InvalidSigningMaterial(
            "configured JWT signing key is not an ECDSA P-256 key; JWT-SVIDs are minted ES256",
        ));
    }
    signing_key_from_key_pair(&key_pair)
        .map_err(|_| JwtSvidError::InvalidSigningMaterial("configured JWT signing key is unusable"))
}

/// Load an operator-configured **retired** key for verification only.
///
/// Held to exactly the same admission rules as an active key
/// ([`signing_key_from_pem`]) — a retired entry is published in the JWT bundle,
/// so material Ferrum would refuse to sign with must not be republished as
/// trusted either — but it produces no [`EncodingKey`]. The `rcgen::KeyPair` is
/// the only thing that ever holds the private half, and it is dropped when this
/// function returns.
fn retained_public_key_from_pem(
    pem: &Zeroizing<String>,
) -> Result<RetainedPublicKey, JwtSvidError> {
    if pem.trim().is_empty() {
        return Err(JwtSvidError::InvalidSigningMaterial(
            "configured JWT signing key PEM is empty",
        ));
    }
    if pem.len() > MAX_JWT_SIGNING_KEY_PEM_BYTES {
        return Err(JwtSvidError::InvalidSigningMaterial(
            "configured JWT signing key PEM is too large",
        ));
    }
    let key_pair = rcgen::KeyPair::from_pem(pem).map_err(|_| {
        JwtSvidError::InvalidSigningMaterial(
            "configured JWT signing key is not a usable private key PEM",
        )
    })?;
    if !key_pair.is_compatible(&rcgen::PKCS_ECDSA_P256_SHA256) {
        return Err(JwtSvidError::InvalidSigningMaterial(
            "configured JWT signing key is not an ECDSA P-256 key; JWT-SVIDs are minted ES256",
        ));
    }
    let public_key_pem = key_pair.public_key_pem();
    let key_id = jwks::published_authority_key_id(&public_key_pem)?;
    Ok(RetainedPublicKey {
        key_id,
        algorithm: JWT_SVID_SIGNING_ALG,
        public_key_pem,
    })
}

/// Generate an ephemeral ES256 signing key. Dev/test only — see
/// [`LocalJwtAuthorityConfig::allow_ephemeral_key`].
fn generate_signing_key() -> Result<JwtSigningKey, JwtSvidError> {
    let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).map_err(|e| {
        JwtSvidError::Internal(format!("JWT-SVID signing key generation failed: {e}"))
    })?;
    signing_key_from_key_pair(&key_pair)
}

/// Derive the public half, the RFC 7638 thumbprint key id, and a signing key
/// from a validated P-256 key pair.
///
/// The `kid` is the thumbprint of the *public key*, so the same configured
/// material always yields the same `kid` — that identity is what makes restart
/// and multi-replica continuity observable to a relying party.
fn signing_key_from_key_pair(key_pair: &rcgen::KeyPair) -> Result<JwtSigningKey, JwtSvidError> {
    let public_key_pem = key_pair.public_key_pem();
    let key_id = jwks::published_authority_key_id(&public_key_pem)?;

    // Held zeroized and dropped as soon as `jsonwebtoken` has taken its own
    // copy — nothing else in the process ever sees the private PEM.
    let private_key_pem = Zeroizing::new(key_pair.serialize_pem());
    let encoding = EncodingKey::from_ec_pem(private_key_pem.as_bytes())
        .map_err(|_| JwtSvidError::Internal("JWT-SVID signing key is unusable".to_string()))?;
    drop(private_key_pem);

    Ok(JwtSigningKey {
        key_id,
        algorithm: JWT_SVID_SIGNING_ALG,
        encoding,
        public_key_pem,
    })
}

/// 128 bits of CSPRNG output, base64url-encoded, used as `jti`.
fn random_token_id() -> Result<String, JwtSvidError> {
    use crate::fips::backend::rand::SecureRandom;
    use base64::Engine as _;

    let rng = crate::fips::backend::rand::SystemRandom::new();
    let mut buf = [0u8; 16];
    rng.fill(&mut buf)
        .map_err(|_| JwtSvidError::Internal("JWT-SVID token id generation failed".to_string()))?;
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(buf))
}
