//! JWT authentication for the Admin API.
//!
//! This module only *validates* admin JWTs — it never mints them. Operators
//! pre-sign tokens externally with the configured secret. Verification checks
//! all six required claims (`iss`, `sub`, `exp`, `iat`, `nbf`, `jti`) and
//! enforces a max-TTL to prevent very long-lived tokens.
//!
//! [`create_jwt_manager_from_env`] requires `FERRUM_ADMIN_JWT_SECRET` to be set
//! and non-empty, with a minimum length of
//! [`crate::config::types::MIN_JWT_SECRET_LENGTH`]. When the secret is unset
//! it returns [`JwtError::NotConfigured`]; when the secret or a
//! related setting (for example `FERRUM_ADMIN_JWT_MAX_TTL`) is present but
//! invalid it returns [`JwtError::VerificationFailed`]. Read-only file/mesh/
//! node_agent modes may generate a random secret only on `NotConfigured`, via
//! [`random_read_only_jwt_manager`]; any other error must fail startup.
//!
//! # Role ceiling (`FERRUM_ADMIN_JWT_VIEWER_SECRET`)
//!
//! An optional second HS256 verification secret whose tokens are capped at
//! [`AdminRole::Viewer`] whatever their `role` claim says. A process that only
//! needs to read configuration (drift detection, dashboards) is given this
//! secret and can then mint nothing that reaches `operator` or `admin`.
//!
//! The ceiling is a property of *which key verified the signature*, recorded as
//! [`VerifiedAdminToken::key_tier`] and applied when the request's
//! [`crate::admin::audit::AuditActor`] is built — the single place every route
//! reads its role from. A viewer-key token's `scope` claims grant nothing, and
//! its `sub` and `ns` are whatever its holder chose: the viewer secret is a
//! fleet-wide read credential, not a per-tenant or per-identity one. The tier
//! is never derived from a token header or claim:
//!
//! - both keys are pinned to HS256 (`Validation::new` sets the only accepted
//!   algorithm, so `none`, `HS384`/`HS512`, and asymmetric algorithms are
//!   refused before any signature check);
//! - the primary key is tried first, and the viewer key only when the primary
//!   reports a signature mismatch, so a token is accepted by exactly the key
//!   that signed it;
//! - the two secrets must differ (enforced here and in `EnvConfig`), so no
//!   signature can verify under both.
//!
//! A symmetric second secret was chosen over asymmetric (ES256/EdDSA or JWKS)
//! verification because the existing admin plane is HS256 end to end and
//! GitForgeOps-style clients already mint their own HS256 tokens: the ceiling
//! reuses that exact verification path (claims, issuer, audience, max TTL)
//! with no key parsing, JWKS fetching, or outbound HTTP on the admin plane.
//!
//! # Namespace ceiling (`FERRUM_ADMIN_JWT_VIEWER_NAMESPACES`)
//!
//! An optional comma-separated list that bounds which namespaces a viewer-key
//! token may read, whatever its `ns` claim or the `X-Ferrum-Namespace` header
//! says. Like the role ceiling it is a property of the verifying key: it is
//! attached to [`VerifiedAdminToken::namespace_ceiling`] only for
//! [`AdminKeyTier::Viewer`] tokens and carried on
//! [`crate::admin::audit::AuditActor`], where the admin dispatcher enforces it
//! on every namespace-scoped route, `GET /config/export`, and the
//! `/namespaces` registry, independently of
//! `FERRUM_ADMIN_REQUIRE_NAMESPACE_CLAIM`. Primary-key tokens are never
//! affected. Unset keeps the viewer key fleet-wide.

use jsonwebtoken::{
    Algorithm, DecodingKey, TokenData, Validation, decode, errors::Error as JwtEncodeError,
};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::Arc;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AdminRole {
    Viewer,
    Operator,
    Admin,
}

impl AdminRole {
    pub fn parse(value: &str) -> Result<Self, String> {
        match value {
            "viewer" => Ok(Self::Viewer),
            "operator" => Ok(Self::Operator),
            "admin" => Ok(Self::Admin),
            _ => Err(format!(
                "Invalid admin role claim '{}'; expected viewer, operator, or admin",
                value
            )),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Viewer => "viewer",
            Self::Operator => "operator",
            Self::Admin => "admin",
        }
    }

    pub fn allows(self, required: Self) -> bool {
        self >= required
    }

    /// The lower of `self` and `ceiling`.
    pub fn capped_at(self, ceiling: Self) -> Self {
        self.min(ceiling)
    }
}

/// Which verification key accepted an admin JWT's signature.
///
/// The tier, not any claim, bounds what the token may do. It is carried on
/// [`crate::admin::audit::AuditActor`] into authorization, log lines, and audit
/// records.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdminKeyTier {
    /// `FERRUM_ADMIN_JWT_SECRET`: the `role` and `scope` claims are honoured.
    Primary,
    /// `FERRUM_ADMIN_JWT_VIEWER_SECRET`: the role is capped at
    /// [`AdminRole::Viewer`] and `scope` claims grant nothing. Its holder can
    /// mint any `sub` and `ns`, so neither is an identity or tenancy boundary.
    Viewer,
}

impl AdminKeyTier {
    /// Stable log / audit label.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Primary => "primary",
            Self::Viewer => "viewer",
        }
    }

    /// Highest role a token verified by this key may exercise.
    pub fn role_ceiling(self) -> AdminRole {
        match self {
            Self::Primary => AdminRole::Admin,
            Self::Viewer => AdminRole::Viewer,
        }
    }

    /// Whether `scope` claims (for example `diagnostics:read`) are honoured.
    pub fn honours_scopes(self) -> bool {
        matches!(self, Self::Primary)
    }
}

/// JWT Claims for Admin API
#[derive(Debug, Serialize, Deserialize)]
pub struct AdminClaims {
    /// Issuer (who created the token)
    pub iss: String,
    /// Subject (who the token is for)
    pub sub: String,
    /// Issued at (when token was created)
    pub iat: i64,
    /// Not before (token is not valid before this time)
    pub nbf: i64,
    /// Expiration time (token expires after this)
    pub exp: i64,
    /// JWT ID (unique identifier for the token)
    pub jti: String,
    /// Additional claims
    #[serde(flatten)]
    pub additional: serde_json::Value,
}

impl AdminClaims {
    /// Effective admin role. The `role` claim is required so tokens fail closed
    /// when RBAC intent is absent.
    pub fn admin_role(&self) -> Result<AdminRole, String> {
        let Some(obj) = self.additional.as_object() else {
            return Err(
                "Missing admin role claim; expected viewer, operator, or admin".to_string(),
            );
        };
        match obj.get("role") {
            None => {
                Err("Missing admin role claim; expected viewer, operator, or admin".to_string())
            }
            Some(serde_json::Value::String(role)) => AdminRole::parse(role),
            Some(_) => Err(
                "Invalid admin role claim type; expected viewer, operator, or admin string"
                    .to_string(),
            ),
        }
    }

    /// Namespaces this token is authorized for, from the optional `ns` claim.
    ///
    /// Shares the parser with the CP/DP gRPC plane so both surfaces accept
    /// identical claim shapes (single string or array of strings). A missing
    /// claim yields `AllowedNamespaces::empty()`; malformed shapes are
    /// rejected (fail-closed) rather than treated as absent — a garbled
    /// tenancy claim must never widen access. Only *enforced* against the
    /// requested namespace when `FERRUM_ADMIN_REQUIRE_NAMESPACE_CLAIM=true`.
    pub fn allowed_namespaces(&self) -> Result<crate::grpc::auth::AllowedNamespaces, String> {
        crate::grpc::auth::parse_ns_claim(&self.additional)
    }

    /// Whether the optional `scope` claim grants `scope`.
    ///
    /// Accepts the OAuth 2.0 space-delimited string form (RFC 8693 §4.2) or
    /// an array of strings. A missing claim, any other shape, or a non-string
    /// array member grants nothing: a capability is never inferred from a
    /// malformed claim, and the admin `role` never implies a scope.
    pub fn grants_scope(&self, scope: &str) -> bool {
        match self.additional.get("scope") {
            Some(serde_json::Value::String(granted)) => {
                granted.split_ascii_whitespace().any(|s| s == scope)
            }
            Some(serde_json::Value::Array(granted)) => {
                granted.iter().any(|s| s.as_str() == Some(scope))
            }
            _ => false,
        }
    }
}

/// JWT Configuration
#[derive(Debug, Clone)]
pub struct JwtConfig {
    pub secret: String,
    pub issuer: String,
    /// Optional expected `aud` (audience) claim. When `Some`, verification
    /// requires the token to carry an `aud` claim that matches this value.
    /// When `None` (default), no audience is acceptable: tokens WITHOUT an
    /// `aud` claim are accepted, but tokens that DO carry `aud` are rejected
    /// (RFC 7519 §4.1.3 — a processor that does not identify itself with a
    /// value in `aud` MUST reject the JWT; jsonwebtoken's `validate_aud`
    /// default implements this). This is the pre-existing behavior and blocks
    /// cross-service token replay when a signing secret is reused.
    pub audience: Option<String>,
    pub max_ttl_seconds: u64,
    pub algorithm: Algorithm,
}

impl Default for JwtConfig {
    fn default() -> Self {
        Self {
            secret: String::new(),
            issuer: "ferrum-edge".to_string(),
            audience: None,
            max_ttl_seconds: 3600,
            algorithm: Algorithm::HS256,
        }
    }
}

/// A signature-verified admin JWT.
///
/// `key_tier` records which verification key accepted the signature.
/// Authorization must use [`VerifiedAdminToken::effective_role`] and
/// [`VerifiedAdminToken::grants_scope`] (or
/// [`crate::admin::audit::AuditActor::from_verified`]), never the raw `role` or
/// `scope` claims.
#[derive(Debug)]
pub struct VerifiedAdminToken {
    pub header: jsonwebtoken::Header,
    pub claims: AdminClaims,
    pub key_tier: AdminKeyTier,
    /// `FERRUM_ADMIN_JWT_VIEWER_NAMESPACES`, attached only to
    /// [`AdminKeyTier::Viewer`] tokens when it is configured. `None` for every
    /// primary-key token and whenever the ceiling is unset.
    pub namespace_ceiling: Option<ViewerNamespaceCeiling>,
}

impl VerifiedAdminToken {
    /// Highest role the verifying key allows.
    pub fn role_ceiling(&self) -> AdminRole {
        self.key_tier.role_ceiling()
    }

    /// The role this token may exercise: its `role` claim capped at the
    /// ceiling of the key that verified it. A missing or malformed `role`
    /// claim still fails closed.
    pub fn effective_role(&self) -> Result<AdminRole, String> {
        Ok(self.claims.admin_role()?.capped_at(self.role_ceiling()))
    }

    /// Whether the token grants `scope`. A viewer-key token grants no scope,
    /// whatever its `scope` claim says.
    pub fn grants_scope(&self, scope: &str) -> bool {
        self.key_tier.honours_scopes() && self.claims.grants_scope(scope)
    }

    /// Namespaces the token is authorized for: its `ns` claim, narrowed to
    /// [`Self::namespace_ceiling`] when one applies. Claim presence is kept
    /// as the token carried it, so a claim-less viewer-key token still reads
    /// as "no `ns` claim"; the ceiling itself is enforced separately. A
    /// malformed claim still fails closed.
    pub fn allowed_namespaces(&self) -> Result<crate::grpc::auth::AllowedNamespaces, String> {
        let claimed = self.claims.allowed_namespaces()?;
        Ok(match &self.namespace_ceiling {
            Some(ceiling) => ceiling.narrow(&claimed),
            None => claimed,
        })
    }
}

/// Name of the viewer-key namespace ceiling setting.
pub const ADMIN_JWT_VIEWER_NAMESPACES_ENV: &str = "FERRUM_ADMIN_JWT_VIEWER_NAMESPACES";

/// The namespaces a viewer-key token may read
/// (`FERRUM_ADMIN_JWT_VIEWER_NAMESPACES`).
///
/// Cheap to clone: the set is shared behind an `Arc`, because it is attached
/// to every verified viewer-key token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ViewerNamespaceCeiling {
    names: Arc<HashSet<String>>,
}

impl ViewerNamespaceCeiling {
    /// Parse the comma-separated setting.
    ///
    /// Fails closed: an empty value, an empty or whitespace-only entry (for
    /// example a doubled or trailing comma), a `*` wildcard, or a name that
    /// breaks the namespace naming rules is refused rather than skipped, since
    /// a silently dropped entry would change a security boundary without any
    /// signal. Entries are trimmed; duplicates collapse. Diagnostics carry the
    /// entry's 1-based position and the key-aware quoted entry, never the whole
    /// value.
    pub fn parse(raw: &str) -> Result<Self, String> {
        if raw.trim().is_empty() {
            return Err(format!(
                "{ADMIN_JWT_VIEWER_NAMESPACES_ENV} is set but lists no namespace; list at least \
                 one namespace, or unset it to leave viewer-key tokens fleet-wide"
            ));
        }
        let mut names = HashSet::new();
        for (index, segment) in raw.split(',').enumerate() {
            let position = index + 1;
            let entry = segment.trim();
            if entry.is_empty() {
                return Err(format!(
                    "{ADMIN_JWT_VIEWER_NAMESPACES_ENV} entry {position} is empty; remove the \
                     extra comma"
                ));
            }
            if entry == "*" {
                return Err(format!(
                    "{ADMIN_JWT_VIEWER_NAMESPACES_ENV} entry {position} is `*`; wildcards are \
                     not supported, unset the setting to leave viewer-key tokens fleet-wide"
                ));
            }
            if crate::config::types::validate_namespace(entry).is_err() {
                return Err(format!(
                    "Invalid {ADMIN_JWT_VIEWER_NAMESPACES_ENV} entry {position} {}: a namespace \
                     must be 1-{} characters, start with an alphanumeric character, and contain \
                     only alphanumerics, dots, underscores, or hyphens",
                    crate::startup::quoted_config_value(ADMIN_JWT_VIEWER_NAMESPACES_ENV, entry),
                    crate::config::types::MAX_NAMESPACE_LENGTH
                ));
            }
            names.insert(entry.to_string());
        }
        Ok(Self {
            names: Arc::new(names),
        })
    }

    /// Whether `namespace` is inside the ceiling.
    pub fn allows(&self, namespace: &str) -> bool {
        self.names.contains(namespace)
    }

    /// How many distinct namespaces the ceiling admits.
    pub fn len(&self) -> usize {
        self.names.len()
    }

    /// Whether the ceiling admits no namespace. [`Self::parse`] never builds
    /// one, so this is `false` for every configured ceiling.
    pub fn is_empty(&self) -> bool {
        self.names.is_empty()
    }

    /// Narrow a parsed `ns` claim to this ceiling.
    ///
    /// A present claim becomes `claim ∩ ceiling` (possibly empty, which
    /// authorizes nothing); an absent claim stays absent, because presence
    /// records what the token carried. The ceiling is enforced on its own for
    /// claim-less tokens, see [`crate::admin::audit::AuditActor`].
    pub fn narrow(
        &self,
        claimed: &crate::grpc::auth::AllowedNamespaces,
    ) -> crate::grpc::auth::AllowedNamespaces {
        if !claimed.is_present() {
            return claimed.clone();
        }
        let Some(claimed_names) = claimed.effective_namespaces() else {
            return crate::grpc::auth::AllowedNamespaces::claimed(HashSet::new());
        };
        let narrowed = claimed_names
            .iter()
            .filter(|name| self.allows(name))
            .cloned()
            .collect();
        crate::grpc::auth::AllowedNamespaces::claimed(narrowed)
    }
}

/// JWT Manager for Admin API
#[derive(Clone)]
pub struct JwtManager {
    config: JwtConfig,
    /// Optional `FERRUM_ADMIN_JWT_VIEWER_SECRET`: tokens it verifies are capped
    /// at [`AdminRole::Viewer`].
    viewer_secret: Option<String>,
    /// Optional `FERRUM_ADMIN_JWT_VIEWER_NAMESPACES`: the namespaces tokens
    /// verified by `viewer_secret` may read.
    viewer_namespace_ceiling: Option<ViewerNamespaceCeiling>,
}

impl JwtManager {
    /// Create new JWT manager
    pub fn new(config: JwtConfig) -> Self {
        Self {
            config,
            viewer_secret: None,
            viewer_namespace_ceiling: None,
        }
    }

    /// Add a role-ceiling verification secret: tokens signed with it are
    /// capped at [`AdminRole::Viewer`] whatever their `role` claim says.
    ///
    /// Refuses a secret shorter than
    /// [`crate::config::types::MIN_JWT_SECRET_LENGTH`] and one equal to the
    /// primary secret — identical keys would let a viewer-secret holder mint
    /// tokens the primary key accepts uncapped. Error text never carries
    /// either secret.
    pub fn with_viewer_secret(mut self, viewer_secret: String) -> Result<Self, JwtError> {
        if viewer_secret.len() < crate::config::types::MIN_JWT_SECRET_LENGTH {
            return Err(JwtError::VerificationFailed(format!(
                "FERRUM_ADMIN_JWT_VIEWER_SECRET must be at least {} characters (got {})",
                crate::config::types::MIN_JWT_SECRET_LENGTH,
                viewer_secret.len()
            )));
        }
        if viewer_secret == self.config.secret {
            return Err(JwtError::VerificationFailed(
                ADMIN_JWT_VIEWER_SECRET_EQUALS_PRIMARY_ERROR.to_string(),
            ));
        }
        self.viewer_secret = Some(viewer_secret);
        Ok(self)
    }

    /// Whether a role-ceiling viewer secret is configured.
    pub fn has_viewer_secret(&self) -> bool {
        self.viewer_secret.is_some()
    }

    /// Bound the namespaces viewer-key tokens may read
    /// (`FERRUM_ADMIN_JWT_VIEWER_NAMESPACES`). Primary-key tokens are never
    /// affected. Without a viewer secret there are no viewer-key tokens, so
    /// the ceiling has nothing to bound.
    pub fn with_viewer_namespace_ceiling(mut self, ceiling: ViewerNamespaceCeiling) -> Self {
        self.viewer_namespace_ceiling = Some(ceiling);
        self
    }

    /// The configured viewer-key namespace ceiling, if any.
    pub fn viewer_namespace_ceiling(&self) -> Option<&ViewerNamespaceCeiling> {
        self.viewer_namespace_ceiling.as_ref()
    }

    /// Key for `GET /config/export` credential fingerprints.
    ///
    /// Derived from the primary admin JWT secret only — never from
    /// `FERRUM_ADMIN_JWT_VIEWER_SECRET` — so the viewer-tier credential that
    /// the export is designed for cannot compute (and therefore cannot
    /// dictionary-test) a fingerprint. `None` when no secret is configured.
    pub(crate) fn config_export_fingerprint_key(
        &self,
    ) -> Option<crate::fips::approved::HmacSha256Key> {
        crate::admin::config_export::fingerprint_key(&self.config.secret)
    }

    /// Key for admin resource `ETag`s, derived from the admin JWT secret so
    /// every replica that accepts the same tokens issues the same tags. `None`
    /// when no secret is configured.
    pub(crate) fn resource_etag_key(&self) -> Option<crate::fips::approved::HmacSha256Key> {
        crate::admin::preconditions::etag_key(&self.config.secret)
    }

    /// Verify and decode a JWT token.
    ///
    /// The primary secret is tried first. Only when it reports a signature
    /// mismatch is the optional viewer secret tried, and a token it verifies
    /// carries [`AdminKeyTier::Viewer`]. Every other failure
    /// (wrong algorithm, expired, bad claims) is final: the viewer key is
    /// never a second chance for a token the primary key could parse.
    pub fn verify_token(&self, token: &str) -> Result<VerifiedAdminToken, JwtEncodeError> {
        let primary = self.verify_with_key(token, &self.config.secret, self.config.algorithm);
        let primary_error = match primary {
            Ok(data) => {
                return Ok(VerifiedAdminToken {
                    header: data.header,
                    claims: data.claims,
                    key_tier: AdminKeyTier::Primary,
                    namespace_ceiling: None,
                });
            }
            Err(error) => error,
        };
        let Some(viewer_secret) = self.viewer_secret.as_deref() else {
            return Err(primary_error);
        };
        if !matches!(
            primary_error.kind(),
            jsonwebtoken::errors::ErrorKind::InvalidSignature
        ) {
            return Err(primary_error);
        }
        // Pinned to HS256 regardless of the primary configuration: the ceiling
        // key must never accept another algorithm.
        let data = self.verify_with_key(token, viewer_secret, Algorithm::HS256)?;
        // The viewer secret's holder chooses `sub`, and it is rendered into
        // log lines next to `key_tier`. Refuse subjects that could forge or
        // flood those lines.
        if !is_acceptable_viewer_key_subject(&data.claims.sub) {
            return Err(jsonwebtoken::errors::Error::from(
                jsonwebtoken::errors::ErrorKind::InvalidToken,
            ));
        }
        Ok(VerifiedAdminToken {
            header: data.header,
            claims: data.claims,
            key_tier: AdminKeyTier::Viewer,
            namespace_ceiling: self.viewer_namespace_ceiling.clone(),
        })
    }

    /// Full verification of `token` under one HMAC key and one algorithm.
    fn verify_with_key(
        &self,
        token: &str,
        secret: &str,
        algorithm: Algorithm,
    ) -> Result<TokenData<AdminClaims>, JwtEncodeError> {
        let key = DecodingKey::from_secret(secret.as_bytes());

        // Configure validation with required claims. `Validation::new` makes
        // `algorithm` the only accepted `alg`, so the header cannot select a
        // different verifier.
        let mut validation = Validation::new(algorithm);
        validation.validate_exp = true; // Enable expiration check
        validation.validate_nbf = true; // Enable not-before check

        // Set required claims
        validation.required_spec_claims = {
            let mut claims = HashSet::new();
            claims.insert("iss".to_string());
            claims.insert("sub".to_string());
            claims.insert("exp".to_string());
            claims.insert("iat".to_string());
            claims.insert("nbf".to_string());
            claims.insert("jti".to_string());
            claims
        };

        // Validate issuer
        validation.set_issuer(&[&self.config.issuer]);

        // Optional audience enforcement. When an operator configures an
        // audience, the token MUST carry a matching `aud` claim: `set_audience`
        // rejects a *mismatching* claim, and adding `aud` to
        // `required_spec_claims` makes its *presence* mandatory (so a token that
        // simply omits `aud` is also rejected). When unset, we deliberately
        // KEEP jsonwebtoken's strict `validate_aud = true` default: tokens
        // without `aud` pass, but a token carrying `aud` is rejected because no
        // acceptable audience is configured (RFC 7519 §4.1.3). Do NOT set
        // `validate_aud = false` here — that would let a token minted for a
        // different service (aud=X) authenticate against the admin API whenever
        // the HS256 secret is shared, silently weakening the fail-closed
        // posture. Operators whose IdP always stamps `aud` must set
        // FERRUM_ADMIN_JWT_AUDIENCE to that value.
        if let Some(audience) = &self.config.audience {
            validation.set_audience(&[audience]);
            validation.required_spec_claims.insert("aud".to_string());
        }

        // Decode and validate
        let token_data = decode::<AdminClaims>(token, &key, &validation)?;

        // Enforce max TTL.
        //
        // # Contract
        //
        // `max_ttl_seconds == 0` is the intentional disable sentinel
        // (documented for `FERRUM_ADMIN_JWT_MAX_TTL`) and is the ONLY way to
        // turn the cap off; a value that cannot be represented as a JWT
        // `NumericDate` (i64 seconds) is a misconfiguration and fails closed.
        //
        // When the cap is enabled, `leeway` (jsonwebtoken's
        // `Validation::leeway`, default 60s — read from the struct so it can
        // never drift from the leeway applied to `exp`/`nbf`) is the SINGLE
        // accepted clock-skew allowance, and it is spent on the issuance
        // side. All four conditions must hold:
        //   1. `exp - iat` is positive and `<= max_ttl` (nominal lifetime);
        //   2. `iat <= now + leeway` — not issued in the future beyond skew;
        //   3. `exp - now <= max_ttl + leeway` — remaining lifetime at
        //      verifier time, carrying the one skew window so an issuer whose
        //      clock runs fast is not locked out of minting full-length
        //      tokens;
        //   4. `exp > now` — expiry re-evaluated against verifier time with
        //      NO additional grace. jsonwebtoken keeps accepting a token
        //      until `exp + leeway`; without this the same skew allowance
        //      would be counted a second time and real acceptance could reach
        //      `max_ttl + 2 * leeway`.
        //
        // Effective maximum real acceptance is therefore exactly
        // `max_ttl + leeway`. All arithmetic is saturating, so hostile
        // `i64::MIN`/`i64::MAX` claims are rejected by (1) rather than
        // overflowing. Keep `docs/configuration.md`, `ferrum.conf`,
        // `EnvConfig::admin_jwt_max_ttl`, `docs/admin_api.md`, and the
        // `openapi.yaml` `bearerAuth` description in sync with this list.
        if self.config.max_ttl_seconds > 0 {
            let Ok(max_ttl) = i64::try_from(self.config.max_ttl_seconds) else {
                // Unrepresentable positive value: invalid configuration, not
                // a disable request. Reject rather than clamping to
                // `i64::MAX`, which would silently turn a `u64::MAX` typo
                // into an effectively unlimited bound. Only signature-valid
                // tokens reach this point, so this warning is not
                // attacker-floodable; `EnvConfig::validate()` and
                // `create_jwt_manager_from_env()` reject the same value at
                // startup. Operators disable the cap with `0`, never with a
                // huge value.
                tracing::warn!(
                    configured_max_ttl = self.config.max_ttl_seconds,
                    max_supported = i64::MAX,
                    "FERRUM_ADMIN_JWT_MAX_TTL is not representable; rejecting all admin JWTs"
                );
                return Err(jsonwebtoken::errors::Error::from(
                    jsonwebtoken::errors::ErrorKind::InvalidToken,
                ));
            };
            // `leeway` is a u64 seconds count with a 60s default; a value
            // beyond i64 range saturates to the strictest representable
            // bound rather than wrapping negative.
            let leeway = i64::try_from(validation.leeway).unwrap_or(i64::MAX);
            let now = i64::try_from(jsonwebtoken::get_current_timestamp()).unwrap_or(i64::MAX);

            // (1) Nominal claim lifetime.
            let ttl = token_data.claims.exp.saturating_sub(token_data.claims.iat);
            if ttl <= 0 || ttl > max_ttl {
                return Err(jsonwebtoken::errors::Error::from(
                    jsonwebtoken::errors::ErrorKind::InvalidToken,
                ));
            }

            // (2) Issued-at in the future beyond accepted clock skew.
            if token_data.claims.iat > now.saturating_add(leeway) {
                return Err(jsonwebtoken::errors::Error::from(
                    jsonwebtoken::errors::ErrorKind::InvalidToken,
                ));
            }

            // (3) Remaining lifetime exceeds the configured maximum even
            // though `exp - iat` looked acceptable (future-shifted iat).
            let remaining = token_data.claims.exp.saturating_sub(now);
            if remaining > max_ttl.saturating_add(leeway) {
                return Err(jsonwebtoken::errors::Error::from(
                    jsonwebtoken::errors::ErrorKind::InvalidToken,
                ));
            }

            // (4) Expiry at verifier time with no grace, so the skew
            // allowance already granted by (2)/(3) is not counted twice.
            // RFC 7519 §4.1.4: the token must not be accepted on or after
            // `exp`.
            if token_data.claims.exp <= now {
                return Err(jsonwebtoken::errors::Error::from(
                    jsonwebtoken::errors::ErrorKind::ExpiredSignature,
                ));
            }
        }

        Ok(token_data)
    }

    /// Extract token from Authorization header
    pub fn extract_token_from_header(auth_header: &str) -> Option<String> {
        let mut parts = auth_header.split_whitespace();
        let scheme = parts.next()?;
        let token = parts.next()?;
        if parts.next().is_some() || !scheme.eq_ignore_ascii_case("Bearer") {
            return None;
        }
        Some(token.to_string())
    }

    /// Verify JWT from request
    pub fn verify_request(
        &self,
        auth_header: Option<&str>,
    ) -> Result<VerifiedAdminToken, JwtError> {
        let auth_header = auth_header.ok_or(JwtError::MissingHeader)?;
        let token =
            Self::extract_token_from_header(auth_header).ok_or(JwtError::InvalidHeaderFormat)?;

        self.verify_token(&token)
            .map_err(|e: JwtEncodeError| JwtError::VerificationFailed(e.to_string()))
    }
}

/// JWT Error types
pub enum JwtError {
    /// `FERRUM_ADMIN_JWT_SECRET` is unset. Read-only modes may
    /// generate a random secret on this variant only.
    NotConfigured,
    MissingHeader,
    InvalidHeaderFormat,
    VerificationFailed(String),
}

impl std::fmt::Debug for JwtError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            JwtError::NotConfigured => write!(f, "NotConfigured"),
            JwtError::MissingHeader => write!(f, "MissingHeader"),
            JwtError::InvalidHeaderFormat => write!(f, "InvalidHeaderFormat"),
            JwtError::VerificationFailed(msg) => write!(f, "VerificationFailed({})", msg),
        }
    }
}

impl std::fmt::Display for JwtError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let msg = match self {
            JwtError::NotConfigured => "FERRUM_ADMIN_JWT_SECRET is not set",
            JwtError::MissingHeader => "Missing Authorization header",
            JwtError::InvalidHeaderFormat => "Invalid Authorization header format",
            JwtError::VerificationFailed(msg) => msg.as_str(),
        };
        write!(f, "{}", msg)
    }
}

impl std::error::Error for JwtError {}

/// Parse `FERRUM_ADMIN_JWT_MAX_TTL` from env/`ferrum.conf`.
///
/// A present-but-invalid value is a misconfiguration of a security control, so
/// it fails instead of silently falling back to the default or to an
/// effectively unlimited cap. `0` remains the documented disable sentinel;
/// values above `i64::MAX` are not representable as a JWT `NumericDate` bound
/// and are rejected the same way `EnvConfig::validate()` rejects them.
fn admin_jwt_max_ttl_from_env() -> Result<u64, JwtError> {
    use crate::config::conf_file::resolve_ferrum_var;

    match resolve_ferrum_var("FERRUM_ADMIN_JWT_MAX_TTL") {
        Some(raw) => {
            let parsed: u64 = raw.trim().parse().map_err(|_| {
                JwtError::VerificationFailed(
                    "FERRUM_ADMIN_JWT_MAX_TTL must be a non-negative integer number of seconds; \
                     use 0 to disable the lifetime cap"
                        .to_string(),
                )
            })?;
            if i64::try_from(parsed).is_err() {
                return Err(JwtError::VerificationFailed(format!(
                    "FERRUM_ADMIN_JWT_MAX_TTL ({parsed}) exceeds the maximum supported value \
                     ({}); use 0 to disable the lifetime cap",
                    i64::MAX
                )));
            }
            Ok(parsed)
        }
        None => Ok(3600),
    }
}

/// Create JWT manager from environment variables and `ferrum.conf`.
///
/// Uses `resolve_ferrum_var()` so that `ferrum.conf` values are respected
/// when the corresponding environment variable is not set.
///
/// Returns [`JwtError::NotConfigured`] only when the secret is unset
/// and any explicitly supplied related JWT settings are valid. Present-but-
/// invalid settings (short secret, malformed max TTL) return
/// [`JwtError::VerificationFailed`] so call sites cannot treat operator
/// intent as "unset".
pub fn create_jwt_manager_from_env() -> Result<JwtManager, JwtError> {
    use crate::config::conf_file::resolve_ferrum_var;

    // Validate related settings before classifying the secret as unset so a
    // present-but-invalid `FERRUM_ADMIN_JWT_MAX_TTL` cannot be downgraded to
    // the read-only random-secret fallback.
    let max_ttl = admin_jwt_max_ttl_from_env()?;

    let secret = match resolve_ferrum_var("FERRUM_ADMIN_JWT_SECRET") {
        Some(secret) => secret,
        None => return Err(JwtError::NotConfigured),
    };

    if secret.len() < crate::config::types::MIN_JWT_SECRET_LENGTH {
        return Err(JwtError::VerificationFailed(format!(
            "FERRUM_ADMIN_JWT_SECRET must be at least {} characters (got {})",
            crate::config::types::MIN_JWT_SECRET_LENGTH,
            secret.len()
        )));
    }

    let issuer =
        resolve_ferrum_var("FERRUM_ADMIN_JWT_ISSUER").unwrap_or_else(|| "ferrum-edge".to_string());

    // Optional: when set (and non-empty), Admin API tokens must carry a
    // matching `aud` claim. Unset ⇒ audience is not validated.
    let audience = resolve_ferrum_var("FERRUM_ADMIN_JWT_AUDIENCE").filter(|s| !s.is_empty());

    let config = JwtConfig {
        secret,
        issuer,
        audience,
        max_ttl_seconds: max_ttl,
        algorithm: Algorithm::HS256,
    };

    with_viewer_secret_from_env(JwtManager::new(config))
}

/// Longest `sub` a viewer-key token may carry, in bytes.
pub const MAX_VIEWER_KEY_SUBJECT_BYTES: usize = 256;

/// Whether a viewer-key token's `sub` is acceptable: at most
/// [`MAX_VIEWER_KEY_SUBJECT_BYTES`] bytes and free of control characters.
/// Primary-key tokens are not subject to this rule; their subjects come from
/// whoever holds the primary secret.
pub fn is_acceptable_viewer_key_subject(sub: &str) -> bool {
    sub.len() <= MAX_VIEWER_KEY_SUBJECT_BYTES && !sub.chars().any(char::is_control)
}

/// Message for a viewer secret equal to the primary admin secret. Names both
/// settings and neither value.
pub const ADMIN_JWT_VIEWER_SECRET_EQUALS_PRIMARY_ERROR: &str = "FERRUM_ADMIN_JWT_VIEWER_SECRET must differ from FERRUM_ADMIN_JWT_SECRET; identical values \
     would let a viewer-secret holder mint tokens the primary key accepts without the viewer \
     role ceiling";

/// Attach `FERRUM_ADMIN_JWT_VIEWER_SECRET` and
/// `FERRUM_ADMIN_JWT_VIEWER_NAMESPACES` (from env/`ferrum.conf`) when set.
fn with_viewer_secret_from_env(manager: JwtManager) -> Result<JwtManager, JwtError> {
    use crate::config::conf_file::resolve_ferrum_var;

    let viewer_secret =
        resolve_ferrum_var("FERRUM_ADMIN_JWT_VIEWER_SECRET").filter(|s| !s.is_empty());
    let manager = match viewer_secret {
        Some(viewer_secret) => manager.with_viewer_secret(viewer_secret)?,
        None => manager,
    };
    match resolve_ferrum_var(ADMIN_JWT_VIEWER_NAMESPACES_ENV) {
        Some(raw) => {
            let parsed = ViewerNamespaceCeiling::parse(&raw);
            let ceiling = parsed.map_err(JwtError::VerificationFailed)?;
            if manager.has_viewer_secret() {
                tracing::info!(
                    namespaces = ceiling.len(),
                    "Admin viewer-key tokens are limited to FERRUM_ADMIN_JWT_VIEWER_NAMESPACES"
                );
            } else {
                tracing::warn!(
                    "FERRUM_ADMIN_JWT_VIEWER_NAMESPACES is set without \
                     FERRUM_ADMIN_JWT_VIEWER_SECRET; it has no effect until a viewer secret \
                     is configured"
                );
            }
            Ok(manager.with_viewer_namespace_ceiling(ceiling))
        }
        None => Ok(manager),
    }
}

/// The read-only-mode fallback for an unset `FERRUM_ADMIN_JWT_SECRET`
/// (`file`, `mesh`, `node_agent`): a random, unguessable primary secret, so no
/// externally minted token reaches `operator` or `admin`, plus
/// `FERRUM_ADMIN_JWT_VIEWER_SECRET` when configured so viewer-tier readers
/// still work. Call only on [`JwtError::NotConfigured`].
pub fn random_read_only_jwt_manager() -> Result<JwtManager, JwtError> {
    use crate::config::conf_file::resolve_ferrum_var;

    let random_secret = format!("{}{}", uuid::Uuid::new_v4(), uuid::Uuid::new_v4());
    let issuer =
        resolve_ferrum_var("FERRUM_ADMIN_JWT_ISSUER").unwrap_or_else(|| "ferrum-edge".to_string());
    let audience = resolve_ferrum_var("FERRUM_ADMIN_JWT_AUDIENCE").filter(|s| !s.is_empty());
    let manager = JwtManager::new(JwtConfig {
        secret: random_secret,
        issuer,
        audience,
        max_ttl_seconds: admin_jwt_max_ttl_from_env()?,
        algorithm: Algorithm::HS256,
    });
    with_viewer_secret_from_env(manager)
}
