//! JWT authentication for the Admin API.
//!
//! This module only *validates* admin JWTs — it never mints them. Operators
//! pre-sign tokens externally with the configured secret. Verification checks
//! all six required claims (`iss`, `sub`, `exp`, `iat`, `nbf`, `jti`) and
//! enforces a max-TTL to prevent very long-lived tokens.
//!
//! [`create_jwt_manager_from_env`] returns [`JwtError::NotConfigured`] when
//! `FERRUM_ADMIN_JWT_SECRET` is unset or empty. A present-but-invalid secret
//! (shorter than [`crate::config::types::MIN_JWT_SECRET_LENGTH`]) or malformed
//! `FERRUM_ADMIN_JWT_MAX_TTL` returns [`JwtError::VerificationFailed`]. The
//! random-secret fallback used by read-only file/mesh mode (so
//! externally-crafted tokens can never validate) must match only
//! [`JwtError::NotConfigured`] at the call site — never other JWT errors.

use jsonwebtoken::{
    Algorithm, DecodingKey, TokenData, Validation, decode, errors::Error as JwtEncodeError,
};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

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

/// JWT Manager for Admin API
#[derive(Clone)]
pub struct JwtManager {
    config: JwtConfig,
}

impl JwtManager {
    /// Create new JWT manager
    pub fn new(config: JwtConfig) -> Self {
        Self { config }
    }

    /// Verify and decode a JWT token
    pub fn verify_token(&self, token: &str) -> Result<TokenData<AdminClaims>, JwtEncodeError> {
        let key = DecodingKey::from_secret(self.config.secret.as_bytes());

        // Configure validation with required claims
        let mut validation = Validation::new(self.config.algorithm);
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
    ) -> Result<TokenData<AdminClaims>, JwtError> {
        let auth_header = auth_header.ok_or(JwtError::MissingHeader)?;
        let token =
            Self::extract_token_from_header(auth_header).ok_or(JwtError::InvalidHeaderFormat)?;

        self.verify_token(&token)
            .map_err(|e: JwtEncodeError| JwtError::VerificationFailed(e.to_string()))
    }
}

/// JWT Error types
pub enum JwtError {
    MissingHeader,
    InvalidHeaderFormat,
    VerificationFailed(String),
    /// `FERRUM_ADMIN_JWT_SECRET` is unset or empty. Read-only modes may mint a
    /// random local secret; writable modes must treat this as fatal.
    NotConfigured,
}

impl std::fmt::Debug for JwtError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            JwtError::MissingHeader => write!(f, "MissingHeader"),
            JwtError::InvalidHeaderFormat => write!(f, "InvalidHeaderFormat"),
            JwtError::VerificationFailed(msg) => write!(f, "VerificationFailed({})", msg),
            JwtError::NotConfigured => write!(f, "NotConfigured"),
        }
    }
}

impl std::fmt::Display for JwtError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let msg = match self {
            JwtError::MissingHeader => "Missing Authorization header",
            JwtError::InvalidHeaderFormat => "Invalid Authorization header format",
            JwtError::VerificationFailed(msg) => msg.as_str(),
            JwtError::NotConfigured => {
                "FERRUM_ADMIN_JWT_SECRET must be set and non-empty"
            }
        };
        write!(f, "{}", msg)
    }
}

impl std::error::Error for JwtError {}

/// Create JWT manager from environment variables and `ferrum.conf`.
///
/// Uses `resolve_ferrum_var()` so that `ferrum.conf` values are respected
/// when the corresponding environment variable is not set.
pub fn create_jwt_manager_from_env() -> Result<JwtManager, JwtError> {
    use crate::config::conf_file::resolve_ferrum_var;

    let secret = resolve_ferrum_var("FERRUM_ADMIN_JWT_SECRET")
        .filter(|s| !s.is_empty())
        .ok_or(JwtError::NotConfigured)?;

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

    // A present-but-invalid value is a misconfiguration of a security
    // control, so it fails startup instead of silently falling back to the
    // default or to an effectively unlimited cap. `0` remains the documented
    // disable sentinel; values above `i64::MAX` are not representable as a
    // JWT `NumericDate` bound and are rejected the same way
    // `EnvConfig::validate()` rejects them.
    let max_ttl = match resolve_ferrum_var("FERRUM_ADMIN_JWT_MAX_TTL").filter(|s| !s.is_empty()) {
        Some(raw) => {
            let parsed: u64 = raw.trim().parse().map_err(|_| {
                JwtError::VerificationFailed(format!(
                    "FERRUM_ADMIN_JWT_MAX_TTL must be a non-negative integer number of seconds \
                     (got '{raw}'); use 0 to disable the lifetime cap"
                ))
            })?;
            if i64::try_from(parsed).is_err() {
                return Err(JwtError::VerificationFailed(format!(
                    "FERRUM_ADMIN_JWT_MAX_TTL ({parsed}) exceeds the maximum supported value \
                     ({}); use 0 to disable the lifetime cap",
                    i64::MAX
                )));
            }
            parsed
        }
        None => 3600,
    };

    let config = JwtConfig {
        secret,
        issuer,
        audience,
        max_ttl_seconds: max_ttl,
        algorithm: Algorithm::HS256,
    };

    Ok(JwtManager::new(config))
}
