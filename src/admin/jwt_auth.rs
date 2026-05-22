//! JWT authentication for the Admin API.
//!
//! This module only *validates* admin JWTs — it never mints them. Operators
//! pre-sign tokens externally with the configured secret. Verification checks
//! all six required claims (`iss`, `sub`, `exp`, `iat`, `nbf`, `jti`) and
//! enforces a max-TTL to prevent very long-lived tokens.
//!
//! [`create_jwt_manager_from_env`] requires `FERRUM_ADMIN_JWT_SECRET` to be set
//! and non-empty, with a minimum length of
//! [`crate::config::types::MIN_JWT_SECRET_LENGTH`]; otherwise it returns
//! [`JwtError::VerificationFailed`]. The random-secret fallback used by
//! read-only file mode (so externally-crafted tokens can never validate) is
//! handled at the call site that constructs the admin state, not here.

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
}

/// JWT Configuration
#[derive(Debug, Clone)]
pub struct JwtConfig {
    pub secret: String,
    pub issuer: String,
    pub max_ttl_seconds: u64,
    pub algorithm: Algorithm,
}

impl Default for JwtConfig {
    fn default() -> Self {
        Self {
            secret: String::new(),
            issuer: "ferrum-edge".to_string(),
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

        // Decode and validate
        let token_data = decode::<AdminClaims>(token, &key, &validation)?;

        // Enforce max TTL: reject tokens with excessive or non-positive lifetimes
        if self.config.max_ttl_seconds > 0 {
            let ttl = token_data.claims.exp - token_data.claims.iat;
            if ttl <= 0 || ttl > self.config.max_ttl_seconds as i64 {
                return Err(jsonwebtoken::errors::Error::from(
                    jsonwebtoken::errors::ErrorKind::InvalidToken,
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
}

impl std::fmt::Debug for JwtError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            JwtError::MissingHeader => write!(f, "MissingHeader"),
            JwtError::InvalidHeaderFormat => write!(f, "InvalidHeaderFormat"),
            JwtError::VerificationFailed(msg) => write!(f, "VerificationFailed({})", msg),
        }
    }
}

impl std::fmt::Display for JwtError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let msg = match self {
            JwtError::MissingHeader => "Missing Authorization header",
            JwtError::InvalidHeaderFormat => "Invalid Authorization header format",
            JwtError::VerificationFailed(msg) => msg.as_str(),
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
        .ok_or_else(|| {
            JwtError::VerificationFailed(
                "FERRUM_ADMIN_JWT_SECRET must be set and non-empty".to_string(),
            )
        })?;

    if secret.len() < crate::config::types::MIN_JWT_SECRET_LENGTH {
        return Err(JwtError::VerificationFailed(format!(
            "FERRUM_ADMIN_JWT_SECRET must be at least {} characters (got {})",
            crate::config::types::MIN_JWT_SECRET_LENGTH,
            secret.len()
        )));
    }

    let issuer =
        resolve_ferrum_var("FERRUM_ADMIN_JWT_ISSUER").unwrap_or_else(|| "ferrum-edge".to_string());

    let max_ttl = resolve_ferrum_var("FERRUM_ADMIN_JWT_MAX_TTL")
        .and_then(|s| s.parse().ok())
        .unwrap_or(3600);

    let config = JwtConfig {
        secret,
        issuer,
        max_ttl_seconds: max_ttl,
        algorithm: Algorithm::HS256,
    };

    Ok(JwtManager::new(config))
}
