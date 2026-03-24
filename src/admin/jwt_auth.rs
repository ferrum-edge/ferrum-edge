//! Enhanced JWT authentication for Admin API
//! Supports ISS claim validation, TTL enforcement, and token generation

use jsonwebtoken::{
    Algorithm, DecodingKey, TokenData, Validation, decode, errors::Error as JwtEncodeError,
};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

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
            issuer: "ferrum-gateway".to_string(),
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

        // Enforce max TTL: reject tokens with excessive lifetimes
        if self.config.max_ttl_seconds > 0 {
            let ttl = token_data.claims.exp - token_data.claims.iat;
            if ttl > self.config.max_ttl_seconds as i64 {
                return Err(jsonwebtoken::errors::Error::from(
                    jsonwebtoken::errors::ErrorKind::InvalidToken,
                ));
            }
        }

        Ok(token_data)
    }

    /// Extract token from Authorization header
    pub fn extract_token_from_header(auth_header: &str) -> Option<String> {
        if !auth_header.starts_with("Bearer ") {
            return None;
        }
        Some(auth_header[7..].to_string())
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

/// Create JWT manager from environment variables
pub fn create_jwt_manager_from_env() -> Result<JwtManager, JwtError> {
    let secret = std::env::var("FERRUM_ADMIN_JWT_SECRET")
        .map_err(|_| JwtError::VerificationFailed("FERRUM_ADMIN_JWT_SECRET not set".to_string()))?;

    let issuer =
        std::env::var("FERRUM_ADMIN_JWT_ISSUER").unwrap_or_else(|_| "ferrum-gateway".to_string());

    let max_ttl = std::env::var("FERRUM_ADMIN_JWT_MAX_TTL")
        .ok()
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
