//! Tests for admin JWT authentication

use chrono::{Duration, Utc};
use ferrum_edge::admin::jwt_auth::{AdminClaims, AdminRole, JwtConfig, JwtError, JwtManager};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use serde_json::json;

fn test_jwt_config() -> JwtConfig {
    JwtConfig {
        secret: "test-secret".to_string(),
        issuer: "test-issuer".to_string(),
        max_ttl_seconds: 3600,
        algorithm: Algorithm::HS256,
    }
}

fn encode_json_claims(claims: serde_json::Value, secret: &str, algorithm: Algorithm) -> String {
    let header = Header::new(algorithm);
    let key = EncodingKey::from_secret(secret.as_bytes());
    encode(&header, &claims, &key).unwrap()
}

#[test]
fn test_jwt_verification() {
    let manager = JwtManager::new(test_jwt_config());

    // Create a test token manually (as a client would)
    let now = Utc::now();
    let claims = AdminClaims {
        iss: "test-issuer".to_string(),
        sub: "admin-user".to_string(),
        iat: now.timestamp(),
        nbf: now.timestamp(),
        exp: (now + Duration::seconds(1800)).timestamp(),
        jti: uuid::Uuid::new_v4().to_string(),
        additional: json!({"role": "admin"}),
    };

    let header = Header::new(Algorithm::HS256);
    let key = EncodingKey::from_secret("test-secret".as_bytes());
    let token = encode(&header, &claims, &key).unwrap();

    // Verify token
    let token_data = manager.verify_token(&token).unwrap();

    assert_eq!(token_data.claims.iss, "test-issuer");
    assert_eq!(token_data.claims.sub, "admin-user");
    assert_eq!(token_data.claims.additional["role"], "admin");
}

#[test]
fn test_authorization_header_extraction_is_case_insensitive_and_strict() {
    assert_eq!(
        JwtManager::extract_token_from_header("Bearer abc.def"),
        Some("abc.def".to_string())
    );
    assert_eq!(
        JwtManager::extract_token_from_header("bearer abc.def"),
        Some("abc.def".to_string())
    );
    assert_eq!(
        JwtManager::extract_token_from_header("BEARER   abc.def"),
        Some("abc.def".to_string())
    );
    assert_eq!(JwtManager::extract_token_from_header("Bearer "), None);
    assert_eq!(JwtManager::extract_token_from_header("Bearer"), None);
    assert_eq!(JwtManager::extract_token_from_header("Basic abc.def"), None);
    assert_eq!(
        JwtManager::extract_token_from_header("Bearer abc.def extra"),
        None
    );
}

#[test]
fn test_verify_request_maps_header_failures_and_accepts_lowercase_bearer() {
    let manager = JwtManager::new(test_jwt_config());
    let now = Utc::now();
    let claims = json!({
        "iss": "test-issuer",
        "sub": "admin-user",
        "iat": now.timestamp(),
        "nbf": now.timestamp(),
        "exp": (now + Duration::seconds(1800)).timestamp(),
        "jti": uuid::Uuid::new_v4().to_string(),
        "role": "admin",
    });
    let token = encode_json_claims(claims, "test-secret", Algorithm::HS256);
    let lowercase_header = format!("bearer {token}");

    assert!(manager.verify_request(Some(&lowercase_header)).is_ok());
    assert!(matches!(
        manager.verify_request(None),
        Err(JwtError::MissingHeader)
    ));
    assert!(matches!(
        manager.verify_request(Some("Basic abc.def")),
        Err(JwtError::InvalidHeaderFormat)
    ));
    assert!(matches!(
        manager.verify_request(Some("Bearer ")),
        Err(JwtError::InvalidHeaderFormat)
    ));
    assert!(matches!(
        manager.verify_request(Some("Bearer abc.def extra")),
        Err(JwtError::InvalidHeaderFormat)
    ));
    assert!(matches!(
        manager.verify_request(Some("Bearer not-a-jwt")),
        Err(JwtError::VerificationFailed(_))
    ));
}

#[test]
fn test_jwt_required_claims_are_enforced() {
    let manager = JwtManager::new(test_jwt_config());
    let now = Utc::now();
    let claims_without_jti = json!({
        "iss": "test-issuer",
        "sub": "admin-user",
        "iat": now.timestamp(),
        "nbf": now.timestamp(),
        "exp": (now + Duration::seconds(1800)).timestamp(),
        "role": "admin",
    });
    let token = encode_json_claims(claims_without_jti, "test-secret", Algorithm::HS256);

    assert!(
        manager.verify_token(&token).is_err(),
        "tokens missing required registered claims must be rejected"
    );
}

#[test]
fn test_jwt_not_before_and_algorithm_are_enforced() {
    let manager = JwtManager::new(test_jwt_config());
    let now = Utc::now();
    let future_nbf_claims = json!({
        "iss": "test-issuer",
        "sub": "admin-user",
        "iat": now.timestamp(),
        "nbf": (now + Duration::hours(1)).timestamp(),
        "exp": (now + Duration::hours(2)).timestamp(),
        "jti": uuid::Uuid::new_v4().to_string(),
        "role": "admin",
    });
    let future_nbf_token = encode_json_claims(future_nbf_claims, "test-secret", Algorithm::HS256);

    assert!(
        manager.verify_token(&future_nbf_token).is_err(),
        "tokens before their nbf time must be rejected"
    );

    let wrong_algorithm_claims = json!({
        "iss": "test-issuer",
        "sub": "admin-user",
        "iat": now.timestamp(),
        "nbf": now.timestamp(),
        "exp": (now + Duration::seconds(1800)).timestamp(),
        "jti": uuid::Uuid::new_v4().to_string(),
        "role": "admin",
    });
    let wrong_algorithm_token =
        encode_json_claims(wrong_algorithm_claims, "test-secret", Algorithm::HS384);

    assert!(
        manager.verify_token(&wrong_algorithm_token).is_err(),
        "tokens signed with an unexpected algorithm must be rejected"
    );
}

#[test]
fn test_admin_role_claim_parses_and_requires_explicit_role() {
    let now = Utc::now();
    let mut claims = AdminClaims {
        iss: "test-issuer".to_string(),
        sub: "admin-user".to_string(),
        iat: now.timestamp(),
        nbf: now.timestamp(),
        exp: (now + Duration::seconds(1800)).timestamp(),
        jti: uuid::Uuid::new_v4().to_string(),
        additional: json!({"role": "operator"}),
    };
    assert_eq!(claims.admin_role().unwrap(), AdminRole::Operator);

    claims.additional = json!({});
    assert!(
        claims.admin_role().is_err(),
        "missing role claims must not fail open as admin"
    );

    claims.additional = json!({"role": null});
    assert!(
        claims.admin_role().is_err(),
        "explicit null role claims must not fail open as admin"
    );
}

#[test]
fn test_admin_role_claim_rejects_unknown_role() {
    let now = Utc::now();
    let claims = AdminClaims {
        iss: "test-issuer".to_string(),
        sub: "admin-user".to_string(),
        iat: now.timestamp(),
        nbf: now.timestamp(),
        exp: (now + Duration::seconds(1800)).timestamp(),
        jti: uuid::Uuid::new_v4().to_string(),
        additional: json!({"role": "root"}),
    };
    assert!(claims.admin_role().is_err());
}

#[test]
fn test_jwt_invalid_issuer() {
    let config1 = JwtConfig {
        secret: "test-secret".to_string(),
        issuer: "issuer-1".to_string(),
        max_ttl_seconds: 3600,
        algorithm: Algorithm::HS256,
    };

    let config2 = JwtConfig {
        secret: "test-secret".to_string(),
        issuer: "issuer-2".to_string(),
        max_ttl_seconds: 3600,
        algorithm: Algorithm::HS256,
    };

    let _manager1 = JwtManager::new(config1);
    let manager2 = JwtManager::new(config2);

    // Create token with issuer-1
    let now = Utc::now();
    let claims = AdminClaims {
        iss: "issuer-1".to_string(),
        sub: "admin-user".to_string(),
        iat: now.timestamp(),
        nbf: now.timestamp(),
        exp: (now + Duration::seconds(1800)).timestamp(),
        jti: uuid::Uuid::new_v4().to_string(),
        additional: json!({}),
    };

    let header = Header::new(Algorithm::HS256);
    let key = EncodingKey::from_secret("test-secret".as_bytes());
    let token = encode(&header, &claims, &key).unwrap();

    // Try to verify with issuer-2 (should fail)
    let result = manager2.verify_token(&token);
    assert!(result.is_err());
}

#[test]
fn test_jwt_expired_token() {
    let config = JwtConfig {
        secret: "test-secret".to_string(),
        issuer: "test-issuer".to_string(),
        max_ttl_seconds: 3600,
        algorithm: Algorithm::HS256,
    };

    let manager = JwtManager::new(config);

    // Create expired token (expired 10 minutes ago)
    let now = Utc::now();
    let claims = AdminClaims {
        iss: "test-issuer".to_string(),
        sub: "admin-user".to_string(),
        iat: (now - Duration::minutes(10)).timestamp(),
        nbf: (now - Duration::minutes(10)).timestamp(),
        exp: (now - Duration::minutes(5)).timestamp(),
        jti: uuid::Uuid::new_v4().to_string(),
        additional: json!({}),
    };

    let header = Header::new(Algorithm::HS256);
    let key = EncodingKey::from_secret("test-secret".as_bytes());
    let token = encode(&header, &claims, &key).unwrap();

    // Should fail verification
    let result = manager.verify_token(&token);
    assert!(result.is_err(), "Expired token should fail verification");
}

#[test]
fn test_jwt_negative_ttl_rejected() {
    let config = JwtConfig {
        secret: "test-secret".to_string(),
        issuer: "test-issuer".to_string(),
        max_ttl_seconds: 3600,
        algorithm: Algorithm::HS256,
    };

    let manager = JwtManager::new(config);

    // Create a token where iat > exp (negative TTL)
    // Token is still not expired (exp is in the future), but iat is even further in the future.
    let now = Utc::now();
    let claims = AdminClaims {
        iss: "test-issuer".to_string(),
        sub: "admin-user".to_string(),
        iat: (now + Duration::hours(2)).timestamp(), // issued "in the future"
        nbf: now.timestamp(),
        exp: (now + Duration::hours(1)).timestamp(), // expires before iat
        jti: uuid::Uuid::new_v4().to_string(),
        additional: json!({}),
    };

    let header = Header::new(Algorithm::HS256);
    let key = EncodingKey::from_secret("test-secret".as_bytes());
    let token = encode(&header, &claims, &key).unwrap();

    let result = manager.verify_token(&token);
    assert!(
        result.is_err(),
        "Token with negative TTL (iat > exp) should be rejected"
    );
}

#[test]
fn test_jwt_zero_ttl_rejected() {
    let config = JwtConfig {
        secret: "test-secret".to_string(),
        issuer: "test-issuer".to_string(),
        max_ttl_seconds: 3600,
        algorithm: Algorithm::HS256,
    };

    let manager = JwtManager::new(config);

    // Create a token where iat == exp (zero TTL)
    let now = Utc::now();
    let exp_time = (now + Duration::hours(1)).timestamp();
    let claims = AdminClaims {
        iss: "test-issuer".to_string(),
        sub: "admin-user".to_string(),
        iat: exp_time, // same as exp
        nbf: now.timestamp(),
        exp: exp_time,
        jti: uuid::Uuid::new_v4().to_string(),
        additional: json!({}),
    };

    let header = Header::new(Algorithm::HS256);
    let key = EncodingKey::from_secret("test-secret".as_bytes());
    let token = encode(&header, &claims, &key).unwrap();

    let result = manager.verify_token(&token);
    assert!(
        result.is_err(),
        "Token with zero TTL (iat == exp) should be rejected"
    );
}

#[test]
fn test_jwt_valid_ttl_within_max() {
    let config = JwtConfig {
        secret: "test-secret".to_string(),
        issuer: "test-issuer".to_string(),
        max_ttl_seconds: 7200,
        algorithm: Algorithm::HS256,
    };

    let manager = JwtManager::new(config);

    let now = Utc::now();
    let claims = AdminClaims {
        iss: "test-issuer".to_string(),
        sub: "admin-user".to_string(),
        iat: now.timestamp(),
        nbf: now.timestamp(),
        exp: (now + Duration::seconds(3600)).timestamp(),
        jti: uuid::Uuid::new_v4().to_string(),
        additional: json!({}),
    };

    let header = Header::new(Algorithm::HS256);
    let key = EncodingKey::from_secret("test-secret".as_bytes());
    let token = encode(&header, &claims, &key).unwrap();

    let result = manager.verify_token(&token);
    assert!(
        result.is_ok(),
        "Token with positive TTL within max should be accepted"
    );
}

#[test]
fn test_jwt_ttl_exceeds_max_rejected() {
    let config = JwtConfig {
        secret: "test-secret".to_string(),
        issuer: "test-issuer".to_string(),
        max_ttl_seconds: 1800, // 30 min max
        algorithm: Algorithm::HS256,
    };

    let manager = JwtManager::new(config);

    let now = Utc::now();
    let claims = AdminClaims {
        iss: "test-issuer".to_string(),
        sub: "admin-user".to_string(),
        iat: now.timestamp(),
        nbf: now.timestamp(),
        exp: (now + Duration::seconds(3600)).timestamp(), // 1 hour > 30 min max
        jti: uuid::Uuid::new_v4().to_string(),
        additional: json!({}),
    };

    let header = Header::new(Algorithm::HS256);
    let key = EncodingKey::from_secret("test-secret".as_bytes());
    let token = encode(&header, &claims, &key).unwrap();

    let result = manager.verify_token(&token);
    assert!(
        result.is_err(),
        "Token with TTL exceeding max_ttl_seconds should be rejected"
    );
}
