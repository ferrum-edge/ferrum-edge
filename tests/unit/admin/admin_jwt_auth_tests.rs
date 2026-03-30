//! Tests for admin JWT authentication

use chrono::{Duration, Utc};
use ferrum_gateway::admin::jwt_auth::{AdminClaims, JwtConfig, JwtManager};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use serde_json::json;

#[test]
fn test_jwt_verification() {
    let config = JwtConfig {
        secret: "test-secret".to_string(),
        issuer: "test-issuer".to_string(),
        max_ttl_seconds: 3600,
        algorithm: Algorithm::HS256,
    };

    let manager = JwtManager::new(config);

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
