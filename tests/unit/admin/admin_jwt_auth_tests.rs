//! Tests for admin JWT authentication

use chrono::{Duration, Utc};
use ferrum_edge::admin::jwt_auth::{AdminClaims, AdminRole, JwtConfig, JwtError, JwtManager};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use serde_json::json;

fn test_jwt_config() -> JwtConfig {
    JwtConfig {
        secret: "test-secret".to_string(),
        issuer: "test-issuer".to_string(),
        audience: None,
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
        audience: None,
        max_ttl_seconds: 3600,
        algorithm: Algorithm::HS256,
    };

    let config2 = JwtConfig {
        secret: "test-secret".to_string(),
        issuer: "issuer-2".to_string(),
        audience: None,
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
        audience: None,
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
        audience: None,
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
        audience: None,
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
        audience: None,
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
        audience: None,
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

#[test]
fn test_jwt_future_iat_within_cap_rejected() {
    // The bypass from the issue: shift `iat` and `exp` far into the future
    // while keeping `exp - iat` within the configured maximum and `nbf` at
    // the current time. The nominal TTL check alone accepts this token even
    // though it remains usable for years.
    let config = JwtConfig {
        secret: "test-secret".to_string(),
        issuer: "test-issuer".to_string(),
        audience: None,
        max_ttl_seconds: 3600,
        algorithm: Algorithm::HS256,
    };

    let manager = JwtManager::new(config);

    let now = Utc::now();
    let claims = AdminClaims {
        iss: "test-issuer".to_string(),
        sub: "admin-user".to_string(),
        iat: (now + Duration::days(3650)).timestamp(), // ~10 years in the future
        nbf: now.timestamp(),                          // immediately usable
        exp: (now + Duration::days(3650) + Duration::seconds(3600)).timestamp(),
        jti: uuid::Uuid::new_v4().to_string(),
        additional: json!({}),
    };

    let header = Header::new(Algorithm::HS256);
    let key = EncodingKey::from_secret("test-secret".as_bytes());
    let token = encode(&header, &claims, &key).unwrap();

    let result = manager.verify_token(&token);
    assert!(
        result.is_err(),
        "Token with a future-shifted iat must be rejected even when exp - iat is within the cap"
    );
}

#[test]
fn test_jwt_future_iat_beyond_clock_skew_rejected() {
    let config = JwtConfig {
        secret: "test-secret".to_string(),
        issuer: "test-issuer".to_string(),
        audience: None,
        max_ttl_seconds: 3600,
        algorithm: Algorithm::HS256,
    };

    let manager = JwtManager::new(config);

    // jsonwebtoken's default leeway is 60 seconds; an iat further in the
    // future than that skew must be rejected.
    let now = Utc::now();
    let claims = AdminClaims {
        iss: "test-issuer".to_string(),
        sub: "admin-user".to_string(),
        iat: (now + Duration::seconds(600)).timestamp(),
        nbf: now.timestamp(),
        exp: (now + Duration::seconds(600 + 1800)).timestamp(),
        jti: uuid::Uuid::new_v4().to_string(),
        additional: json!({}),
    };

    let header = Header::new(Algorithm::HS256);
    let key = EncodingKey::from_secret("test-secret".as_bytes());
    let token = encode(&header, &claims, &key).unwrap();

    let result = manager.verify_token(&token);
    assert!(
        result.is_err(),
        "Token with iat beyond the accepted clock skew should be rejected"
    );
}

#[test]
fn test_jwt_iat_within_clock_skew_accepted() {
    let config = JwtConfig {
        secret: "test-secret".to_string(),
        issuer: "test-issuer".to_string(),
        audience: None,
        max_ttl_seconds: 3600,
        algorithm: Algorithm::HS256,
    };

    let manager = JwtManager::new(config);

    // A slightly future iat from a skewed-but-honest issuer clock remains
    // acceptable (jsonwebtoken's default leeway is 60 seconds).
    let now = Utc::now();
    let claims = AdminClaims {
        iss: "test-issuer".to_string(),
        sub: "admin-user".to_string(),
        iat: (now + Duration::seconds(30)).timestamp(),
        nbf: now.timestamp(),
        exp: (now + Duration::seconds(30 + 1800)).timestamp(),
        jti: uuid::Uuid::new_v4().to_string(),
        additional: json!({}),
    };

    let header = Header::new(Algorithm::HS256);
    let key = EncodingKey::from_secret("test-secret".as_bytes());
    let token = encode(&header, &claims, &key).unwrap();

    let result = manager.verify_token(&token);
    assert!(
        result.is_ok(),
        "Token with iat within the accepted clock skew should be accepted: {:?}",
        result.err()
    );
}

#[test]
fn test_jwt_zero_max_ttl_disables_cap() {
    // `0` is the documented disable sentinel: the lifetime cap is skipped
    // entirely, so even a very long-lived (but unexpired) token verifies.
    let config = JwtConfig {
        secret: "test-secret".to_string(),
        issuer: "test-issuer".to_string(),
        audience: None,
        max_ttl_seconds: 0,
        algorithm: Algorithm::HS256,
    };

    let manager = JwtManager::new(config);

    let now = Utc::now();
    let claims = AdminClaims {
        iss: "test-issuer".to_string(),
        sub: "admin-user".to_string(),
        iat: now.timestamp(),
        nbf: now.timestamp(),
        exp: (now + Duration::days(365)).timestamp(),
        jti: uuid::Uuid::new_v4().to_string(),
        additional: json!({}),
    };

    let header = Header::new(Algorithm::HS256);
    let key = EncodingKey::from_secret("test-secret".as_bytes());
    let token = encode(&header, &claims, &key).unwrap();

    let result = manager.verify_token(&token);
    assert!(
        result.is_ok(),
        "max_ttl_seconds = 0 is the documented disable sentinel and must skip the cap: {:?}",
        result.err()
    );
}

// ── `FERRUM_ADMIN_JWT_MAX_TTL` boundaries ─────────────────────────────
//
// The enforced contract (see `JwtManager::verify_token`) counts the 60-second
// clock-skew leeway exactly once: `exp - iat` positive and `<= max_ttl`,
// `iat <= now + leeway`, `exp - now <= max_ttl + leeway`, and `exp > now`.
// Effective maximum real acceptance is `max_ttl + leeway`.

fn config_with_max_ttl(max_ttl_seconds: u64) -> JwtConfig {
    JwtConfig {
        max_ttl_seconds,
        ..test_jwt_config()
    }
}

/// Sign claims with the shared test key/issuer used by `test_jwt_config()`.
fn sign_claims(claims: &AdminClaims) -> String {
    let header = Header::new(Algorithm::HS256);
    let key = EncodingKey::from_secret("test-secret".as_bytes());
    encode(&header, claims, &key).unwrap()
}

/// Claims with explicit `iat`/`exp` offsets (seconds) from the current time
/// and `nbf` pinned to now, matching the shape a minter would emit.
fn claims_at(iat_offset: i64, exp_offset: i64) -> AdminClaims {
    let now = Utc::now().timestamp();
    AdminClaims {
        iss: "test-issuer".to_string(),
        sub: "admin-user".to_string(),
        iat: now + iat_offset,
        nbf: now,
        exp: now + exp_offset,
        jti: uuid::Uuid::new_v4().to_string(),
        additional: json!({}),
    }
}

/// Sign and verify `claims_at(iat_offset, exp_offset)`, retrying until the whole
/// sign-then-verify cycle stays inside one wall-clock second.
///
/// `claims_at()` floors `Utc::now()` to seconds while `verify_token()` reads its
/// own fresh timestamp. A whole-second tick landing between the two shifts every
/// verifier-time bound by one second, so an assertion placed exactly one second
/// outside a bound can legitimately flip. Requiring both samples to land in the
/// same second pins claim time and verifier time together, which makes the
/// exact boundary deterministic without widening the offsets under test.
///
/// Only exact-boundary assertions need this. Assertions whose outcome is
/// claim-relative (`exp - iat`), or that a later verifier timestamp can only
/// push further in the asserted direction, are already drift-safe.
fn verify_within_one_second(
    manager: &JwtManager,
    iat_offset: i64,
    exp_offset: i64,
) -> Result<(), String> {
    // A sign-and-verify cycle is sub-millisecond, so a tick-free sample is
    // effectively immediate. The bound exists only so a pathological
    // environment fails loudly instead of spinning forever.
    for _ in 0..64 {
        let before = Utc::now().timestamp();
        let token = sign_claims(&claims_at(iat_offset, exp_offset));
        let result = manager.verify_token(&token);
        // Both `claims_at()`'s clock read and the verifier's fall between
        // `before` and this sample, so an unchanged second forces all three
        // to be equal.
        if Utc::now().timestamp() == before {
            return result.map(|_| ()).map_err(|err| err.to_string());
        }
    }
    panic!("could not sign and verify a token within a single wall-clock second");
}

#[test]
fn test_jwt_nominal_max_ttl_boundary_accepted() {
    // exp - iat == max_ttl exactly: the documented nominal maximum.
    let manager = JwtManager::new(config_with_max_ttl(3600));
    let token = sign_claims(&claims_at(0, 3600));

    let result = manager.verify_token(&token);
    assert!(
        result.is_ok(),
        "A token whose nominal lifetime equals max_ttl exactly must be accepted: {:?}",
        result.err()
    );
}

#[test]
fn test_jwt_nominal_max_ttl_one_second_over_rejected() {
    let manager = JwtManager::new(config_with_max_ttl(3600));
    let token = sign_claims(&claims_at(0, 3601));

    assert!(
        manager.verify_token(&token).is_err(),
        "A nominal lifetime one second beyond max_ttl must be rejected"
    );
}

#[test]
fn test_jwt_final_acceptance_window_is_one_skew_allowance() {
    // Worst legitimate case: an issuer whose clock is a full leeway window
    // fast mints a full-length token. `exp - now == max_ttl + leeway`, the
    // documented maximum real acceptance, and it is accepted.
    let manager = JwtManager::new(config_with_max_ttl(3600));
    let token = sign_claims(&claims_at(60, 60 + 3600));

    let result = manager.verify_token(&token);
    assert!(
        result.is_ok(),
        "A fast-but-within-skew issuer must still mint full-length tokens: {:?}",
        result.err()
    );

    // One second more of future shift breaks the single skew allowance on
    // both the `iat` and remaining-lifetime bounds. This sits exactly one
    // second outside those bounds, so claim time and verifier time must be
    // pinned to the same second; the accepted case above needs no pinning
    // because a later verifier timestamp only relaxes bounds (2) and (3).
    assert!(
        verify_within_one_second(&manager, 61, 61 + 3600).is_err(),
        "Shifting beyond one skew window must not extend real acceptance"
    );
}

#[test]
fn test_jwt_expired_within_jsonwebtoken_leeway_rejected_under_cap() {
    // Anti-double-count: jsonwebtoken alone keeps accepting a token until
    // `exp + leeway`. With the cap enabled the verifier re-checks expiry at
    // verifier time with no grace, so the same 60s skew allowance is never
    // spent twice (which would stretch real acceptance to max_ttl + 120s).
    let manager = JwtManager::new(config_with_max_ttl(3600));
    let token = sign_claims(&claims_at(-3610, -10));

    assert!(
        manager.verify_token(&token).is_err(),
        "A token past `exp` must be rejected under the cap even inside jsonwebtoken's expiry leeway"
    );
}

#[test]
fn test_jwt_oversized_max_ttl_rejected_not_treated_as_unlimited() {
    // `u64::MAX` is a typo, not the documented `0` disable sentinel: it is
    // unrepresentable as an i64-second bound and must fail closed rather
    // than clamping to an effectively unlimited cap.
    let manager = JwtManager::new(config_with_max_ttl(u64::MAX));
    let token = sign_claims(&claims_at(0, 1800));

    assert!(
        manager.verify_token(&token).is_err(),
        "An unrepresentable max_ttl must fail closed, not behave as an unlimited cap"
    );
}

#[test]
fn test_jwt_max_ttl_representable_boundary() {
    // One past the representable bound fails closed; the bound itself is a
    // valid (if absurd) configuration and still enforces the cap.
    let over = JwtManager::new(config_with_max_ttl(i64::MAX as u64 + 1));
    assert!(
        over.verify_token(&sign_claims(&claims_at(0, 1800)))
            .is_err(),
        "max_ttl above i64::MAX must be rejected as invalid configuration"
    );

    let at_bound = JwtManager::new(config_with_max_ttl(i64::MAX as u64));
    let result = at_bound.verify_token(&sign_claims(&claims_at(0, 1800)));
    assert!(
        result.is_ok(),
        "max_ttl at the representable bound remains a usable configuration: {:?}",
        result.err()
    );
}

#[test]
fn test_jwt_hostile_timestamp_extremes_rejected() {
    let manager = JwtManager::new(config_with_max_ttl(3600));

    // `iat = i64::MIN` with a sane `exp`: `exp - iat` saturates instead of
    // overflowing, so the nominal-lifetime check rejects it.
    let mut claims = claims_at(0, 1800);
    claims.iat = i64::MIN;
    assert!(
        manager.verify_token(&sign_claims(&claims)).is_err(),
        "iat = i64::MIN must be rejected, not overflow the lifetime computation"
    );

    // `exp = i64::MAX`: far beyond the cap in both nominal and remaining
    // lifetime.
    let mut claims = claims_at(0, 1800);
    claims.exp = i64::MAX;
    assert!(
        manager.verify_token(&sign_claims(&claims)).is_err(),
        "exp = i64::MAX must be rejected"
    );

    // Both extremes at once.
    let mut claims = claims_at(0, 1800);
    claims.iat = i64::MIN;
    claims.exp = i64::MAX;
    assert!(
        manager.verify_token(&sign_claims(&claims)).is_err(),
        "iat = i64::MIN with exp = i64::MAX must be rejected"
    );

    // A negative `exp` is not a valid JWT NumericDate for jsonwebtoken's
    // expiry validation and is rejected at decode.
    let mut claims = claims_at(0, 1800);
    claims.exp = i64::MIN;
    assert!(
        manager.verify_token(&sign_claims(&claims)).is_err(),
        "exp = i64::MIN must be rejected"
    );
}

/// Panic-safe snapshot for the admin JWT environment touched by the manager
/// construction test. The shared lock stays held until Drop restores every
/// previous value.
struct AdminJwtEnvGuard {
    _lock: std::sync::MutexGuard<'static, ()>,
    saved: Vec<(&'static str, Option<std::ffi::OsString>)>,
}

impl AdminJwtEnvGuard {
    const KEYS: [&'static str; 4] = [
        "FERRUM_ADMIN_JWT_SECRET",
        "FERRUM_ADMIN_JWT_ISSUER",
        "FERRUM_ADMIN_JWT_AUDIENCE",
        "FERRUM_ADMIN_JWT_MAX_TTL",
    ];

    fn new() -> Self {
        let lock = crate::unit::env_lock::ENV_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let saved = Self::KEYS
            .iter()
            .map(|&key| (key, std::env::var_os(key)))
            .collect();
        Self { _lock: lock, saved }
    }

    fn set(&self, key: &'static str, value: &str) {
        // SAFETY: this guard holds the process-wide environment lock.
        unsafe { std::env::set_var(key, value) }
    }

    fn unset(&self, key: &'static str) {
        // SAFETY: this guard holds the process-wide environment lock.
        unsafe { std::env::remove_var(key) }
    }
}

impl Drop for AdminJwtEnvGuard {
    fn drop(&mut self) {
        for (key, value) in &self.saved {
            // SAFETY: `_lock` remains held while Drop restores the snapshot.
            unsafe {
                match value {
                    Some(value) => std::env::set_var(key, value),
                    None => std::env::remove_var(key),
                }
            }
        }
    }
}

/// `FERRUM_ADMIN_JWT_MAX_TTL` is a security control, so a present-but-invalid
/// value fails startup instead of silently falling back to the default or to
/// an effectively unlimited cap.
#[test]
fn test_create_jwt_manager_rejects_invalid_max_ttl() {
    use ferrum_edge::admin::jwt_auth::create_jwt_manager_from_env;

    let env = AdminJwtEnvGuard::new();
    env.set(
        "FERRUM_ADMIN_JWT_SECRET",
        "secret-padding-for-32-characters!!",
    );
    env.unset("FERRUM_ADMIN_JWT_ISSUER");
    env.unset("FERRUM_ADMIN_JWT_AUDIENCE");

    for invalid in ["18446744073709551615", "9223372036854775808", "-1", "abc"] {
        env.set("FERRUM_ADMIN_JWT_MAX_TTL", invalid);
        assert!(
            create_jwt_manager_from_env().is_err(),
            "FERRUM_ADMIN_JWT_MAX_TTL='{invalid}' must be rejected at startup"
        );
    }

    // Control cases: the documented disable sentinel and an ordinary value
    // both construct successfully, so the rejection above is specific.
    for valid in ["0", "3600", "9223372036854775807"] {
        env.set("FERRUM_ADMIN_JWT_MAX_TTL", valid);
        assert!(
            create_jwt_manager_from_env().is_ok(),
            "FERRUM_ADMIN_JWT_MAX_TTL='{valid}' must be accepted"
        );
    }
}

// ── Optional audience (`aud`) enforcement ─────────────────────────────

fn config_with_audience(audience: Option<&str>) -> JwtConfig {
    JwtConfig {
        secret: "test-secret".to_string(),
        issuer: "test-issuer".to_string(),
        audience: audience.map(str::to_string),
        max_ttl_seconds: 3600,
        algorithm: Algorithm::HS256,
    }
}

fn admin_claims_json(aud: Option<&str>) -> serde_json::Value {
    let now = Utc::now();
    let mut claims = json!({
        "iss": "test-issuer",
        "sub": "admin-user",
        "iat": now.timestamp(),
        "nbf": now.timestamp(),
        "exp": (now + Duration::seconds(1800)).timestamp(),
        "jti": uuid::Uuid::new_v4().to_string(),
        "role": "admin",
    });
    if let Some(aud) = aud {
        claims["aud"] = json!(aud);
    }
    claims
}

#[test]
fn test_audience_match_is_accepted() {
    let manager = JwtManager::new(config_with_audience(Some("ferrum-admin")));
    let token = encode_json_claims(
        admin_claims_json(Some("ferrum-admin")),
        "test-secret",
        Algorithm::HS256,
    );
    let token_data = manager
        .verify_token(&token)
        .expect("token with matching aud must be accepted");
    assert_eq!(token_data.claims.sub, "admin-user");
}

#[test]
fn test_audience_mismatch_is_rejected() {
    let manager = JwtManager::new(config_with_audience(Some("ferrum-admin")));
    let token = encode_json_claims(
        admin_claims_json(Some("some-other-service")),
        "test-secret",
        Algorithm::HS256,
    );
    assert!(
        manager.verify_token(&token).is_err(),
        "token whose aud does not match the configured audience must be rejected"
    );
}

#[test]
fn test_audience_required_when_configured_rejects_missing_aud() {
    let manager = JwtManager::new(config_with_audience(Some("ferrum-admin")));
    let token = encode_json_claims(admin_claims_json(None), "test-secret", Algorithm::HS256);
    assert!(
        manager.verify_token(&token).is_err(),
        "when an audience is configured, a token that omits aud must be rejected"
    );
}

#[test]
fn test_audience_unset_does_not_require_aud() {
    // Default (audience: None): behavior is unchanged — a token that carries no
    // aud claim is accepted, so operators who never configure an audience are
    // unaffected.
    let manager = JwtManager::new(config_with_audience(None));
    let token = encode_json_claims(admin_claims_json(None), "test-secret", Algorithm::HS256);
    manager
        .verify_token(&token)
        .expect("with no audience configured, a token without aud must be accepted");
}

#[test]
fn test_audience_unset_rejects_aud_bearing_token() {
    // Default (audience: None): jsonwebtoken's strict `validate_aud = true`
    // default is deliberately kept. A token that CARRIES an `aud` claim is
    // rejected because no acceptable audience is configured (RFC 7519 §4.1.3).
    // This blocks cross-service token replay under HS256 secret reuse; it is
    // the pre-existing behavior, pinned here so it is never loosened silently.
    // Operators whose minter stamps `aud` must set FERRUM_ADMIN_JWT_AUDIENCE.
    let manager = JwtManager::new(config_with_audience(None));
    let token = encode_json_claims(
        admin_claims_json(Some("some-other-service")),
        "test-secret",
        Algorithm::HS256,
    );
    assert!(
        manager.verify_token(&token).is_err(),
        "with no audience configured, a token carrying aud must be rejected (strict RFC 7519 handling)"
    );
}

#[test]
fn test_create_jwt_manager_not_configured_when_secret_unset() {
    use ferrum_edge::admin::jwt_auth::{JwtError, create_jwt_manager_from_env};

    let env = AdminJwtEnvGuard::new();
    env.unset("FERRUM_ADMIN_JWT_SECRET");
    env.unset("FERRUM_ADMIN_JWT_ISSUER");
    env.unset("FERRUM_ADMIN_JWT_AUDIENCE");
    env.unset("FERRUM_ADMIN_JWT_MAX_TTL");

    match create_jwt_manager_from_env() {
        Err(JwtError::NotConfigured) => {}
        other => panic!("unset secret must be NotConfigured, got: {other:?}"),
    }
}

#[test]
fn test_create_jwt_manager_short_secret_is_invalid_not_unconfigured() {
    use ferrum_edge::admin::jwt_auth::{JwtError, create_jwt_manager_from_env};

    let env = AdminJwtEnvGuard::new();
    env.set("FERRUM_ADMIN_JWT_SECRET", "only-twenty-chars!!!"); // 20 chars
    env.unset("FERRUM_ADMIN_JWT_ISSUER");
    env.unset("FERRUM_ADMIN_JWT_AUDIENCE");
    env.unset("FERRUM_ADMIN_JWT_MAX_TTL");

    match create_jwt_manager_from_env() {
        Err(JwtError::VerificationFailed(msg)) => {
            assert!(
                msg.contains("at least"),
                "short secret must be an actionable invalid-config error: {msg}"
            );
        }
        Err(JwtError::NotConfigured) => {
            panic!("short secret must not be treated as NotConfigured")
        }
        other => panic!("expected VerificationFailed for short secret, got: {other:?}"),
    }
}
