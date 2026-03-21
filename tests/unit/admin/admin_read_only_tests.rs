//! Admin Read-Only Mode Tests
//!
//! Tests for the Admin API read-only mode functionality

use ferrum_gateway::admin::{
    AdminState,
    jwt_auth::{JwtConfig, JwtManager},
};
use jsonwebtoken::{EncodingKey, Header, encode};
use serde_json::json;

/// Test configuration for admin API
#[derive(Clone)]
struct TestConfig {
    jwt_secret: String,
    jwt_issuer: String,
    max_ttl: u64,
}

impl Default for TestConfig {
    fn default() -> Self {
        Self {
            jwt_secret: "test-secret-key-for-admin-api".to_string(),
            jwt_issuer: "test-ferrum-gateway".to_string(),
            max_ttl: 3600,
        }
    }
}

/// Create a test JWT manager
fn create_test_jwt_manager(config: &TestConfig) -> JwtManager {
    let jwt_config = JwtConfig {
        secret: config.jwt_secret.clone(),
        issuer: config.jwt_issuer.clone(),
        max_ttl_seconds: config.max_ttl,
        algorithm: jsonwebtoken::Algorithm::HS256,
    };
    JwtManager::new(jwt_config)
}

/// Create a test admin state with specified read-only mode
fn create_test_admin_state(config: &TestConfig, read_only: bool) -> AdminState {
    AdminState {
        db: None,
        jwt_manager: create_test_jwt_manager(config),
        cached_config: None,
        proxy_state: None,
        mode: "test".to_string(),
        read_only,
    }
}

/// Generate a valid JWT token for testing
fn generate_test_token(config: &TestConfig, subject: &str) -> String {
    let now = chrono::Utc::now();
    let claims = json!({
        "iss": config.jwt_issuer,
        "sub": subject,
        "iat": now.timestamp(),
        "nbf": now.timestamp(),
        "exp": (now + chrono::Duration::seconds(config.max_ttl as i64)).timestamp(),
        "jti": uuid::Uuid::new_v4().to_string()
    });

    let header = Header::new(jsonwebtoken::Algorithm::HS256);
    let key = EncodingKey::from_secret(config.jwt_secret.as_bytes());

    encode(&header, &claims, &key).unwrap()
}

#[tokio::test]
async fn test_admin_state_read_only_field() {
    let config = TestConfig::default();

    // Test read-only state
    let admin_state_read_only = create_test_admin_state(&config, true);
    assert!(
        admin_state_read_only.read_only,
        "Admin state should be read-only"
    );

    // Test read-write state
    let admin_state_read_write = create_test_admin_state(&config, false);
    assert!(
        !admin_state_read_write.read_only,
        "Admin state should not be read-only"
    );
}

#[tokio::test]
async fn test_jwt_token_validation() {
    let config = TestConfig::default();
    let jwt_manager = create_test_jwt_manager(&config);

    // Test valid token
    let valid_token = generate_test_token(&config, "test-user");
    let result = jwt_manager.verify_token(&valid_token);
    assert!(result.is_ok(), "Valid token should pass verification");

    // Test invalid token (wrong secret)
    let wrong_config = TestConfig {
        jwt_secret: "wrong-secret".to_string(),
        jwt_issuer: config.jwt_issuer.clone(),
        max_ttl: config.max_ttl,
    };
    let invalid_token = generate_test_token(&wrong_config, "test-user");
    let result = jwt_manager.verify_token(&invalid_token);
    assert!(result.is_err(), "Invalid token should fail verification");
}

#[tokio::test]
async fn test_admin_api_integration() {
    let config = TestConfig::default();
    let admin_state = create_test_admin_state(&config, false);

    // Test that admin API is properly initialized
    assert_eq!(admin_state.mode, "test");
    assert!(
        !admin_state.read_only,
        "Default admin state should not be read-only"
    );

    // Test basic functionality
    let token = generate_test_token(&config, "test-user");
    let result = admin_state.jwt_manager.verify_token(&token);
    assert!(result.is_ok(), "Generated token should be valid");
}

#[tokio::test]
async fn test_admin_read_only_mode_configuration() {
    let config = TestConfig::default();

    // Test read-only mode configuration
    let admin_state_read_only = create_test_admin_state(&config, true);
    assert!(
        admin_state_read_only.read_only,
        "Read-only mode should be enabled"
    );

    // Test read-write mode configuration
    let admin_state_read_write = create_test_admin_state(&config, false);
    assert!(
        !admin_state_read_write.read_only,
        "Read-write mode should not be read-only"
    );
}

#[tokio::test]
async fn test_admin_state_mode_field() {
    let config = TestConfig::default();
    let admin_state = create_test_admin_state(&config, false);

    // Test mode field is set correctly
    assert_eq!(admin_state.mode, "test");

    // Test mode field can be different
    let admin_state_prod = AdminState {
        db: None,
        jwt_manager: create_test_jwt_manager(&config),
        cached_config: None,
        proxy_state: None,
        mode: "production".to_string(),
        read_only: false,
    };
    assert_eq!(admin_state_prod.mode, "production");
}

#[tokio::test]
async fn test_admin_state_jwt_manager() {
    let config = TestConfig::default();
    let admin_state = create_test_admin_state(&config, false);

    // Test JWT manager is properly initialized
    let token = generate_test_token(&config, "test-user");
    let result = admin_state.jwt_manager.verify_token(&token);
    assert!(result.is_ok(), "JWT manager should work correctly");
}
