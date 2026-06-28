//! Admin API Tests
//!
//! Tests for the Ferrum Edge Admin API including JWT authentication

use chrono::Utc;
use ferrum_edge::admin::{
    AdminState,
    jwt_auth::{AdminClaims, AdminRole, JwtConfig, JwtManager},
};
use jsonwebtoken::{EncodingKey, Header, encode};
use serde_json::json;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use uuid::Uuid;

/// Test configuration for admin API
#[derive(Clone)]
struct TestConfig {
    jwt_secret: String,
    jwt_issuer: String,
    max_ttl: u64,
    admin_addr: SocketAddr,
}

impl Default for TestConfig {
    fn default() -> Self {
        Self {
            jwt_secret: "test-secret-key-for-admin-api".to_string(),
            jwt_issuer: "test-ferrum-edge".to_string(),
            max_ttl: 3600,
            admin_addr: "127.0.0.1:0".parse().unwrap(),
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

/// Create a test admin state
fn create_test_admin_state(config: &TestConfig) -> AdminState {
    AdminState {
        db: None,
        jwt_manager: create_test_jwt_manager(config),
        cached_config: None,
        proxy_state: None,
        mode: "test".to_string(),
        read_only: false, // Default to read-write for existing tests
        admin_audit_enabled: false,
        startup_ready: None,
        db_available: None,
        admin_restore_max_body_size_mib: 100,
        admin_spec_max_body_size_mib: 25,
        reserved_ports: std::collections::HashSet::new(),
        stream_proxy_bind_address: "0.0.0.0".to_string(),
        admin_allowed_cidrs: std::sync::Arc::new(
            ferrum_edge::proxy::client_ip::TrustedProxies::none(),
        ),
        cached_db_health: std::sync::Arc::new(arc_swap::ArcSwap::new(std::sync::Arc::new(None))),
        dp_registry: None,
        mesh_registry: None,
        cp_connection_state: None,
        admin_http_header_read_timeout_seconds: 10,
        mesh_runtime_state: None,
        admin_tls_handshake_timeout_seconds: 10,
        backend_allow_ips: ferrum_edge::config::BackendEgressPolicy::unrestricted(),
    }
}

/// Generate a valid JWT token for testing
fn generate_test_token(config: &TestConfig, subject: &str) -> String {
    let now = Utc::now();
    let claims = json!({
        "iss": config.jwt_issuer,
        "sub": subject,
        "role": "admin",
        "iat": now.timestamp(),
        "nbf": now.timestamp(),
        "exp": (now + chrono::Duration::seconds(config.max_ttl as i64)).timestamp(),
        "jti": Uuid::new_v4().to_string()
    });

    let header = Header::new(jsonwebtoken::Algorithm::HS256);
    let key = EncodingKey::from_secret(config.jwt_secret.as_bytes());

    encode(&header, &claims, &key).unwrap()
}

/// Generate an invalid JWT token (wrong secret)
fn generate_invalid_token(config: &TestConfig, subject: &str) -> String {
    let now = Utc::now();
    let claims = json!({
        "iss": config.jwt_issuer,
        "sub": subject,
        "role": "admin",
        "iat": now.timestamp(),
        "nbf": now.timestamp(),
        "exp": (now + chrono::Duration::seconds(config.max_ttl as i64)).timestamp(),
        "jti": Uuid::new_v4().to_string()
    });

    let header = Header::new(jsonwebtoken::Algorithm::HS256);
    let key = EncodingKey::from_secret("wrong-secret".as_bytes());

    encode(&header, &claims, &key).unwrap()
}

fn admin_claims_with_role(role: serde_json::Value) -> AdminClaims {
    let now = Utc::now();
    AdminClaims {
        iss: "test-ferrum-edge".to_string(),
        sub: "test-user".to_string(),
        iat: now.timestamp(),
        nbf: now.timestamp(),
        exp: (now + chrono::Duration::seconds(3600)).timestamp(),
        jti: Uuid::new_v4().to_string(),
        additional: role,
    }
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
    let invalid_token = generate_invalid_token(&config, "test-user");
    let result = jwt_manager.verify_token(&invalid_token);
    assert!(result.is_err(), "Invalid token should fail verification");

    // Test malformed token
    let result = jwt_manager.verify_token("malformed-token");
    assert!(result.is_err(), "Malformed token should fail verification");
}

#[test]
fn test_admin_jwt_role_claim_parsing() {
    assert!(
        admin_claims_with_role(json!({})).admin_role().is_err(),
        "missing role must fail closed"
    );
    assert_eq!(
        admin_claims_with_role(json!({"role": "viewer"}))
            .admin_role()
            .unwrap(),
        AdminRole::Viewer
    );
    assert_eq!(
        admin_claims_with_role(json!({"role": "operator"}))
            .admin_role()
            .unwrap(),
        AdminRole::Operator
    );
    assert_eq!(
        admin_claims_with_role(json!({"role": "admin"}))
            .admin_role()
            .unwrap(),
        AdminRole::Admin
    );
    assert!(
        admin_claims_with_role(json!({"role": 1}))
            .admin_role()
            .is_err()
    );
    assert!(
        admin_claims_with_role(json!({"role": "root"}))
            .admin_role()
            .is_err()
    );
}

#[tokio::test]
async fn test_admin_api_integration() {
    let config = TestConfig::default();
    let admin_state = create_test_admin_state(&config);

    // Test that the admin API is properly initialized
    assert_eq!(admin_state.mode, "test");

    // Test basic functionality
    let token = generate_test_token(&config, "test-user");
    let result = admin_state.jwt_manager.verify_token(&token);
    assert!(result.is_ok(), "Generated token should be valid");
}

#[tokio::test]
async fn test_admin_http1_slow_header_timeout_closes_connection() {
    let config = TestConfig::default();
    let mut admin_state = create_test_admin_state(&config);
    admin_state.admin_http_header_read_timeout_seconds = 1;

    let listener = tokio::net::TcpListener::bind(config.admin_addr)
        .await
        .expect("bind admin listener");
    let addr = listener.local_addr().expect("admin listener addr");
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

    let server = tokio::spawn(async move {
        ferrum_edge::admin::serve_admin_on_listener(listener, admin_state, shutdown_rx, None).await
    });

    let mut stream = tokio::net::TcpStream::connect(addr)
        .await
        .expect("connect to admin listener");
    stream
        .write_all(b"GET /health HTTP/1.1\r\nHost: localhost\r\n")
        .await
        .expect("write partial headers");

    let mut buf = [0u8; 1];
    let read_result = tokio::time::timeout(Duration::from_secs(3), stream.read(&mut buf))
        .await
        .expect("admin listener should close slow header connection");

    match read_result {
        Ok(0) => {}
        Err(e)
            if matches!(
                e.kind(),
                std::io::ErrorKind::ConnectionReset
                    | std::io::ErrorKind::BrokenPipe
                    | std::io::ErrorKind::UnexpectedEof
            ) => {}
        other => panic!("expected EOF or reset after header timeout, got {other:?}"),
    }

    shutdown_tx.send(true).expect("signal admin shutdown");
    tokio::time::timeout(Duration::from_secs(2), server)
        .await
        .expect("admin listener task should stop")
        .expect("admin listener task join")
        .expect("admin listener should exit cleanly");
}

#[tokio::test]
async fn test_jwt_configuration_validation() {
    // Test various configuration scenarios
    let configs = vec![
        (TestConfig::default(), "Default configuration"),
        (
            TestConfig {
                jwt_secret: "different-secret".to_string(),
                jwt_issuer: "different-issuer".to_string(),
                max_ttl: 7200,
                admin_addr: "127.0.0.1:0".parse().unwrap(),
            },
            "Custom configuration",
        ),
        (
            TestConfig {
                jwt_secret: "short".to_string(),
                jwt_issuer: "test".to_string(),
                max_ttl: 60,
                admin_addr: "127.0.0.1:0".parse().unwrap(),
            },
            "Minimal configuration",
        ),
    ];

    for (config, description) in configs {
        let admin_state = create_test_admin_state(&config);
        let token = generate_test_token(&config, "test-user");
        let result = admin_state.jwt_manager.verify_token(&token);

        assert!(
            result.is_ok(),
            "Configuration '{}' should work: {:?}",
            description,
            result
        );
        println!("Configuration test passed: {}", description);
    }
}

#[tokio::test]
async fn test_jwt_security_scenarios() {
    let config = TestConfig::default();
    let jwt_manager = create_test_jwt_manager(&config);

    // Test 1: Token reuse
    let token = generate_test_token(&config, "test-user");
    for _ in 0..5 {
        let result = jwt_manager.verify_token(&token);
        assert!(result.is_ok());
    }

    // Test 2: Token tampering
    let token = generate_test_token(&config, "test-user");
    let tampered_token = format!("{}tampered", token);
    let result = jwt_manager.verify_token(&tampered_token);
    assert!(result.is_err());

    // Test 3: Cross-issuer attack
    let wrong_config = TestConfig {
        jwt_secret: config.jwt_secret.clone(),
        jwt_issuer: "attacker".to_string(),
        max_ttl: config.max_ttl,
        admin_addr: config.admin_addr,
    };
    let wrong_token = generate_test_token(&wrong_config, "test-user");
    let result = jwt_manager.verify_token(&wrong_token);
    assert!(result.is_err());

    println!("All security tests passed");
}

#[tokio::test]
async fn test_jwt_performance() {
    let config = TestConfig::default();
    let jwt_manager = create_test_jwt_manager(&config);

    // Test performance characteristics
    let start = std::time::Instant::now();

    // Generate and verify multiple tokens
    for i in 0..100 {
        let token = generate_test_token(&config, &format!("user-{}", i));
        let result = jwt_manager.verify_token(&token);
        assert!(result.is_ok());
    }

    let duration = start.elapsed();
    assert!(
        duration.as_millis() < 1000,
        "100 token verifications should complete within 1 second"
    );

    println!(
        "Performance test completed in {}ms for 100 tokens",
        duration.as_millis()
    );
}

#[tokio::test]
async fn test_jwt_concurrent_access() {
    let config = TestConfig::default();
    let jwt_manager = create_test_jwt_manager(&config);

    // Test concurrent token generation and verification
    let mut handles = Vec::new();

    for i in 0..50 {
        let config_clone = config.clone();
        let jwt_manager_clone = jwt_manager.clone();

        let handle = tokio::spawn(async move {
            let token = generate_test_token(&config_clone, &format!("user-{}", i));
            jwt_manager_clone.verify_token(&token).is_ok()
        });

        handles.push(handle);
    }

    let mut success_count = 0;
    for handle in handles {
        if handle.await.unwrap() {
            success_count += 1;
        }
    }

    assert_eq!(
        success_count, 50,
        "All concurrent token verifications should succeed"
    );
}
